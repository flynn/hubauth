package idp

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/idp/token"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"go.uber.org/zap"
	"golang.org/x/exp/errors"
	"golang.org/x/exp/errors/fmt"
	"golang.org/x/sync/errgroup"
)

const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"
const codeExpiry = 30 * time.Second
const accessTokenDuration = 5 * time.Minute

type clock interface {
	Now() time.Time
}

type clockImpl struct{}

func (clockImpl) Now() time.Time {
	return time.Now()
}

type idpSteps interface {
	VerifyAudience(ctx context.Context, audienceURL, clientID, userID string) ([]string, error)
	VerifyUserGroups(ctx context.Context, userID string) error

	CreateCode(ctx context.Context, code *hubauth.Code) (string, string, error)
	VerifyCode(ctx context.Context, c *verifyCodeData) (*hubauth.Code, error)
	SignCode(ctx context.Context, signKey hmacpb.Key, code *signCodeData) (string, error)

	AllocateRefreshToken(ctx context.Context, clientID string) (string, error)
	SaveRefreshToken(ctx context.Context, codeID, redirectURI string, t *refreshTokenData) (*hubauth.Client, error)
	SignRefreshToken(ctx context.Context, signKey signpb.PrivateKey, t *signedRefreshTokenData) (string, error)
	RenewRefreshToken(ctx context.Context, clientID, oldTokenID string, oldTokenIssueTime, now time.Time) (*hubauth.RefreshToken, error)
	VerifyRefreshToken(ctx context.Context, rt *hubauth.RefreshToken, now time.Time) error
	BuildAccessToken(ctx context.Context, audience string, t *token.AccessTokenData) (string, string, error)
}

type idpService struct {
	db hubauth.DataStore
	rp rp.AuthService

	codeKey    hmacpb.Key
	refreshKey signpb.Key

	steps idpSteps
	clock clock
}

var _ hubauth.IdPService = (*idpService)(nil)

func New(db hubauth.DataStore, rp rp.AuthService, codeKey hmacpb.Key, refreshKey signpb.Key, tokenBuilder token.AccessTokenBuilder) hubauth.IdPService {
	return &idpService{
		db:         db,
		rp:         rp,
		codeKey:    codeKey,
		refreshKey: refreshKey,
		steps: &steps{
			db:      db,
			builder: tokenBuilder,
		},
		clock: clockImpl{},
	}
}

func (s *idpService) AuthorizeUserRedirect(ctx context.Context, req *hubauth.AuthorizeUserRequest) (*hubauth.AuthorizeResponse, error) {
	client, err := s.db.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, hubauth.ErrNotFound) {
			return nil, &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "unknown client",
			}
		}
		return nil, fmt.Errorf("idp: error getting client %q: %w", req.ClientID, err)
	}
	foundRedirectURI := false
	for _, u := range client.RedirectURIs {
		if req.RedirectURI == u {
			foundRedirectURI = true
			break
		}
	}
	if !foundRedirectURI {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "specified redirect_uri is not whitelisted for client",
		}
	}

	if req.RedirectURI != oobRedirectURI {
		if ci := hubauth.GetClientInfo(ctx); ci != nil {
			ci.RedirectURI = req.RedirectURI
			ci.State = req.ClientState
			ci.Fragment = req.ResponseMode == hubauth.ResponseModeFragment
		}
	}

	if len(req.ClientState) == 0 && req.RedirectURI != oobRedirectURI {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing state parameter",
		}
	}
	if len(req.Nonce) == 0 {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing nonce parameter",
		}
	}
	if len(req.CodeChallenge) == 0 {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing code_challenge parameter",
		}
	}
	if req.ResponseMode != hubauth.ResponseModeQuery && req.ResponseMode != hubauth.ResponseModeFragment {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid response_mode parameter",
		}
	}
	res, err := s.rp.Redirect(ctx)
	if err != nil {
		return nil, fmt.Errorf("idp: error generating RP redirect: %w", err)
	}
	return &hubauth.AuthorizeResponse{
		URL:     res.URL,
		RPState: res.State,
	}, nil
}

func (s *idpService) AuthorizeCodeRedirect(ctx context.Context, req *hubauth.AuthorizeCodeRequest) (*hubauth.AuthorizeResponse, error) {
	if req.RedirectURI != oobRedirectURI {
		if ci := hubauth.GetClientInfo(ctx); ci != nil {
			ci.RedirectURI = req.RedirectURI
			ci.State = req.ClientState
			ci.Fragment = req.ResponseMode == hubauth.ResponseModeFragment
		}
	}

	token, err := s.rp.Exchange(ctx, &rp.RedirectResult{
		State:  req.RPState,
		Params: req.Params,
	})
	if err != nil {
		if oa, ok := err.(*hubauth.OAuthError); ok && (oa.Code == "access_denied" || oa.Code == "temporarily_unavailable") {
			return nil, err
		}
		return nil, fmt.Errorf("idp: error from RP: %w", err)
	}
	clog.Set(ctx,
		zap.String("rp_user_id", token.UserID),
		zap.String("rp_user_email", token.Email),
	)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		// check that we know of the user at all, as a DoS prevention measure (the
		// actual user checks happen in the token endpoint)
		return s.steps.VerifyUserGroups(ctx, token.UserID)
	})

	now := s.clock.Now()
	code := &hubauth.Code{
		ClientID:      req.ClientID,
		UserID:        token.UserID,
		UserEmail:     token.Email,
		RedirectURI:   req.RedirectURI,
		Nonce:         req.Nonce,
		PKCEChallenge: req.CodeChallenge,
		ExpiryTime:    now.Add(codeExpiry),
	}
	var codeID, codeSecret string
	g.Go(func() (err error) {
		codeID, codeSecret, err = s.steps.CreateCode(ctx, code)
		if err != nil {
			return fmt.Errorf("idp: error creating code: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	codeRes, err := s.steps.SignCode(ctx, s.codeKey, &signCodeData{
		Key:        codeID,
		Secret:     codeSecret,
		UserID:     token.UserID,
		UserEmail:  token.Email,
		ExpiryTime: now.Add(codeExpiry),
	})
	if err != nil {
		return nil, err
	}

	clog.Set(ctx,
		zap.String("issued_code_id", codeID),
		zap.Time("issued_code_expiry", code.ExpiryTime),
	)
	if req.RedirectURI == oobRedirectURI {
		return &hubauth.AuthorizeResponse{DisplayCode: codeRes}, nil
	}
	dest, isLocalhost := hubauth.RedirectURI(req.RedirectURI, req.ResponseMode == hubauth.ResponseModeFragment, map[string]string{
		"code":  codeRes,
		"state": req.ClientState,
	})
	if dest == "" {
		return nil, fmt.Errorf("idp: error parsing redirect URI %q", req.RedirectURI)
	}

	return &hubauth.AuthorizeResponse{
		URL:          dest,
		Interstitial: isLocalhost,
	}, nil
}

func (s *idpService) ExchangeCode(parentCtx context.Context, req *hubauth.ExchangeCodeRequest) (*hubauth.AccessToken, error) {
	codeBytes, err := base64Decode(req.Code)
	if err != nil {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid code encoding",
		}
	}
	codeInfo := &pb.Code{}
	if err := hmacpb.VerifyUnmarshal(s.codeKey, codeBytes, codeInfo); err != nil {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid code",
		}
	}

	now := s.clock.Now()
	if now.After(codeInfo.ExpireTime.AsTime()) {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "expired code",
		}
	}

	codeID := base64Encode(codeInfo.Key)
	codeSecret := base64Encode(codeInfo.Secret)

	g, ctx := errgroup.WithContext(parentCtx)

	rtID, err := s.steps.AllocateRefreshToken(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("idp: error allocating refresh token ID: %w", err)
	}

	var code *hubauth.Code
	g.Go(func() (err error) {
		code, err = s.steps.VerifyCode(ctx, &verifyCodeData{
			ClientID:     req.ClientID,
			RedirectURI:  req.RedirectURI,
			CodeVerifier: req.CodeVerifier,
			CodeID:       codeID,
			CodeSecret:   codeSecret,
		})
		return err
	})

	var userGroups []string
	g.Go(func() (err error) {
		userGroups, err = s.steps.VerifyAudience(ctx, req.Audience, req.ClientID, codeInfo.UserId)
		return err
	})

	var client *hubauth.Client
	var refreshToken string
	g.Go(func() (err error) {
		rtData := &refreshTokenData{
			Key:       rtID,
			IssueTime: now,
			UserID:    codeInfo.UserId,
			UserEmail: codeInfo.UserEmail,
			ClientID:  req.ClientID,
		}
		client, err = s.steps.SaveRefreshToken(ctx, codeID, req.RedirectURI, rtData)
		if err != nil {
			return err
		}

		refreshToken, err = s.steps.SignRefreshToken(ctx, s.refreshKey, &signedRefreshTokenData{
			refreshTokenData: rtData,
			ExpiryTime:       now.Add(client.RefreshTokenExpiry),
		})
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// build access token
	var accessToken string
	var tokenType string
	if req.Audience != "" {
		var userPublicKey []byte
		if len(req.UserPublicKey) > 0 {
			var err error
			userPublicKey, err = base64Decode(req.UserPublicKey)
			if err != nil {
				return nil, fmt.Errorf("idp: invalid public key: %v", err)
			}
		}

		accessToken, tokenType, err = s.steps.BuildAccessToken(parentCtx, req.Audience, &token.AccessTokenData{
			ClientID:      req.ClientID,
			UserID:        codeInfo.UserId,
			UserEmail:     codeInfo.UserEmail,
			UserPublicKey: userPublicKey,
			UserGroups:    userGroups,
			IssueTime:     now,
			ExpireTime:    now.Add(accessTokenDuration),
		})
		if err != nil {
			return nil, err
		}
	}

	res := &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		Nonce:                 code.Nonce,
		RedirectURI:           req.RedirectURI,
		Audience:              req.Audience,
		RefreshTokenExpiresIn: int(client.RefreshTokenExpiry / time.Second),
		RefreshTokenIssueTime: now,
	}

	if res.AccessToken == "" {
		// if no audience was provided, provide a refresh token that can be used to to access /audiences
		res.TokenType = "RefreshToken"
		res.AccessToken = res.RefreshToken
		res.ExpiresIn = res.RefreshTokenExpiresIn
	} else {
		res.TokenType = tokenType
		res.ExpiresIn = int(accessTokenDuration / time.Second)
	}
	return res, nil
}

func (s *idpService) RefreshToken(parentCtx context.Context, req *hubauth.RefreshTokenRequest) (*hubauth.AccessToken, error) {
	oldToken, err := s.decodeRefreshToken(parentCtx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	g, ctx := errgroup.WithContext(parentCtx)

	var userGroups []string
	g.Go(func() (err error) {
		userGroups, err = s.steps.VerifyAudience(ctx, req.Audience, req.ClientID, oldToken.UserID)
		return err
	})

	now := s.clock.Now()

	var newToken *hubauth.RefreshToken
	g.Go(func() (err error) {
		newToken, err = s.steps.RenewRefreshToken(ctx, req.ClientID, oldToken.ID, oldToken.IssueTime, now)
		return err
	})

	var refreshToken string
	g.Go(func() (err error) {
		refreshToken, err = s.steps.SignRefreshToken(ctx, s.refreshKey, &signedRefreshTokenData{
			refreshTokenData: &refreshTokenData{
				Key:       oldToken.ID,
				IssueTime: now,
				UserID:    oldToken.UserID,
				UserEmail: oldToken.UserEmail,
				ClientID:  req.ClientID,
			},
			ExpiryTime: oldToken.ExpiryTime,
		})
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	var accessToken string
	var tokenType string
	if req.Audience != "" {
		var userPublicKey []byte
		if len(req.UserPublicKey) > 0 {
			var err error
			userPublicKey, err = base64Decode(req.UserPublicKey)
			if err != nil {
				return nil, fmt.Errorf("idp: invalid public key: %v", err)
			}
		}

		accessToken, tokenType, err = s.steps.BuildAccessToken(parentCtx, req.Audience, &token.AccessTokenData{
			ClientID:      req.ClientID,
			UserID:        oldToken.UserID,
			UserEmail:     oldToken.UserEmail,
			UserGroups:    userGroups,
			UserPublicKey: userPublicKey,
			IssueTime:     now,
			ExpireTime:    now.Add(accessTokenDuration),
		})
		if err != nil {
			return nil, err
		}
	}

	res := &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		RedirectURI:           newToken.RedirectURI,
		Audience:              req.Audience,
		RefreshTokenExpiresIn: int(time.Until(newToken.ExpiryTime) / time.Second),
		RefreshTokenIssueTime: now,
	}
	if res.AccessToken == "" {
		// if no audience was provided, provide a refresh token that can be used to access /audiences
		res.TokenType = "RefreshToken"
		res.AccessToken = res.RefreshToken
		res.ExpiresIn = res.RefreshTokenExpiresIn
	} else {
		res.TokenType = tokenType
		res.ExpiresIn = int(accessTokenDuration / time.Second)
	}
	return res, nil
}

func (s *idpService) ListAudiences(ctx context.Context, req *hubauth.ListAudiencesRequest) (*hubauth.ListAudiencesResponse, error) {
	rt, err := s.decodeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.steps.VerifyRefreshToken(ctx, rt, s.clock.Now())
	})

	var userGroups []string
	g.Go(func() (err error) {
		userGroups, err = s.db.GetCachedMemberGroups(ctx, rt.UserID)
		if err != nil {
			return fmt.Errorf("idp: error getting cached groups for user %s: %w", rt.UserID, err)
		}
		return nil
	})

	var clientAudiences []*hubauth.Audience
	g.Go(func() (err error) {
		clientAudiences, err = s.db.ListAudiencesForClient(ctx, rt.ClientID)
		if err != nil {
			return fmt.Errorf("idp: error listing audiences for client %s: %w", rt.ClientID, err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := &hubauth.ListAudiencesResponse{
		Audiences: make([]*hubauth.Audience, 0, len(clientAudiences)),
	}
outer:
	for _, aud := range clientAudiences {
		for _, p := range aud.UserGroups {
			for _, allowedGroup := range p.Groups {
				for _, userGroup := range userGroups {
					if allowedGroup == userGroup {
						res.Audiences = append(res.Audiences, aud)
						continue outer
					}
				}
			}
		}
	}

	return res, nil
}

func (s *idpService) decodeRefreshToken(ctx context.Context, t string) (*hubauth.RefreshToken, error) {
	tokenMsg, err := base64Decode(t)
	if err != nil {
		clog.Set(ctx, zap.NamedError("decode_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "malformed refresh_token",
		}
	}
	token := &pb.RefreshToken{}
	if err := signpb.VerifyUnmarshal(s.refreshKey, tokenMsg, token); err != nil {
		clog.Set(ctx, zap.NamedError("unmarshal_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid refresh_token",
		}
	}

	if s.clock.Now().After(token.ExpireTime.AsTime()) {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "expired refresh token",
		}
	}

	issueTime, err := ptypes.Timestamp(token.IssueTime)
	if err != nil {
		clog.Set(ctx, zap.NamedError("issue_time_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid refresh_token",
		}
	}
	res := &hubauth.RefreshToken{
		ID:         base64Encode(token.Key),
		ClientID:   base64Encode(token.ClientId),
		UserID:     token.UserId,
		UserEmail:  token.UserEmail,
		IssueTime:  issueTime,
		ExpiryTime: token.ExpireTime.AsTime(),
	}
	clog.Set(ctx,
		zap.String("refresh_token_id", res.ID),
		zap.Time("refresh_token_issue_time", issueTime),
		zap.String("refresh_token_user_id", res.UserID),
		zap.String("refresh_token_user_email", res.UserEmail),
		zap.String("refresh_token_client_id", res.ClientID),
	)
	return res, nil
}

func base64Decode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func base64Encode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
