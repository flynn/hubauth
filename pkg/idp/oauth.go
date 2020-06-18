package idp

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"golang.org/x/exp/errors"
	"golang.org/x/exp/errors/fmt"
	"golang.org/x/sync/errgroup"
)

type AudienceKeyNamer func(audience string) string

func AudienceKeyNameFunc(projectID, location, keyRing string) func(string) string {
	return func(aud string) string {
		u, err := url.Parse(aud)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1", projectID, location, keyRing, strings.Replace(u.Host, ".", "_", -1))
	}
}

func New(db hubauth.DataStore, rp rp.AuthService, kms kmssign.KMSClient, codeKey hmacpb.Key, refreshKey signpb.Key, audienceKey AudienceKeyNamer) hubauth.IdPService {
	return &idpService{
		db:          db,
		rp:          rp,
		kms:         kms,
		codeKey:     codeKey,
		refreshKey:  refreshKey,
		audienceKey: audienceKey,
	}
}

type idpService struct {
	db  hubauth.DataStore
	rp  rp.AuthService
	kms kmssign.KMSClient

	codeKey     hmacpb.Key
	refreshKey  signpb.Key
	audienceKey AudienceKeyNamer
}

func (s *idpService) AuthorizeUserRedirect(ctx context.Context, req *hubauth.AuthorizeUserRequest) (*hubauth.AuthorizeRedirect, error) {
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

	ci := hubauth.GetClientInfo(ctx)
	ci.RedirectURI = req.RedirectURI
	ci.State = req.ClientState
	ci.Fragment = req.ResponseMode == "fragment"

	if len(req.ClientState) == 0 {
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
	if req.ResponseMode != "query" && req.ResponseMode != "fragment" {
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid response_mode parameter",
		}
	}
	res, err := s.rp.Redirect(ctx)
	if err != nil {
		return nil, fmt.Errorf("idp: error generating RP redirect: %w", err)
	}
	return &hubauth.AuthorizeRedirect{
		URL:     res.URL,
		RPState: res.State,
	}, nil
}

const codeExpiry = 30 * time.Second

func (s *idpService) AuthorizeCodeRedirect(ctx context.Context, req *hubauth.AuthorizeCodeRequest) (*hubauth.AuthorizeRedirect, error) {
	ci := hubauth.GetClientInfo(ctx)
	ci.RedirectURI = req.RedirectURI
	ci.State = req.ClientState
	ci.Fragment = req.ResponseMode == "fragment"

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
		groups, err := s.db.GetCachedMemberGroups(ctx, token.UserID)
		if err != nil {
			return fmt.Errorf("idp: error getting cached groups for user: %w", err)
		}
		if len(groups) == 0 {
			return &hubauth.OAuthError{
				Code:        "access_denied",
				Description: "unknown user",
			}
		}
		return nil
	})

	code := &hubauth.Code{
		ClientID:      req.ClientID,
		UserID:        token.UserID,
		UserEmail:     token.Email,
		RedirectURI:   req.RedirectURI,
		Nonce:         req.Nonce,
		PKCEChallenge: req.CodeChallenge,
		ExpiryTime:    time.Now().Add(codeExpiry),
	}
	var codeID, codeSecret string
	g.Go(func() error {
		var err error
		codeID, codeSecret, err = s.db.CreateCode(ctx, code)
		if err != nil {
			return fmt.Errorf("idp: error creating code: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	codeRes, err := s.signCode(&codeData{
		Key:       codeID,
		Secret:    codeSecret,
		UserID:    token.UserID,
		UserEmail: token.Email,
	})
	if err != nil {
		return nil, err
	}

	clog.Set(ctx,
		zap.String("issued_code_id", codeID),
		zap.Time("issued_code_expiry", code.ExpiryTime),
	)
	dest := hubauth.RedirectURI(req.RedirectURI, req.ResponseMode == "fragment", map[string]string{
		"code":  codeRes,
		"state": req.ClientState,
	})
	if dest == "" {
		return nil, fmt.Errorf("idp: error parsing redirect URI %q", req.RedirectURI)
	}

	return &hubauth.AuthorizeRedirect{URL: dest}, nil
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
	codeID := base64Encode(codeInfo.Key)
	codeSecret := base64Encode(codeInfo.Secret)

	g, ctx := errgroup.WithContext(parentCtx)

	now := time.Now()
	rtID, err := s.db.AllocateRefreshTokenID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("idp: error allocating refresh token ID: %w", err)
	}

	var code *hubauth.Code
	g.Go(func() error {
		var err error
		code, err = s.db.VerifyAndDeleteCode(ctx, codeID, codeSecret)
		if err != nil {
			if errors.Is(err, hubauth.ErrIncorrectCodeSecret) || errors.Is(err, hubauth.ErrNotFound) {
				deleted, _ := s.db.DeleteRefreshTokensWithCode(ctx, codeID)
				if len(deleted) > 0 {
					clog.Set(ctx, zap.Strings("deleted_refresh_tokens", deleted))
				}
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "code is malformed or has already been exchanged",
				}
			}
			return fmt.Errorf("idp: error verifying and deleting code %s: %w", codeID, err)
		}
		clog.Set(ctx,
			zap.String("code_user_id", code.UserID),
			zap.String("code_user_email", code.UserEmail),
		)
		if req.ClientID != code.ClientID {
			clog.Set(ctx, zap.String("code_client_id", code.ClientID))
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "client_id mismatch",
			}
		}
		if req.RedirectURI != code.RedirectURI {
			clog.Set(ctx, zap.String("code_redirect_uri", code.RedirectURI))
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "redirect_uri mismatch",
			}
		}

		chall := sha256.Sum256([]byte(req.CodeVerifier))
		challenge := base64Encode(chall[:])
		if code.PKCEChallenge != challenge {
			clog.Set(ctx,
				zap.String("code_challenge", code.PKCEChallenge),
				zap.String("expected_challenge", challenge),
			)
			return &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "code_verifier mismatch",
			}
		}

		return nil
	})

	g.Go(func() error {
		if req.Audience == "" {
			return nil
		}
		audience, err := s.db.GetAudience(ctx, req.Audience)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_request",
					Description: "unknown audience",
				}
			}
			return fmt.Errorf("idp: error getting audience %s: %w", req.Audience, err)
		}
		foundClient := false
		for _, c := range audience.ClientIDs {
			if req.ClientID == c {
				foundClient = true
				break
			}
		}
		if !foundClient {
			clog.Set(ctx, zap.Strings("audience_client_ids", audience.ClientIDs))
			return &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client for audience",
			}
		}

		err = s.checkUser(ctx, audience, codeInfo.UserId)
		if errors.Is(err, hubauth.ErrUnauthorizedUser) {
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "user is not authorized for access",
			}
		}
		return err
	})

	var client *hubauth.Client
	g.Go(func() error {
		var err error
		client, err = s.db.GetClient(ctx, req.ClientID)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_client",
					Description: "unknown client",
				}
			}
			return fmt.Errorf("idp: error getting client %s: %w", req.ClientID, err)
		}

		rt := &hubauth.RefreshToken{
			ID:          rtID,
			ClientID:    req.ClientID,
			UserID:      codeInfo.UserId,
			UserEmail:   codeInfo.UserEmail,
			RedirectURI: req.RedirectURI,
			CodeID:      codeID,
			IssueTime:   now,
			ExpiryTime:  now.Add(client.RefreshTokenExpiry),
		}
		_, err = s.db.CreateRefreshToken(ctx, rt)
		if err != nil {
			return fmt.Errorf("idp: error creating refresh token for code %s: %w", codeID, err)
		}
		clog.Set(ctx,
			zap.Time("issued_refresh_token_expiry", rt.ExpiryTime),
			zap.String("issued_refresh_token_id", rt.ID),
			zap.Int("issued_refresh_token_version", 0),
		)
		return nil
	})

	var refreshToken string
	g.Go(func() error {
		var err error
		refreshToken, err = s.signRefreshToken(ctx, &refreshTokenData{
			Key:       rtID,
			IssueTime: now,
			UserID:    codeInfo.UserId,
			UserEmail: codeInfo.UserEmail,
			ClientID:  req.ClientID,
		})
		return err
	})

	var accessToken string
	g.Go(func() error {
		if req.Audience == "" {
			return nil
		}
		var err error
		var accessTokenID string
		accessToken, accessTokenID, err = s.signAccessToken(ctx, &accessTokenData{
			keyName:   s.audienceKey(req.Audience),
			clientID:  req.ClientID,
			userID:    codeInfo.UserId,
			userEmail: codeInfo.UserEmail,
		})
		if err != nil {
			return err
		}
		clog.Set(ctx,
			zap.String("issued_access_token_id", accessTokenID),
			zap.Duration("issued_access_token_expires_in", accessTokenDuration),
		)
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		Nonce:                 code.Nonce,
		RedirectURI:           req.RedirectURI,
		RefreshTokenExpiresIn: int(client.RefreshTokenExpiry / time.Second),
	}
	if res.AccessToken != "" {
		res.ExpiresIn = int(accessTokenDuration / time.Second)
		res.TokenType = "Bearer"
	}
	return res, nil
}

func (s *idpService) RefreshToken(ctx context.Context, req *hubauth.RefreshTokenRequest) (*hubauth.AccessToken, error) {
	oldToken, err := s.decodeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if req.Audience == "" {
			return nil
		}
		audience, err := s.db.GetAudience(ctx, req.Audience)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_request",
					Description: "unknown audience",
				}
			}
			return fmt.Errorf("idp: error getting audience %s: %w", req.Audience, err)
		}
		foundClient := false
		for _, c := range audience.ClientIDs {
			if req.ClientID == c {
				foundClient = true
				break
			}
		}
		if !foundClient {
			clog.Set(ctx, zap.Strings("audience_client_ids", audience.ClientIDs))
			return &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client for audience",
			}
		}

		err = s.checkUser(ctx, audience, oldToken.UserID)
		if errors.Is(err, hubauth.ErrUnauthorizedUser) {
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "user is not authorized for access",
			}
		}
		return err
	})

	var newToken *hubauth.RefreshToken
	g.Go(func() error {
		var err error
		newToken, err = s.db.RenewRefreshToken(ctx, req.ClientID, oldToken.ID, oldToken.IssueTime, now)
		if err != nil {
			switch {
			case errors.Is(err, hubauth.ErrNotFound):
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "refresh_token not found",
				}
			case errors.Is(err, hubauth.ErrRefreshTokenVersionMismatch):
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "unexpected refresh_token issue time",
				}
			case errors.Is(err, hubauth.ErrClientIDMismatch):
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "client_id mismatch",
				}
			case errors.Is(err, hubauth.ErrExpired):
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "refresh_token expired",
				}
			}
			return fmt.Errorf("idp: error renewing refresh token: %w", err)
		}
		clog.Set(ctx,
			zap.String("issued_refresh_token_id", newToken.ID),
			zap.Time("issued_refresh_token_issue_time", newToken.IssueTime),
			zap.Time("issued_refresh_token_expiry", newToken.ExpiryTime),
		)
		return nil
	})

	var refreshToken string
	g.Go(func() error {
		var err error
		refreshToken, err = s.signRefreshToken(ctx, &refreshTokenData{
			Key:       oldToken.ID,
			IssueTime: now,
			UserID:    oldToken.UserID,
			UserEmail: oldToken.UserEmail,
			ClientID:  req.ClientID,
		})
		if err != nil {
			return err
		}
		return nil
	})

	var accessToken, accessTokenID string
	g.Go(func() error {
		if req.Audience == "" {
			return nil
		}
		var err error
		accessToken, accessTokenID, err = s.signAccessToken(ctx, &accessTokenData{
			keyName:   s.audienceKey(req.Audience),
			clientID:  req.ClientID,
			userID:    oldToken.UserID,
			userEmail: oldToken.UserEmail,
		})
		clog.Set(ctx,
			zap.String("issued_access_token_id", accessTokenID),
			zap.Duration("issued_access_token_expires_in", accessTokenDuration),
		)
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		RedirectURI:           newToken.RedirectURI,
		RefreshTokenExpiresIn: int(time.Until(newToken.ExpiryTime) / time.Second),
	}
	if res.AccessToken != "" {
		res.TokenType = "Bearer"
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
		dbToken, err := s.db.GetRefreshToken(ctx, rt.ID)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "refresh token not found",
				}
			}
			return fmt.Errorf("idp: error getting refresh token %s: %w", rt.ID, err)
		}
		if !dbToken.IssueTime.Truncate(time.Millisecond).Equal(rt.IssueTime.Truncate(time.Millisecond)) {
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "unexpected refresh token issue time",
			}
		}
		if time.Now().After(dbToken.ExpiryTime) {
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token expired",
			}
		}
		return nil
	})

	var userGroups []string
	g.Go(func() error {
		var err error
		userGroups, err = s.db.GetCachedMemberGroups(ctx, rt.UserID)
		if err != nil {
			return fmt.Errorf("idp: error getting cached groups for user %s: %w", rt.UserID, err)
		}
		return nil
	})

	var clientAudiences []*hubauth.Audience
	g.Go(func() error {
		var err error
		clientAudiences, err = s.db.ListAudiencesForClient(ctx, rt.ClientID)
		if err != nil {
			return fmt.Errorf("idp: error listing audiences for client %s: %w", rt.ClientID, err)
		}
		return nil
	})

	res := &hubauth.ListAudiencesResponse{
		Audiences: make([]*hubauth.Audience, 0, len(clientAudiences)),
	}
outer:
	for _, aud := range clientAudiences {
		for _, p := range aud.Policies {
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
	issueTime, err := ptypes.Timestamp(token.IssueTime)
	if err != nil {
		clog.Set(ctx, zap.NamedError("issue_time_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid refresh_token",
		}
	}
	res := &hubauth.RefreshToken{
		ID:        base64Encode(token.Key),
		ClientID:  base64Encode(token.ClientId),
		UserID:    token.UserId,
		UserEmail: token.UserEmail,
		IssueTime: issueTime,
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

func (s *idpService) checkUser(ctx context.Context, cluster *hubauth.Audience, userID string) error {
	groups, err := s.db.GetCachedMemberGroups(ctx, userID)
	if err != nil {
		return fmt.Errorf("idp: error getting cached groups for user: %w", err)
	}

	// TODO: log allowed groups and cached groups
	allowed := false
outer:
	for _, p := range cluster.Policies {
		for _, allowedGroup := range p.Groups {
			for _, g := range groups {
				if g == allowedGroup {
					allowed = true
					clog.Set(ctx, zap.String("authorized_group", g))
					break outer
				}
			}
		}
	}
	if !allowed {
		return hubauth.ErrUnauthorizedUser
	}
	return nil
}

type codeData struct {
	Key       string
	Secret    string
	UserID    string
	UserEmail string
}

func (s *idpService) signCode(code *codeData) (string, error) {
	keyBytes, err := base64Decode(code.Key)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding key secret: %w", err)
	}

	secretBytes, err := base64Decode(code.Secret)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding code secret: %w", err)
	}

	res, err := hmacpb.SignMarshal(s.codeKey, &pb.Code{
		Key:       keyBytes,
		Secret:    secretBytes,
		UserId:    code.UserID,
		UserEmail: code.UserEmail,
	})
	if err != nil {
		return "", fmt.Errorf("idp: error encoding signing code: %w", err)
	}
	return base64Encode(res), nil
}

type refreshTokenData struct {
	Key       string
	IssueTime time.Time
	UserID    string
	UserEmail string
	ClientID  string
}

func (s *idpService) signRefreshToken(ctx context.Context, t *refreshTokenData) (string, error) {
	ctx, span := trace.StartSpan(ctx, "idp.SignRefreshToken")
	span.AddAttributes(
		trace.StringAttribute("refresh_token_id", t.Key),
		trace.StringAttribute("user_id", t.UserID),
		trace.StringAttribute("refresh_token_issue_time", t.IssueTime.String()),
	)
	defer span.End()

	keyBytes, err := base64Decode(t.Key)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding refresh token key %q: %w", t.Key, err)
	}

	clientIDBytes, err := base64Decode(t.ClientID)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding client id %q: %w", t.ClientID, err)
	}

	iss, _ := ptypes.TimestampProto(t.IssueTime)
	msg := &pb.RefreshToken{
		Key:       keyBytes,
		IssueTime: iss,
		UserId:    t.UserID,
		UserEmail: t.UserEmail,
		ClientId:  clientIDBytes,
	}
	tokenBytes, err := signpb.SignMarshal(ctx, s.refreshKey, msg)
	if err != nil {
		return "", fmt.Errorf("idp: error signing refresh token: %w", err)
	}
	return base64Encode(tokenBytes), nil
}

const accessTokenDuration = 5 * time.Minute

type accessTokenData struct {
	keyName   string
	clientID  string
	userID    string
	userEmail string
}

func (s *idpService) signAccessToken(ctx context.Context, t *accessTokenData) (token string, id string, err error) {
	ctx, span := trace.StartSpan(ctx, "idp.SignAccessToken")
	span.AddAttributes(
		trace.StringAttribute("client_id", t.clientID),
		trace.StringAttribute("user_id", t.userID),
		trace.StringAttribute("user_email", t.userEmail),
	)
	defer span.End()

	now := time.Now()
	exp, _ := ptypes.TimestampProto(now.Add(accessTokenDuration))
	iss, _ := ptypes.TimestampProto(now)
	msg := &pb.AccessToken{
		ClientId:   t.clientID,
		UserId:     t.userID,
		UserEmail:  t.userEmail,
		IssueTime:  iss,
		ExpireTime: exp,
	}
	k := kmssign.NewPrivateKey(s.kms, t.keyName, crypto.SHA256)
	tokenBytes, err := signpb.SignMarshal(ctx, k, msg)
	if err != nil {
		return "", "", fmt.Errorf("idp: error signing access token: %w", err)
	}
	idBytes := sha256.Sum256(tokenBytes)

	token = base64.URLEncoding.EncodeToString(tokenBytes)
	id = base64Encode(idBytes[:])
	span.AddAttributes(trace.StringAttribute("access_token_id", id))
	return token, id, nil
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
