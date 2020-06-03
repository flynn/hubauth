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

type ClusterKeyNamer func(audience string) string

func ClusterKeyNameFunc(projectID, location, keyRing string) func(string) string {
	return func(aud string) string {
		u, err := url.Parse(aud)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1", projectID, location, keyRing, strings.Replace(u.Host, ".", "_", -1))
	}
}

func New(db hubauth.DataStore, rp rp.AuthService, kms kmssign.KMSClient, codeKey hmacpb.Key, refreshKey signpb.Key, clusterKey ClusterKeyNamer) hubauth.IdPService {
	return &idpService{
		db:         db,
		rp:         rp,
		kms:        kms,
		codeKey:    codeKey,
		refreshKey: refreshKey,
		clusterKey: clusterKey,
	}
}

type idpService struct {
	db  hubauth.DataStore
	rp  rp.AuthService
	kms kmssign.KMSClient

	codeKey    hmacpb.Key
	refreshKey signpb.Key
	clusterKey ClusterKeyNamer
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
	clog.Set(ctx, zap.String("rp_user_id", token.UserID))
	clog.Set(ctx, zap.String("rp_user_email", token.Email))

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

	clog.Set(ctx, zap.String("issued_code_id", codeID))
	clog.Set(ctx, zap.Time("issued_code_expiry", code.ExpiryTime))
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
	codeBytes, err := base64.URLEncoding.DecodeString(padBase64(req.Code))
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
	codeID := strings.TrimRight(base64.URLEncoding.EncodeToString(codeInfo.Key), "=")
	codeSecret := strings.TrimRight(base64.URLEncoding.EncodeToString(codeInfo.Secret), "=")

	g, ctx := errgroup.WithContext(parentCtx)

	rtID, err := s.db.AllocateRefreshTokenID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("idp: error allocating refresh token ID: %w", err)
	}

	g.Go(func() error {
		deleted, err := s.db.DeleteRefreshTokensWithCode(ctx, codeID)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "invalid code",
				}
			}
			return fmt.Errorf("idp: error deleting refresh tokens with code: %q", err)
		}
		if len(deleted) > 0 {
			clog.Set(ctx, zap.Strings("deleted_refresh_tokens", deleted))
			return &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "code already exchanged",
			}
		}
		return nil
	})

	var code *hubauth.Code
	g.Go(func() error {
		var err error
		code, err = s.db.VerifyAndDeleteCode(ctx, codeID, codeSecret)
		if err != nil {
			if errors.Is(err, hubauth.ErrIncorrectCodeSecret) || errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_grant",
					Description: "malformed or incorrect code",
				}
			}
			return fmt.Errorf("idp: error verifying and deleting code %s: %w", codeID, err)
		}
		clog.Set(ctx, zap.String("code_user_id", code.UserID))
		clog.Set(ctx, zap.String("code_user_email", code.UserEmail))
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
		challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(chall[:]), "=")
		if code.PKCEChallenge != challenge {
			clog.Set(ctx, zap.String("code_challenge", code.PKCEChallenge))
			clog.Set(ctx, zap.String("expected_challenge", challenge))
			return &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "code_verifier mismatch",
			}
		}

		return nil
	})

	g.Go(func() error {
		cluster, err := s.db.GetCluster(ctx, req.Audience)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_request",
					Description: "unknown audience",
				}
			}
			return fmt.Errorf("idp: error getting cluster %s: %w", req.Audience, err)
		}
		foundClient := false
		for _, c := range cluster.ClientIDs {
			if req.ClientID == c {
				foundClient = true
				break
			}
		}
		if !foundClient {
			clog.Set(ctx, zap.Strings("cluster_client_ids", cluster.ClientIDs))
			return &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client for audience",
			}
		}

		err = s.checkUser(ctx, cluster, codeInfo.UserId)
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
			ExpiryTime:  time.Now().Add(client.RefreshTokenExpiry),
		}
		_, err = s.db.CreateRefreshToken(ctx, rt)
		if err != nil {
			return fmt.Errorf("idp: error creating refresh token for code %s: %w", codeID, err)
		}
		clog.Set(ctx, zap.Time("issued_refresh_token_expiry", rt.ExpiryTime))
		clog.Set(ctx, zap.String("issued_refresh_token_id", rt.ID))
		clog.Set(ctx, zap.Int("issued_refresh_token_version", 0))
		return nil
	})

	var refreshToken string
	g.Go(func() error {
		var err error
		refreshToken, err = s.signRefreshToken(ctx, &refreshTokenData{
			Key:       rtID,
			Version:   0,
			UserID:    codeInfo.UserId,
			UserEmail: codeInfo.UserEmail,
		})
		return err
	})

	var accessToken string
	g.Go(func() error {
		var err error
		var accessTokenID string
		accessToken, accessTokenID, err = s.signAccessToken(ctx, &accessTokenData{
			keyName:   s.clusterKey(req.Audience),
			clientID:  req.ClientID,
			userID:    codeInfo.UserId,
			userEmail: codeInfo.UserEmail,
		})
		if err != nil {
			return err
		}
		clog.Set(ctx, zap.String("issued_access_token_id", accessTokenID))
		clog.Set(ctx, zap.Duration("issued_access_token_expires_in", accessTokenDuration))
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		TokenType:             "Bearer",
		Nonce:                 code.Nonce,
		ExpiresIn:             int(accessTokenDuration / time.Second),
		RedirectURI:           req.RedirectURI,
		RefreshTokenExpiresIn: int(client.RefreshTokenExpiry / time.Second),
	}, nil
}

func rpcError(err error) {

}

func (s *idpService) RefreshToken(ctx context.Context, req *hubauth.RefreshTokenRequest) (*hubauth.AccessToken, error) {
	tokenMsg, err := base64.URLEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		clog.Set(ctx, zap.NamedError("decode_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "malformed refresh_token",
		}
	}
	oldToken := &pb.RefreshToken{}
	if err := signpb.VerifyUnmarshal(s.refreshKey, tokenMsg, oldToken); err != nil {
		clog.Set(ctx, zap.NamedError("unmarshal_error", err))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "invalid refresh_token",
		}
	}
	rtKey := strings.TrimRight(base64.URLEncoding.EncodeToString(oldToken.Key), "=")
	clog.Set(ctx, zap.String("refresh_token_id", rtKey))
	clog.Set(ctx, zap.Uint64("refresh_token_version", oldToken.Version))
	clog.Set(ctx, zap.String("refresh_token_user_id", oldToken.UserId))
	clog.Set(ctx, zap.String("refresh_token_user_email", oldToken.UserEmail))

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		cluster, err := s.db.GetCluster(ctx, req.Audience)
		if err != nil {
			if errors.Is(err, hubauth.ErrNotFound) {
				return &hubauth.OAuthError{
					Code:        "invalid_request",
					Description: "unknown audience",
				}
			}
			return fmt.Errorf("idp: error getting cluster %s: %w", req.Audience, err)
		}
		foundClient := false
		for _, c := range cluster.ClientIDs {
			if req.ClientID == c {
				foundClient = true
				break
			}
		}
		if !foundClient {
			clog.Set(ctx, zap.Strings("cluster_client_ids", cluster.ClientIDs))
			return &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client for audience",
			}
		}

		err = s.checkUser(ctx, cluster, oldToken.UserId)
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
		newToken, err = s.db.RenewRefreshToken(ctx, req.ClientID, rtKey, int(oldToken.Version))
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
					Description: "unexpected refresh_token version",
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
		return nil
	})

	var refreshToken string
	g.Go(func() error {
		var err error
		refreshToken, err = s.signRefreshToken(ctx, &refreshTokenData{
			Key:       rtKey,
			Version:   int(oldToken.Version) + 1,
			UserID:    oldToken.UserId,
			UserEmail: oldToken.UserEmail,
		})
		if err != nil {
			return err
		}
		return nil
	})

	var accessToken, accessTokenID string
	g.Go(func() error {
		var err error
		accessToken, accessTokenID, err = s.signAccessToken(ctx, &accessTokenData{
			keyName:   s.clusterKey(req.Audience),
			clientID:  req.ClientID,
			userID:    oldToken.UserId,
			userEmail: oldToken.UserEmail,
		})
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	clog.Set(ctx, zap.String("issued_access_token_id", accessTokenID))
	clog.Set(ctx, zap.Duration("issued_access_token_expires_in", accessTokenDuration))
	clog.Set(ctx, zap.String("issued_refresh_token_id", newToken.ID))
	clog.Set(ctx, zap.Int("issued_refresh_token_version", newToken.Version))
	clog.Set(ctx, zap.Time("issued_refresh_token_expiry", newToken.ExpiryTime))

	return &hubauth.AccessToken{
		RefreshToken:          refreshToken,
		AccessToken:           accessToken,
		TokenType:             "Bearer",
		ExpiresIn:             int(accessTokenDuration / time.Second),
		RedirectURI:           newToken.RedirectURI,
		RefreshTokenExpiresIn: int(time.Until(newToken.ExpiryTime) / time.Second),
	}, nil
}

func (s *idpService) checkUser(ctx context.Context, cluster *hubauth.Cluster, userID string) error {
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
	keyBytes, err := base64.URLEncoding.DecodeString(padBase64(code.Key))
	if err != nil {
		return "", fmt.Errorf("idp: error decoding key secret: %w", err)
	}

	secretBytes, err := base64.URLEncoding.DecodeString(padBase64(code.Secret))
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
	return strings.TrimRight(base64.URLEncoding.EncodeToString(res), "="), nil
}

type refreshTokenData struct {
	Key       string
	Version   int
	UserID    string
	UserEmail string
}

func (s *idpService) signRefreshToken(ctx context.Context, t *refreshTokenData) (string, error) {
	ctx, span := trace.StartSpan(ctx, "idp.SignRefreshToken")
	span.AddAttributes(
		trace.StringAttribute("refresh_token_id", t.Key),
		trace.StringAttribute("user_id", t.UserID),
		trace.Int64Attribute("refresh_token_version", int64(t.Version)),
	)
	defer span.End()

	keyBytes, err := base64.URLEncoding.DecodeString(padBase64(t.Key))
	if err != nil {
		return "", fmt.Errorf("idp: error decoding refresh token key %q: %w", t.Key, err)
	}

	msg := &pb.RefreshToken{
		Key:       keyBytes,
		Version:   uint64(t.Version),
		UserId:    t.UserID,
		UserEmail: t.UserEmail,
	}
	tokenBytes, err := signpb.SignMarshal(ctx, s.refreshKey, msg)
	if err != nil {
		return "", fmt.Errorf("idp: error signing refresh token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
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
	exp, err := ptypes.TimestampProto(now.Add(accessTokenDuration))
	if err != nil {
		// this should be unreachable
		panic(err)
	}
	iss, err := ptypes.TimestampProto(now)
	if err != nil {
		// this should be unreachable
		panic(err)
	}
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
	id = base64.URLEncoding.EncodeToString(idBytes[:])
	span.AddAttributes(trace.StringAttribute("access_token_id", id))
	return token, id, nil
}

func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}
