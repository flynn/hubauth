package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/idp/token"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"golang.org/x/exp/errors"
	"golang.org/x/exp/errors/fmt"
)

type steps struct {
	db      hubauth.DataStore
	builder token.AccessTokenBuilder
}

var _ idpSteps = (*steps)(nil)

func (s *steps) CreateCode(ctx context.Context, code *hubauth.Code) (string, string, error) {
	return s.db.CreateCode(ctx, code)
}

type verifyCodeData struct {
	ClientID     string
	RedirectURI  string
	CodeVerifier string
	CodeID       string
	CodeSecret   string
}

func (s *steps) VerifyCode(ctx context.Context, c *verifyCodeData) (*hubauth.Code, error) {
	code, err := s.db.VerifyAndDeleteCode(ctx, c.CodeID, c.CodeSecret)
	if err != nil {
		if errors.Is(err, hubauth.ErrIncorrectCodeSecret) || errors.Is(err, hubauth.ErrNotFound) {
			deleted, _ := s.db.DeleteRefreshTokensWithCode(ctx, c.CodeID)
			if len(deleted) > 0 {
				clog.Set(ctx, zap.Strings("deleted_refresh_tokens", deleted))
			}
			return nil, &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "code is malformed or has already been exchanged",
			}
		}
		return nil, fmt.Errorf("idp: error verifying and deleting code %s: %w", c.CodeID, err)
	}
	clog.Set(ctx,
		zap.String("code_user_id", code.UserID),
		zap.String("code_user_email", code.UserEmail),
	)
	if c.ClientID != code.ClientID {
		clog.Set(ctx, zap.String("code_client_id", code.ClientID))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "client_id mismatch",
		}
	}

	if c.RedirectURI != code.RedirectURI {
		clog.Set(ctx, zap.String("code_redirect_uri", code.RedirectURI))
		return nil, &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "redirect_uri mismatch",
		}
	}

	chall := sha256.Sum256([]byte(c.CodeVerifier))
	challenge := base64Encode(chall[:])
	if code.PKCEChallenge != challenge {
		clog.Set(ctx,
			zap.String("code_challenge", code.PKCEChallenge),
			zap.String("expected_challenge", challenge),
		)
		return nil, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "code_verifier mismatch",
		}
	}

	return code, nil
}

type signCodeData struct {
	Key        string
	Secret     string
	UserID     string
	UserEmail  string
	ExpiryTime time.Time
}

func (s *steps) SignCode(ctx context.Context, signKey hmacpb.Key, code *signCodeData) (string, error) {
	keyBytes, err := base64Decode(code.Key)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding key secret: %w", err)
	}

	secretBytes, err := base64Decode(code.Secret)
	if err != nil {
		return "", fmt.Errorf("idp: error decoding code secret: %w", err)
	}

	expireTime, _ := ptypes.TimestampProto(code.ExpiryTime)
	res, err := hmacpb.SignMarshal(signKey, &pb.Code{
		Key:        keyBytes,
		Secret:     secretBytes,
		UserId:     code.UserID,
		UserEmail:  code.UserEmail,
		ExpireTime: expireTime,
	})
	if err != nil {
		return "", fmt.Errorf("idp: error encoding signing code: %w", err)
	}
	return base64Encode(res), nil
}

func (s *steps) VerifyAudience(ctx context.Context, audienceURL, clientID, userID string) error {
	if audienceURL == "" {
		return nil
	}
	audience, err := s.db.GetAudience(ctx, audienceURL)
	if err != nil {
		if errors.Is(err, hubauth.ErrNotFound) {
			return &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "unknown audience",
			}
		}
		return fmt.Errorf("idp: error getting audience %s: %w", audienceURL, err)
	}
	foundClient := false
	for _, c := range audience.ClientIDs {
		if clientID == c {
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

	err = s.checkUser(ctx, audience, userID)
	if errors.Is(err, hubauth.ErrUnauthorizedUser) {
		return &hubauth.OAuthError{
			Code:        "access_denied",
			Description: "user is not authorized for access",
		}
	}
	return err
}

func (s *steps) VerifyUserGroups(ctx context.Context, userID string) error {
	groups, err := s.db.GetCachedMemberGroups(ctx, userID)
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
}

func (s *steps) checkUser(ctx context.Context, cluster *hubauth.Audience, userID string) error {
	groups, err := s.db.GetCachedMemberGroups(ctx, userID)
	if err != nil {
		return fmt.Errorf("idp: error getting cached groups for user: %w", err)
	}

	// TODO: log allowed groups and cached groups
	allowed := false
outer:
	for _, p := range cluster.UserGroups {
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

type refreshTokenData struct {
	Key       string
	IssueTime time.Time
	UserID    string
	UserEmail string
	ClientID  string
}

type signedRefreshTokenData struct {
	*refreshTokenData
	ExpiryTime time.Time
}

func (s *steps) AllocateRefreshToken(ctx context.Context, clientID string) (string, error) {
	return s.db.AllocateRefreshTokenID(ctx, clientID)
}

func (s *steps) SaveRefreshToken(ctx context.Context, codeID, redirectURI string, t *refreshTokenData) (*hubauth.Client, error) {
	client, err := s.db.GetClient(ctx, t.ClientID)
	if err != nil {
		if errors.Is(err, hubauth.ErrNotFound) {
			return nil, &hubauth.OAuthError{
				Code:        "invalid_client",
				Description: "unknown client",
			}
		}
		return nil, fmt.Errorf("idp: error getting client %s: %w", t.ClientID, err)
	}

	rt := &hubauth.RefreshToken{
		ID:          t.Key,
		ClientID:    t.ClientID,
		UserID:      t.UserID,
		UserEmail:   t.UserEmail,
		RedirectURI: redirectURI,
		CodeID:      codeID,
		IssueTime:   t.IssueTime,
		ExpiryTime:  t.IssueTime.Add(client.RefreshTokenExpiry),
	}
	_, err = s.db.CreateRefreshToken(ctx, rt)
	if err != nil {
		return nil, fmt.Errorf("idp: error creating refresh token for code %s: %w", codeID, err)
	}
	clog.Set(ctx,
		zap.Time("issued_refresh_token_expiry", rt.ExpiryTime),
		zap.String("issued_refresh_token_id", rt.ID),
		zap.Int("issued_refresh_token_version", 0),
	)
	return client, nil
}

func (s *steps) SignRefreshToken(ctx context.Context, signKey signpb.PrivateKey, t *signedRefreshTokenData) (string, error) {
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
	exp, _ := ptypes.TimestampProto(t.ExpiryTime)
	msg := &pb.RefreshToken{
		Key:        keyBytes,
		IssueTime:  iss,
		UserId:     t.UserID,
		UserEmail:  t.UserEmail,
		ClientId:   clientIDBytes,
		ExpireTime: exp,
	}
	tokenBytes, err := signpb.SignMarshal(ctx, signKey, msg)
	if err != nil {
		return "", fmt.Errorf("idp: error signing refresh token: %w", err)
	}
	return base64Encode(tokenBytes), nil
}

func (s *steps) RenewRefreshToken(ctx context.Context, clientID, oldTokenID string, oldTokenIssueTime, now time.Time) (*hubauth.RefreshToken, error) {
	newToken, err := s.db.RenewRefreshToken(ctx, clientID, oldTokenID, oldTokenIssueTime, now)
	if err != nil {
		switch {
		case errors.Is(err, hubauth.ErrNotFound):
			return nil, &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token not found",
			}
		case errors.Is(err, hubauth.ErrRefreshTokenVersionMismatch):
			return nil, &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "unexpected refresh_token issue time",
			}
		case errors.Is(err, hubauth.ErrClientIDMismatch):
			return nil, &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "client_id mismatch",
			}
		case errors.Is(err, hubauth.ErrExpired):
			return nil, &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "refresh_token expired",
			}
		}
		return nil, fmt.Errorf("idp: error renewing refresh token: %w", err)
	}
	clog.Set(ctx,
		zap.String("issued_refresh_token_id", newToken.ID),
		zap.Time("issued_refresh_token_issue_time", newToken.IssueTime),
		zap.Time("issued_refresh_token_expiry", newToken.ExpiryTime),
	)

	return newToken, nil
}

func (s *steps) VerifyRefreshToken(ctx context.Context, rt *hubauth.RefreshToken, now time.Time) error {
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
	if now.After(dbToken.ExpiryTime) {
		return &hubauth.OAuthError{
			Code:        "invalid_grant",
			Description: "refresh_token expired",
		}
	}

	return nil
}

func (s *steps) BuildAccessToken(ctx context.Context, audience string, t *token.AccessTokenData) (token string, err error) {
	ctx, span := trace.StartSpan(ctx, "idp.BuildAccessToken")
	span.AddAttributes(
		trace.StringAttribute("client_id", t.ClientID),
		trace.StringAttribute("user_id", t.UserID),
		trace.StringAttribute("user_email", t.UserEmail),
	)
	defer span.End()

	tokenBytes, err := s.builder.Build(ctx, audience, t)
	if err != nil {
		return "", fmt.Errorf("idp: error building access token: %w", err)
	}

	idBytes := sha256.Sum256(tokenBytes)
	accessTokenID := base64Encode(idBytes[:])
	span.AddAttributes(trace.StringAttribute("access_token_id", accessTokenID))

	clog.Set(ctx,
		zap.String("issued_access_token_id", accessTokenID),
		zap.Duration("issued_access_token_expires_in", accessTokenDuration),
	)

	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}
