package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"golang.org/x/exp/errors/fmt"
)

type IdPService struct {
	db hubauth.DataStore
	rp rp.AuthService

	refreshKey signpb.Key
	accessKey  signpb.Key
}

func (s *IdPService) AuthorizeUserRedirect(ctx context.Context, req *hubauth.AuthorizeRequest) (*hubauth.AuthorizeRedirect, error) {
	client, err := s.db.GetClient(ctx, req.ClientID)
	if err != nil {
		// TODO: 400 error if notfound
		return nil, fmt.Errorf("idp: error getting client: %w", req.ClientID, err)
	}
	foundRedirectURI := false
	for _, u := range client.RedirectURIs {
		if req.RedirectURI == u {
			foundRedirectURI = true
			break
		}
	}
	if !foundRedirectURI {
		// TODO: 400 error
		return nil, fmt.Errorf("idp: redirect URI %q is not whitelisted for client %s", req.RedirectURI, req.ClientID)
	}

	if len(req.State) == 0 {
		// TODO: redirect with tagged error
		return nil, fmt.Errorf("idp: missing state")
	}
	if len(req.Nonce) == 0 {
		// TODO: redirect with tagged error
		return nil, fmt.Errorf("idp: missing nonce")
	}
	if len(req.CodeChallenge) == 0 {
		// TODO: redirect with tagged error
		return nil, fmt.Errorf("idp: missing PKCE code challenge")
	}
	res, err := s.rp.Redirect(ctx)
	if err != nil {
		return nil, fmt.Errorf("idp: error generating RP redirect: %w", err)
	}
	return &hubauth.AuthorizeRedirect{
		URL:   res.URL,
		State: res.State,
	}, nil
}

const codeExpiry = 30 * time.Second

func (s *IdPService) AuthorizeCodeRedirect(ctx context.Context, req *hubauth.AuthorizeRequest) (*hubauth.AuthorizeRedirect, error) {
	client, err := s.db.GetClient(ctx, req.ClientID)
	if err != nil {
		// TODO: 400 error if notfound
		return nil, fmt.Errorf("idp: error getting client %s: %w", req.ClientID, err)
	}
	if err := s.checkUser(ctx, client, req.UserID); err != nil {
		// TODO: redirect with tagged error if unauthorized
		return nil, err
	}
	codeData := &hubauth.Code{
		ClientID:      req.ClientID,
		UserID:        req.UserID,
		RedirectURI:   req.RedirectURI,
		Nonce:         req.Nonce,
		PKCEChallenge: req.CodeChallenge,
		ExpiryTime:    time.Now().Add(codeExpiry),
	}
	codeID, codeSecret, err := s.db.CreateCode(ctx, codeData)
	if err != nil {
		return nil, fmt.Errorf("idp: error creating code: %w", err)
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("idp: error parsing redirect URI %q: %w", req.RedirectURI, err)
	}
	q := u.Query()
	q.Set("code", codeID+":"+codeSecret)
	q.Set("state", req.State)
	u.RawQuery = q.Encode()

	return &hubauth.AuthorizeRedirect{URL: u.String()}, nil
}

func (s *IdPService) ExchangeCode(ctx context.Context, req *hubauth.ExchangeCodeRequest) (*hubauth.AccessToken, error) {
	deleted, err := s.db.DeleteRefreshTokensWithCode(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("idp: error deleting refresh tokens with code: %q", err)
	}
	if len(deleted) > 0 {
		// TODO: format error, log info
		return nil, fmt.Errorf("idp: found existing refresh tokens for code: %v")
	}

	splitCode := strings.SplitN(req.Code, ":", 2)
	if len(splitCode) != 2 {
		// TODO: format error
		return nil, fmt.Errorf("idp: invalid code %q", req.Code)
	}

	code, err := s.db.VerifyAndDeleteCode(ctx, splitCode[0], splitCode[1])
	if err != nil {
		return nil, fmt.Errorf("idp: error verifying and deleting code %s: %w", splitCode[0], err)
	}
	if req.ClientID != code.ClientID {
		// TODO: format error
		return nil, fmt.Errorf("idp: client mismatch, expected %s but request had %s", code.ClientID, req.ClientID)
	}
	if req.RedirectURI != code.RedirectURI {
		// TODO: format error
		return nil, fmt.Errorf("idp: redirect URI mismatch, expected %s but request had %s", code.RedirectURI, req.RedirectURI)
	}

	chall := sha256.Sum256([]byte(req.CodeVerifier))
	challenge := base64.URLEncoding.EncodeToString(chall[:])
	if code.PKCEChallenge != challenge {
		return nil, fmt.Errorf("idp: PKCE challenge mismatch")
	}

	client, err := s.db.GetClient(ctx, code.ClientID)
	if err != nil {
		return nil, fmt.Errorf("idp: error getting client %s: %w", code.ClientID, err)
	}

	rt := &hubauth.RefreshToken{
		ClientID:   req.ClientID,
		UserID:     code.UserID,
		CodeID:     splitCode[0],
		ExpiryTime: time.Now().Add(client.RefreshTokenExpiry),
	}
	rt.ID, err = s.db.CreateRefreshToken(ctx, rt)
	if err != nil {
		return nil, fmt.Errorf("idp: error creating refresh token for code %s: %w", splitCode[0], err)
	}

	refreshToken, err := s.signRefreshToken(ctx, rt.ID, rt.Version)
	if err != nil {
		return nil, err
	}
	// TODO: log refresh token

	accessToken, _, err := s.signAccessToken(ctx, req.ClientID, code.UserID)
	if err != nil {
		return nil, err
	}
	// TODO: log access token ID

	return &hubauth.AccessToken{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		Nonce:        code.Nonce,
		ExpiresIn:    int(accessTokenDuration / time.Second),
	}, nil
}

func (s *IdPService) RefreshToken(ctx context.Context, req *hubauth.RefreshTokenRequest) (*hubauth.AccessToken, error) {
	tokenMsg, err := base64.URLEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		// TODO: 400
		return nil, fmt.Errorf("idp: error decoding refresh token: %w", err)
	}
	oldToken := &pb.RefreshToken{}
	if err := signpb.VerifyUnmarshal(s.refreshKey, tokenMsg, oldToken); err != nil {
		// TODO: 400
		return nil, fmt.Errorf("idp: error verifying refresh token signature: %w", err)
	}

	rtKey := strings.TrimRight(base64.URLEncoding.EncodeToString(oldToken.Key), "=")
	newToken, err := s.db.RenewRefreshToken(ctx, req.ClientID, rtKey, int(oldToken.Version))
	if err != nil {
		if err == hubauth.ErrNotFound || err == hubauth.ErrRefreshTokenVersionMismatch || err == hubauth.ErrClientIDMismatch || err == hubauth.ErrExpired {
			// TODO: 400
		}
		return nil, fmt.Errorf("idp: error renewing refresh token: %w", err)
	}

	refreshToken, err := s.signRefreshToken(ctx, newToken.ID, newToken.Version)
	if err != nil {
		return nil, err
	}
	// TODO: log refresh token

	accessToken, _, err := s.signAccessToken(ctx, newToken.ClientID, newToken.UserID)
	if err != nil {
		return nil, err
	}
	// TODO: log access token ID

	return &hubauth.AccessToken{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenDuration / time.Second),
	}, nil
}

func (s *IdPService) checkUser(ctx context.Context, client *hubauth.Client, userID string) error {
	groups, err := s.db.GetCachedMemberGroups(ctx, userID)
	if err != nil {
		return fmt.Errorf("idp: error getting cached groups for user: %w", err)
	}

	allowed := false
outer:
	for _, p := range client.Policies {
		for _, allowedGroup := range p.Groups {
			for _, g := range groups {
				if g == allowedGroup {
					allowed = true
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

func (s *IdPService) signRefreshToken(ctx context.Context, key string, version int) (string, error) {
	if m := len(key) % 4; m != 0 {
		key += strings.Repeat("=", 4-m)
	}
	keyBytes, err := base64.URLEncoding.DecodeString(key)

	if err != nil {
		return "", fmt.Errorf("idp: error decoding refresh token key %q: %w", key, err)
	}

	msg := &pb.RefreshToken{
		Key:     keyBytes,
		Version: uint64(version),
	}
	tokenBytes, err := signpb.SignMarshal(ctx, s.refreshKey, msg)
	if err != nil {
		return "", fmt.Errorf("idp: error signing refresh token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

const accessTokenDuration = 5 * time.Minute

func (s *IdPService) signAccessToken(ctx context.Context, clientID, user string) (token string, id string, err error) {
	exp, err := ptypes.TimestampProto(time.Now().Add(accessTokenDuration))
	if err != nil {
		// this should be unreachable
		panic(err)
	}
	msg := &pb.AccessToken{
		ClientId:   clientID,
		User:       user,
		ExpireTime: exp,
	}
	tokenBytes, err := signpb.SignMarshal(ctx, s.accessKey, msg)
	if err != nil {
		return "", "", fmt.Errorf("idp: error signing access token: %w", err)
	}
	idBytes := sha256.Sum256(tokenBytes)

	return base64.URLEncoding.EncodeToString(tokenBytes), base64.URLEncoding.EncodeToString(idBytes[:]), nil
}
