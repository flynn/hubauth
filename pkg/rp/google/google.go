package google

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func New(clientID, clientSecret, redirectURL string, sigKey signpb.Key) rp.AuthService {
	return &service{
		conf: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "profile", "email"},
		},
		sigKey: sigKey,
	}
}

type service struct {
	conf   *oauth2.Config
	sigKey signpb.Key
}

const nonceExpiry = 5 * time.Minute
const nonceRandom = 8

func (s *service) newNonce(ctx context.Context) (string, error) {
	nonce, err := genNonce(ctx, s.sigKey, time.Now().Add(nonceExpiry))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(nonce), nil
}

func genNonce(ctx context.Context, k signpb.Key, expiry time.Time) ([]byte, error) {
	exp, err := ptypes.TimestampProto(expiry)
	if err != nil {
		// this should be unreachable
		panic(err)
	}
	n := &pb.Nonce{
		ExpireTime: exp,
		Random:     make([]byte, nonceRandom),
	}
	if _, err := io.ReadFull(rand.Reader, n.Random); err != nil {
		// this should be unreachable
		panic(err)
	}

	return signpb.SignMarshal(ctx, k, n)
}

func (s *service) checkNonce(n string) bool {
	msg, err := base64.URLEncoding.DecodeString(n)
	if err != nil {
		return false
	}

	nonce := &pb.Nonce{}
	if err := signpb.VerifyUnmarshal(s.sigKey, msg, nonce); err != nil {
		return false
	}

	if len(nonce.Random) < nonceRandom {
		// incorrect length
		return false
	}

	exp, err := ptypes.Timestamp(nonce.ExpireTime)
	if err != nil {
		return false
	}
	return exp.After(time.Now())
}

func (s *service) Redirect(ctx context.Context) (*rp.AuthCodeRedirect, error) {
	nonce, err := s.newNonce(ctx)
	if err != nil {
		return nil, err
	}
	u := s.conf.AuthCodeURL(nonce, oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("hd", "*"))
	return &rp.AuthCodeRedirect{
		URL:   u,
		State: nonce,
	}, nil
}

const codeInvalid = "invalid_request"

func (s *service) Exchange(ctx context.Context, r *rp.RedirectResult) (*rp.Token, error) {
	if e := r.Params.Get("error"); e != "" {
		return nil, hubauth.OAuthError{Description: r.Params.Get("error_description"), Code: e}
	}

	nonce := r.Params.Get("state")
	if nonce == "" {
		return nil, hubauth.OAuthError{Description: "missing state", Code: codeInvalid}
	}
	if r.State != nonce {
		return nil, hubauth.OAuthError{Description: "state mismatch", Code: codeInvalid}
	}
	if !s.checkNonce(nonce) {
		return nil, hubauth.OAuthError{Description: "invalid state", Code: codeInvalid}
	}

	code := r.Params.Get("code")
	if code == "" {
		return nil, hubauth.OAuthError{Description: "missing code", Code: codeInvalid}
	}

	t, err := s.conf.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	id, ok := t.Extra("id_token").(string)
	if !ok || id == "" {
		return nil, hubauth.OAuthError{Description: "missing id_token", Code: codeInvalid}
	}
	clog.Set(ctx, zap.String("google_id_token", id))
	splitJWT := strings.SplitN(id, ".", 3)
	if len(splitJWT) < 3 {
		return nil, hubauth.OAuthError{Description: "invalid id_token", Code: codeInvalid}
	}
	// no need to check the signature, as we just got it over TLS from Google
	if m := len(splitJWT[1]) % 4; m != 0 {
		splitJWT[1] += strings.Repeat("=", 4-m)
	}
	idJSON, err := base64.URLEncoding.DecodeString(splitJWT[1])
	if err != nil {
		return nil, hubauth.OAuthError{Description: "invalid id_token encoding", Code: codeInvalid}
	}

	var idt idToken
	if err := json.Unmarshal(idJSON, &idt); err != nil {
		return nil, hubauth.OAuthError{Description: "invalid id_token json", Code: codeInvalid}
	}
	if idt.Nonce != nonce {
		return nil, hubauth.OAuthError{Description: "id_token missing nonce", Code: codeInvalid}
	}
	if idt.EmailVerified != "true" || idt.Email == "" || idt.Sub == "" {
		return nil, hubauth.OAuthError{Description: "id_token missing user", Code: codeInvalid}
	}

	return &rp.Token{
		Token:   t,
		UserID:  idt.Sub,
		Email:   idt.Email,
		Name:    idt.Name,
		Picture: idt.Picture,
	}, nil
}

type idToken struct {
	Nonce         string
	Sub           string
	Email         string
	EmailVerified string `json:"email_verified"`
	Name          string
	Picture       string
}
