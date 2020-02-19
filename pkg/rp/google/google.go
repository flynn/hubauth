package google

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/rp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func New(clientID, clientSecret, redirectURL string, internalSecret []byte) rp.AuthService {
	return &service{
		conf: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "profile", "email"},
		},
		secret: internalSecret,
	}
}

type service struct {
	conf   *oauth2.Config
	secret []byte
}

const nonceExpiry = 5 * time.Minute
const nonceLen = 17 + sha256.Size

func (s *service) newNonce() string {
	expiry := time.Now().Add(nonceExpiry)
	// version (1 byte) | expiry unix seconds (8 bytes) | random (8 bytes) | HMAC-SHA256 (32 bytes)
	data := make([]byte, 17, nonceLen)
	binary.BigEndian.PutUint64(data[1:], uint64(expiry.Unix()))
	if _, err := io.ReadFull(rand.Reader, data[9:]); err != nil {
		panic(err)
	}
	h := hmac.New(sha256.New, s.secret)
	h.Write(data)
	return base64.URLEncoding.EncodeToString(h.Sum(data))
}

func (s *service) checkNonce(n string) bool {
	nonce, err := base64.URLEncoding.DecodeString(n)
	if err != nil {
		return false
	}

	if len(nonce) != nonceLen {
		// incorrect length
		return false
	}

	if nonce[0] != 0 {
		// unexpected version
		return false
	}

	h := hmac.New(sha256.New, s.secret)
	h.Write(nonce[:len(nonce)-sha256.Size])
	if !hmac.Equal(h.Sum(nil), nonce[len(nonce)-sha256.Size:]) {
		// signature mismatch
		return false
	}

	exp := time.Unix(int64(binary.BigEndian.Uint64(nonce[1:])), 0)
	return exp.After(time.Now())
}

func (s *service) Redirect() *rp.AuthCodeRedirect {
	nonce := s.newNonce()
	u := s.conf.AuthCodeURL(nonce, oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("hd", "*"))
	return &rp.AuthCodeRedirect{
		URL:   u,
		State: nonce,
	}
}

const codeInvalid = "invalid_request"

func (s *service) Exchange(ctx context.Context, r *rp.RedirectResult) (*rp.Token, error) {
	if e := r.Params.Get("error"); e != "" {
		return nil, rp.Error{Message: r.Params.Get("error_description"), Code: e}
	}

	nonce := r.Params.Get("state")
	if nonce == "" {
		return nil, rp.Error{Message: "missing state", Code: codeInvalid}
	}
	if r.State != nonce {
		return nil, rp.Error{Message: "state mismatch", Code: codeInvalid}
	}
	if !s.checkNonce(nonce) {
		return nil, rp.Error{Message: "invalid state", Code: codeInvalid}
	}

	code := r.Params.Get("code")
	if code == "" {
		return nil, rp.Error{Message: "missing code", Code: codeInvalid}
	}

	t, err := s.conf.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	id, ok := t.Extra("id_token").(string)
	if !ok || id == "" {
		return nil, rp.Error{Message: "missing id_token", Code: codeInvalid}
	}
	splitJWT := strings.SplitN(id, ".", 3)
	if len(splitJWT) < 3 {
		return nil, rp.Error{Message: "invalid id_token", Code: codeInvalid}
	}
	// no need to check the signature, as we just got it over TLS from Google
	idJSON, err := base64.URLEncoding.DecodeString(splitJWT[1])
	if err != nil {
		return nil, rp.Error{Message: "invalid id_token encoding", Code: codeInvalid}
	}

	var idt idToken
	if err := json.Unmarshal(idJSON, &idt); err != nil {
		return nil, rp.Error{Message: "invalid id_token json", Code: codeInvalid}
	}
	if idt.Nonce != nonce {
		return nil, rp.Error{Message: "id_token missing nonce", Code: codeInvalid}
	}
	if idt.EmailVerified != "true" || idt.Email == "" || idt.Sub == "" {
		return nil, rp.Error{Message: "id_token missing user", Code: codeInvalid}
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
