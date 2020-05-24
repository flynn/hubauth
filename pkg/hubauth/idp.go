package hubauth

import (
	"context"
	"errors"
)

var ErrUnauthorizedUser = errors.New("hubauth: unauthorized user")

type AuthorizeRequest struct {
	ClientID      string
	RedirectURI   string
	State         string
	Nonce         string
	CodeChallenge string
	UserID        string
}

type AuthorizeRedirect struct {
	URL   string
	State string
}

type ExchangeCodeRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type AccessToken struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Nonce        string `json:"nonce,omitempty"`
}

type RefreshTokenRequest struct {
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

type IdPService interface {
	AuthorizeUserRedirect(ctx context.Context, req *AuthorizeRequest) (*AuthorizeRedirect, error)
	AuthorizeCodeRedirect(ctx context.Context, req *AuthorizeRequest) (*AuthorizeRedirect, error)
	ExchangeCode(ctx context.Context, req *ExchangeCodeRequest) (*AccessToken, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*AccessToken, error)
}
