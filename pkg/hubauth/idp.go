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
	ClientID     string
	RedirectURI  string
	Code         string
	CodeVerifier string
}

type ExchangeCodeResponse struct {
	RefreshToken string
	AuthToken    string
}

type RefreshTokenRequest struct {
	ClientID     string
	RefreshToken string
}

type RefreshTokenResponse struct {
	RefreshToken string
	AuthToken    string
}

type IdPService interface {
	AuthorizeUserRedirect(ctx context.Context, req *AuthorizeRequest) (*AuthorizeRedirect, error)
	AuthorizeCodeRedirect(ctx context.Context, req *AuthorizeRequest) (*AuthorizeRedirect, error)
	ExchangeCode(ctx context.Context, req *ExchangeCodeRequest) (*ExchangeCodeResponse, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error)
}
