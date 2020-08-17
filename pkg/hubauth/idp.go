package hubauth

import (
	"context"
	"errors"
	"net/url"
	"time"
)

var ErrUnauthorizedUser = errors.New("hubauth: unauthorized user")

type AuthorizeCodeRequest struct {
	AuthorizeUserRequest
	RPState string
	Params  url.Values
}

const (
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
)

type AuthorizeUserRequest struct {
	ClientID      string
	RedirectURI   string
	ClientState   string
	Nonce         string
	CodeChallenge string
	ResponseMode  string
}

type AuthorizeResponse struct {
	URL     string
	RPState string

	Interstitial bool
	DisplayCode  string
}

type ExchangeCodeRequest struct {
	ClientID     string
	RedirectURI  string
	Audience     string
	Code         string
	CodeVerifier string
}

type AccessToken struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Nonce        string `json:"nonce,omitempty"`
	Audience     string `json:"audience,omitempty"`

	RefreshTokenExpiresIn int       `json:"refresh_token_expires_in"`
	RefreshTokenIssueTime time.Time `json:"refresh_token_issue_time"`

	// used by HTTP layer to set Access-Control-Allow-Origin
	RedirectURI string `json:"-"`
}

type RefreshTokenRequest struct {
	ClientID     string
	Audience     string
	RefreshToken string
}

type ListAudiencesRequest struct {
	RefreshToken string
}

type ListAudiencesResponse struct {
	Audiences []*Audience `json:"audiences"`
}

type IdPService interface {
	AuthorizeUserRedirect(ctx context.Context, req *AuthorizeUserRequest) (*AuthorizeResponse, error)
	AuthorizeCodeRedirect(ctx context.Context, req *AuthorizeCodeRequest) (*AuthorizeResponse, error)
	ExchangeCode(ctx context.Context, req *ExchangeCodeRequest) (*AccessToken, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*AccessToken, error)
	ListAudiences(ctx context.Context, req *ListAudiencesRequest) (*ListAudiencesResponse, error)
}
