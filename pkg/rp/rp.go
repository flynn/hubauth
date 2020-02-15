package rp

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type AuthService interface {
	Redirect() *AuthCodeRedirect
	Exchange(context.Context, *RedirectResult) (*Token, error)
}

type AuthCodeRedirect struct {
	URL   string
	State string
}

type RedirectResult struct {
	Params url.Values

	// From the cookie
	State string
}

type Token struct {
	*oauth2.Token

	UserID  string
	Email   string
	Name    string
	Picture string
}

type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string {
	if e.Message == "" {
		return "oauth error: " + e.Code
	}
	return e.Message
}
