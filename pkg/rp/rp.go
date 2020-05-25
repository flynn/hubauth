package rp

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type AuthService interface {
	Redirect(context.Context) (*AuthCodeRedirect, error)
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
