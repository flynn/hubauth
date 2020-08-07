// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Derived from https://github.com/salrashid123/oauth2/blob/4342bfaf8491f79fce4c951dff55384ad1f90f1f/google/impersonate.go

package impersonate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opencensus.io/plugin/ochttp"
	"golang.org/x/exp/errors/fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

type TokenConfig struct {
	// TokenSource is used to acquire the target identity TokenSource. It *must*
	// include the scopes "https://www.googleapis.com/auth/iam" or
	// "https://www.googleapis.com/auth/cloud.platform"
	TokenSource oauth2.TokenSource

	// TargetPrincipal is the service account to impersonate.
	TargetPrincipal string

	// Lifetime is the number of seconds the impersonated credential should be
	// valid for (up to 3600).
	Lifetime time.Duration

	// Delegates is a chain of delegates required to grant the final
	// access_token. If set, the sequence of identities must have "Service
	// Account Token Creator" capability granted to the preceeding identity. For
	// example, if set to [serviceAccountB, serviceAccountC], the TokenSource
	// must have the Token Creator role on serviceAccountB. serviceAccountB must
	// have the Token Creator on serviceAccountC. Finally, C must have Token
	// Creator on TokenPrincipal. If left unset, TokenSource must have that
	// role on TargetPrincipal.
	Delegates []string

	// TargetScopes are the scopes to request during the authorization grant.
	TargetScopes []string

	// Subject is the subject used for G Suite Domain Wide Delegation. Specify
	// this field only if you wish to use G Suite Admin SDK and utilize domain
	// wide delegation with impersonated credentials.
	// https://developers.google.com/admin-sdk/directory/v1/guides/delegation
	Subject string
}

var (
	ErrNilRootSource   = errors.New("impersonate: rootSource cannot be nil")
	ErrInvalidLifetime = errors.New("impersonate: lifetime must be less than or equal to 3600 seconds")
)

const (
	MaxTokenLifetime = 3600 * time.Second
)

type iamAPI interface {
	GenerateAccessToken(ctx context.Context, name string, req *iamcredentials.GenerateAccessTokenRequest) (*iamcredentials.GenerateAccessTokenResponse, error)
	SignJWT(ctx context.Context, name string, req *iamcredentials.SignJwtRequest) (*iamcredentials.SignJwtResponse, error)
}

type googleIAM struct {
	api *iamcredentials.Service
}

func (g *googleIAM) GenerateAccessToken(ctx context.Context, name string, req *iamcredentials.GenerateAccessTokenRequest) (*iamcredentials.GenerateAccessTokenResponse, error) {
	return g.api.Projects.ServiceAccounts.GenerateAccessToken(name, req).Context(ctx).Do()
}

func (g *googleIAM) SignJWT(ctx context.Context, name string, req *iamcredentials.SignJwtRequest) (*iamcredentials.SignJwtResponse, error) {
	return g.api.Projects.ServiceAccounts.SignJwt(name, req).Context(ctx).Do()
}

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

// TokenSource returns a TokenSource issued to a user or service account to
// impersonate another. The source project using must enable the
// iamcredentials.googleapis.com API. Also, the target service account must
// grant the orginating principal the "Service Account Token Creator" IAM role:
// https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role
//
// Note that this is not a standard OAuth flow, but rather uses Google Cloud
// IAMCredentials API to exchange one oauth token for an impersonated account
// see:
// https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken
func TokenSource(ctx context.Context, c *TokenConfig) (oauth2.TokenSource, error) {
	if c.TokenSource == nil {
		return nil, ErrNilRootSource
	}
	if c.Lifetime > MaxTokenLifetime {
		return nil, ErrInvalidLifetime
	}

	hc := oauth2.NewClient(ctx, nil)
	hc.Transport = &ochttp.Transport{Base: hc.Transport}

	iam, err := iamcredentials.NewService(ctx, option.WithTokenSource(c.TokenSource))
	if err != nil {
		return nil, fmt.Errorf("impersonate: error creating iamcredentials client: %w", err)
	}

	return &tokenSource{
		httpClient:      hc,
		iam:             &googleIAM{api: iam},
		targetPrincipal: c.TargetPrincipal,
		lifetime:        c.Lifetime,
		delegates:       c.Delegates,
		targetScopes:    c.TargetScopes,
		subject:         c.Subject,
		ctx:             ctx,
	}, nil
}

type claimSet struct {
	Iss   string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   string `json:"aud"`             // descriptor of the intended target of the assertion (Optional).
	Exp   int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string `json:"typ,omitempty"`   // token type (Optional).

	// Email for which the application is requesting delegated access (Optional).
	Sub string `json:"sub,omitempty"`

	// The old name of Sub. Client keeps setting Prn to be
	// complaint with legacy OAuth 2.0 providers. (Optional)
	Prn string `json:"prn,omitempty"`
}

type tokenSource struct {
	refreshMutex      sync.Mutex    // guards impersonatedToken; held while fetching or updating it.
	impersonatedToken *oauth2.Token // Token representing the impersonated identity.

	iam             iamAPI
	httpClient      httpClient
	targetPrincipal string
	lifetime        time.Duration
	delegates       []string
	targetScopes    []string
	subject         string
	ctx             context.Context
}

func (ts *tokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.impersonatedToken.Valid() {
		return ts.impersonatedToken, nil
	}

	name := "projects/-/serviceAccounts/" + ts.targetPrincipal
	if ts.subject == "" {
		tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
			Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
			Delegates: ts.delegates,
			Scope:     ts.targetScopes,
		}
		at, err := ts.iam.GenerateAccessToken(ts.ctx, name, tokenRequest)
		if err != nil {
			return nil, fmt.Errorf("impersonate: error calling iamcredentials.GenerateAccessToken: %w", err)
		}

		ts.impersonatedToken = &oauth2.Token{
			AccessToken: at.AccessToken,
		}
		ts.impersonatedToken.Expiry, err = time.Parse(time.RFC3339, at.ExpireTime)
		if err != nil {
			return nil, fmt.Errorf("impersonate: error parsing ExpireTime from iamcredentials: %w", err)
		}
	} else {
		// Domain-Wide Delegation token
		// ref: https://github.com/googleapis/google-api-go-client/issues/379#issuecomment-514806450
		// ref: https://gist.github.com/julianvmodesto/ed73201703dac8a047ec35a24dce4524
		iat := time.Now()
		exp := iat.Add(time.Hour)
		claims := claimSet{
			Iss:   ts.targetPrincipal,
			Scope: strings.Join(ts.targetScopes, " "),
			Sub:   ts.subject,
			Aud:   google.JWTTokenURL,
			Iat:   iat.Unix(),
			Exp:   exp.Unix(),
		}
		b, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}

		signJwtRequest := &iamcredentials.SignJwtRequest{
			Delegates: []string{name},
			Payload:   string(b),
		}
		jwt, err := ts.iam.SignJWT(ts.ctx, name, signJwtRequest)
		if err != nil {
			return nil, fmt.Errorf("impersonate: error retrieving short-lived iamcredentials token: %w", err)
		}

		v := make(url.Values, 3)
		v.Set("grant_type", "assertion")
		v.Set("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		v.Set("assertion", jwt.SignedJwt)
		req, _ := http.NewRequest("POST", google.JWTTokenURL, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := ts.httpClient.Do(req.WithContext(ts.ctx))
		if err != nil {
			return nil, fmt.Errorf("impersonate: error exchanging jwt for access token: %w", err)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("impersonate: error reading access token body: %w", err)
		}
		if res.StatusCode != http.StatusOK {
			return nil, &oauth2.RetrieveError{
				Response: res,
				Body:     body,
			}
		}

		var tokenRes struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			IDToken     string `json:"id_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &tokenRes); err != nil {
			return nil, fmt.Errorf("impersonate: error parsing access token: %w", err)
		}

		ts.impersonatedToken = &oauth2.Token{
			AccessToken: tokenRes.AccessToken,
			Expiry:      time.Now().Add(time.Second * time.Duration(tokenRes.ExpiresIn)),
		}
	}

	return ts.impersonatedToken, nil
}
