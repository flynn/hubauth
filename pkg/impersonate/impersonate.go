// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Derived from https://github.com/salrashid123/oauth2/blob/4342bfaf8491f79fce4c951dff55384ad1f90f1f/google/impersonate.go

package impersonate

import (
	"context"
	"encoding/json"
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
	"golang.org/x/oauth2/jws"
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
func TokenSource(ctx context.Context, tokenConfig *TokenConfig) (oauth2.TokenSource, error) {
	if tokenConfig.TokenSource == nil {
		return nil, fmt.Errorf("impersonate: rootSource cannot be nil")
	}
	if tokenConfig.Lifetime > (3600 * time.Second) {
		return nil, fmt.Errorf("impersonate: lifetime must be less than or equal to 3600 seconds")
	}

	hc := oauth2.NewClient(ctx, nil)
	hc.Transport = &ochttp.Transport{Base: hc.Transport}

	return &tokenSource{
		httpClient:      hc,
		rootSource:      tokenConfig.TokenSource,
		targetPrincipal: tokenConfig.TargetPrincipal,
		lifetime:        tokenConfig.Lifetime,
		delegates:       tokenConfig.Delegates,
		targetScopes:    tokenConfig.TargetScopes,
		subject:         tokenConfig.Subject,
		ctx:             ctx,
	}, nil
}

type tokenSource struct {
	refreshMutex      sync.Mutex    // guards impersonatedToken; held while fetching or updating it.
	impersonatedToken *oauth2.Token // Token representing the impersonated identity.

	httpClient      *http.Client
	rootSource      oauth2.TokenSource
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

	service, err := iamcredentials.NewService(ts.ctx, option.WithTokenSource(ts.rootSource))
	if err != nil {
		return nil, fmt.Errorf("impersonate: error creating iamcredentials client: %w", err)
	}
	name := "projects/-/serviceAccounts/" + ts.targetPrincipal

	if ts.subject == "" {
		tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
			Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
			Delegates: ts.delegates,
			Scope:     ts.targetScopes,
		}
		at, err := service.Projects.ServiceAccounts.GenerateAccessToken(name, tokenRequest).Context(ts.ctx).Do()
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
		claims := &jws.ClaimSet{
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
		jwt, err := service.Projects.ServiceAccounts.SignJwt(name, signJwtRequest).Context(ts.ctx).Do()
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
