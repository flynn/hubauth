package impersonate

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors/fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
)

type mockIAM struct {
	mock.Mock
}

var _ iamAPI = (*mockIAM)(nil)

func (m *mockIAM) GenerateAccessToken(ctx context.Context, name string, req *iamcredentials.GenerateAccessTokenRequest) (*iamcredentials.GenerateAccessTokenResponse, error) {
	args := m.Called(ctx, name, req)
	return args.Get(0).(*iamcredentials.GenerateAccessTokenResponse), args.Error(1)
}
func (m *mockIAM) SignJWT(ctx context.Context, name string, req *iamcredentials.SignJwtRequest) (*iamcredentials.SignJwtResponse, error) {
	args := m.Called(ctx, name, req)
	return args.Get(0).(*iamcredentials.SignJwtResponse), args.Error(1)
}

type mockHTTPClient struct {
	mock.Mock
}

var _ httpClient = (*mockHTTPClient)(nil)

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestTokenSource(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		Desc           string
		Config         *TokenConfig
		ExpectedErr    error
		ValidateTSFunc func(ts *tokenSource)
	}{
		{
			Desc:        "nil rootSource",
			Config:      &TokenConfig{},
			ExpectedErr: ErrNilRootSource,
		},
		{
			Desc: "invalid lifetime",
			Config: &TokenConfig{
				TokenSource: &tokenSource{},
				Lifetime:    MaxTokenLifetime + 1,
			},
			ExpectedErr: ErrInvalidLifetime,
		},
		{
			Desc: "valid parameters",
			Config: &TokenConfig{
				TokenSource:     &tokenSource{},
				Lifetime:        5 * time.Second,
				TargetPrincipal: "targetPrincipal",
				Delegates:       []string{"del1", "del2"},
				TargetScopes:    []string{"scope1", "scope2"},
				Subject:         "subject",
			},
			ExpectedErr: nil,
			ValidateTSFunc: func(ts *tokenSource) {
				require.NotNil(t, ts.httpClient)
				require.NotNil(t, ts.iam)
				require.Equal(t, "targetPrincipal", ts.targetPrincipal)
				require.Equal(t, 5*time.Second, ts.lifetime)
				require.Equal(t, []string{"del1", "del2"}, ts.delegates)
				require.Equal(t, []string{"scope1", "scope2"}, ts.targetScopes)
				require.Equal(t, "subject", ts.subject)
				require.Equal(t, ctx, ts.ctx)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			ts, err := TokenSource(ctx, testCase.Config)
			require.Equal(t, testCase.ExpectedErr, err)
			if testCase.ValidateTSFunc != nil {
				testCase.ValidateTSFunc(ts.(*tokenSource))
			}
		})
	}
}

func TestTokenSourceToken(t *testing.T) {
	t.Run("returns existing token when valid", func(t *testing.T) {
		ts := &tokenSource{
			impersonatedToken: &oauth2.Token{
				AccessToken: "accessToken",
			},
		}

		token, err := ts.Token()
		require.NoError(t, err)
		require.Equal(t, ts.impersonatedToken, token)
	})

	t.Run("generates a new token with no subject", func(t *testing.T) {
		ts := &tokenSource{
			iam:             &mockIAM{},
			targetPrincipal: "targetPrincipal",
			lifetime:        5 * time.Second,
			delegates:       []string{"del1", "del2"},
			targetScopes:    []string{"scope1", "scope2"},
			ctx:             context.Background(),
		}

		req := &iamcredentials.GenerateAccessTokenRequest{
			Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
			Delegates: ts.delegates,
			Scope:     ts.targetScopes,
		}
		resp := &iamcredentials.GenerateAccessTokenResponse{
			AccessToken: "accessToken",
			ExpireTime:  time.Now().Add(3 * time.Second).Format(time.RFC3339),
		}
		ts.iam.(*mockIAM).On("GenerateAccessToken", mock.Anything, fmt.Sprintf("projects/-/serviceAccounts/%s", ts.targetPrincipal), req).Return(resp, nil)

		token, err := ts.Token()
		require.NoError(t, err)

		expireTime, err := time.Parse(time.RFC3339, resp.ExpireTime)
		require.NoError(t, err)

		expectedToken := &oauth2.Token{
			AccessToken: resp.AccessToken,
			Expiry:      expireTime,
		}
		require.Equal(t, expectedToken, token)
	})

	t.Run("generates a new token with a subject", func(t *testing.T) {
		ts := &tokenSource{
			httpClient:      &mockHTTPClient{},
			iam:             &mockIAM{},
			subject:         "subject",
			targetPrincipal: "targetPrincipal",
			targetScopes:    []string{"scope1", "scope2"},
			ctx:             context.Background(),
		}

		jsonClaims, err := json.Marshal(claimSet{
			Iss:   ts.targetPrincipal,
			Scope: strings.Join(ts.targetScopes, " "),
			Sub:   ts.subject,
			Aud:   google.JWTTokenURL,
			Iat:   time.Now().Unix(),
			Exp:   time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		name := fmt.Sprintf("projects/-/serviceAccounts/%s", ts.targetPrincipal)
		req := &iamcredentials.SignJwtRequest{
			Delegates: []string{name},
			Payload:   string(jsonClaims),
		}
		resp := &iamcredentials.SignJwtResponse{
			SignedJwt: "signedJWT",
		}
		ts.iam.(*mockIAM).On("SignJWT", mock.Anything, name, req).Return(resp, nil)

		v := make(url.Values, 3)
		v.Set("grant_type", "assertion")
		v.Set("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		v.Set("assertion", resp.SignedJwt)

		httpResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"access_token":"jwtAccessToken", "expires_in": 5}`)),
		}

		ts.httpClient.(*mockHTTPClient).On("Do", mock.Anything).Run(func(args mock.Arguments) {
			httpReq, ok := args.Get(0).(*http.Request)
			require.True(t, ok)

			require.Equal(t, "POST", httpReq.Method)
			require.Equal(t, google.JWTTokenURL, httpReq.URL.String())
			require.Equal(t, "application/x-www-form-urlencoded", httpReq.Header.Get("Content-Type"))

			body, err := ioutil.ReadAll(httpReq.Body)
			require.NoError(t, err)
			require.Equal(t, v.Encode(), string(body))
		}).Return(httpResp, nil)

		token, err := ts.Token()
		require.NoError(t, err)

		require.Equal(t, "jwtAccessToken", token.AccessToken)
		require.Equal(t, time.Now().Add(5*time.Second).Truncate(time.Second), token.Expiry.Truncate(time.Second))
	})
}

func TestTokenSourceTokenErrors(t *testing.T) {
	expectedErr := errors.New("expected err")

	invalidExpireTime := time.Now().Format(time.RFC1123)

	httpErrorResp := &http.Response{
		StatusCode: http.StatusTeapot,
		Body:       ioutil.NopCloser(strings.NewReader("body error string")),
	}

	httpExpectedErr := &oauth2.RetrieveError{
		Response: httpErrorResp,
		Body:     []byte("body error string"),
	}

	httpInvalidBodyResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(strings.NewReader("body not valid json")),
	}

	testCases := []struct {
		Desc string

		Subject string

		GenerateATErr  error
		GenerateATResp *iamcredentials.GenerateAccessTokenResponse
		SignJWTErr     error
		HttpErr        error
		HttpResp       *http.Response

		ExpectedErr error
		NeedsUnwrap bool
	}{
		{
			Desc:           "GenerateAccessToken fails",
			Subject:        "",
			GenerateATErr:  expectedErr,
			GenerateATResp: &iamcredentials.GenerateAccessTokenResponse{},
			ExpectedErr:    expectedErr,
			NeedsUnwrap:    true,
		},
		{
			Desc:    "GenerateAccessToken invalid time format",
			Subject: "",
			GenerateATResp: &iamcredentials.GenerateAccessTokenResponse{
				ExpireTime: invalidExpireTime,
			},
		},
		{
			Desc:       "SignJWT fails",
			Subject:    "not empty",
			SignJWTErr: expectedErr,

			ExpectedErr: expectedErr,
			NeedsUnwrap: true,
		},
		{
			Desc:    "HTTP call fails",
			Subject: "not empty",
			HttpErr: expectedErr,

			ExpectedErr: expectedErr,
			NeedsUnwrap: true,
		},
		{
			Desc:     "HTTP status code not 200",
			Subject:  "not empty",
			HttpResp: httpErrorResp,

			ExpectedErr: httpExpectedErr,
		},
		{
			Desc:     "HTTP body is not valid json",
			Subject:  "not empty",
			HttpResp: httpInvalidBodyResp,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			ts := &tokenSource{
				httpClient:      &mockHTTPClient{},
				iam:             &mockIAM{},
				subject:         testCase.Subject,
				targetPrincipal: "targetPrincipal",
				targetScopes:    []string{"scope1", "scope2"},
				ctx:             context.Background(),
			}

			ts.iam.(*mockIAM).On("GenerateAccessToken", mock.Anything, mock.Anything, mock.Anything).Return(testCase.GenerateATResp, testCase.GenerateATErr)
			ts.iam.(*mockIAM).On("SignJWT", mock.Anything, mock.Anything, mock.Anything).Return(&iamcredentials.SignJwtResponse{}, testCase.SignJWTErr)
			ts.httpClient.(*mockHTTPClient).On("Do", mock.Anything).Return(testCase.HttpResp, testCase.HttpErr)

			_, err := ts.Token()
			if testCase.NeedsUnwrap {
				err = errors.Unwrap(err)
			}

			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
