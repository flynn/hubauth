package idp

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	gdatastore "cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/flynn/hubauth/pkg/signpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockAuthService struct {
	mock.Mock
}

var _ rp.AuthService = (*mockAuthService)(nil)

func (m *mockAuthService) Redirect(ctx context.Context) (*rp.AuthCodeRedirect, error) {
	args := m.Called(ctx)
	return args.Get(0).(*rp.AuthCodeRedirect), args.Error(1)
}

func (m *mockAuthService) Exchange(ctx context.Context, rr *rp.RedirectResult) (*rp.Token, error) {
	args := m.Called(ctx, rr)
	return args.Get(0).(*rp.Token), args.Error(1)
}

func audienceKeyNamer(s string) string {
	return fmt.Sprintf("%s_named", s)
}

type mockSteps struct {
	mock.Mock
}

var _ idpSteps = (*mockSteps)(nil)

func (m *mockSteps) CreateCode(ctx context.Context, code *hubauth.Code) (string, string, error) {
	args := m.Called(ctx, code)
	return args.String(0), args.String(1), args.Error(2)
}
func (m *mockSteps) VerifyCode(ctx context.Context, c *verifyCodeData) (*hubauth.Code, error) {
	args := m.Called(ctx, c)
	return args.Get(0).(*hubauth.Code), args.Error(1)
}
func (m *mockSteps) SignCode(ctx context.Context, signKey hmacpb.Key, code *signCodeData) (string, error) {
	args := m.Called(ctx, signKey, code)
	return args.String(0), args.Error(1)
}
func (m *mockSteps) VerifyAudience(ctx context.Context, audienceURL, clientID, userID string) error {
	args := m.Called(ctx, audienceURL, clientID, userID)
	return args.Error(0)
}
func (m *mockSteps) VerifyUserGroups(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
func (m *mockSteps) AllocateRefreshToken(ctx context.Context, clientID string) (string, error) {
	args := m.Called(ctx, clientID)
	return args.String(0), args.Error(1)
}
func (m *mockSteps) SaveRefreshToken(ctx context.Context, codeID, redirectURI string, t *refreshTokenData) (*hubauth.Client, error) {
	args := m.Called(ctx, codeID, redirectURI, t)
	return args.Get(0).(*hubauth.Client), args.Error(1)
}
func (m *mockSteps) SignRefreshToken(ctx context.Context, signKey signpb.PrivateKey, t *signedRefreshTokenData) (string, error) {
	args := m.Called(ctx, signKey, t)
	return args.String(0), args.Error(1)
}
func (m *mockSteps) SignAccessToken(ctx context.Context, signKey signpb.PrivateKey, t *accessTokenData, now time.Time) (string, error) {
	args := m.Called(ctx, signKey, t, now)
	return args.String(0), args.Error(1)
}
func (m *mockSteps) RenewRefreshToken(ctx context.Context, clientID, oldTokenID string, oldTokenIssueTime, now time.Time) (*hubauth.RefreshToken, error) {
	args := m.Called(ctx, clientID, oldTokenID, oldTokenIssueTime, now)
	return args.Get(0).(*hubauth.RefreshToken), args.Error(1)
}
func (m *mockSteps) VerifyRefreshToken(ctx context.Context, rt *hubauth.RefreshToken, now time.Time) error {
	args := m.Called(ctx, rt, now)
	return args.Error(0)
}

type mockClock struct {
	mock.Mock
}

var _ clock = (*mockClock)(nil)

func (m *mockClock) Now() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func newTestIdPService(t *testing.T, kmsKeys ...string) *idpService {
	dsc, err := gdatastore.NewClient(context.Background(), "test")
	require.NoError(t, err)
	db := datastore.New(dsc)
	authService := new(mockAuthService)

	refreshKeyName := "refreshKey"
	kmsKeys = append(kmsKeys, refreshKeyName)
	kms := kmssim.NewClient(kmsKeys)

	codeKey := make(hmacpb.Key, 32)
	_, err = rand.Read(codeKey)
	require.NoError(t, err)
	require.Equal(t, len(codeKey), 32)

	refreshKey, err := kmssign.NewKey(context.Background(), kms, refreshKeyName)
	require.NoError(t, err)

	s := New(db, authService, kms, codeKey, refreshKey, audienceKeyNamer).(*idpService)
	s.steps = &mockSteps{}
	s.clock = &mockClock{}

	return s
}

func TestIDPServiceAuthorizeUserRedirect(t *testing.T) {
	idpService := newTestIdPService(t)

	clientState := "client state"
	nonce := "nonce"
	challenge := "challenge"
	redirectURI := "http://redirect:1234/uri"

	clientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID: "clientID123",
		RedirectURIs: []string{
			redirectURI,
		},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)

	req := &hubauth.AuthorizeUserRequest{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		ClientState:   clientState,
		Nonce:         nonce,
		CodeChallenge: challenge,
		ResponseMode:  hubauth.ResponseModeQuery,
	}

	expectedURL := "redirect_url"
	expectedState := "rp_state"

	ctx := hubauth.InitClientInfo(context.Background())
	idpService.rp.(*mockAuthService).On("Redirect", ctx).Return(&rp.AuthCodeRedirect{
		URL:   expectedURL,
		State: expectedState,
	}, nil)

	got, err := idpService.AuthorizeUserRedirect(ctx, req)
	require.NoError(t, err)

	want := &hubauth.AuthorizeResponse{
		URL:     expectedURL,
		RPState: expectedState,
	}

	require.Equal(t, want, got)
	require.Equal(t, &hubauth.ClientInfo{
		RedirectURI: req.RedirectURI,
		State:       req.ClientState,
		Fragment:    req.ResponseMode == hubauth.ResponseModeFragment,
	}, hubauth.GetClientInfo(ctx))
}

func TestIDPServiceAuthorizeUserRedirectParameters(t *testing.T) {
	idpService := newTestIdPService(t)

	redirectURI := "http://redirect:1234/uri"

	clientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID: "clientID123",
		RedirectURIs: []string{
			redirectURI,
			oobRedirectURI,
		},
		RefreshTokenExpiry: time.Second * 60,
	})

	require.NoError(t, err)
	clientState := "clientState"
	nonce := "nonce"
	challenge := "challenge"

	testCases := []struct {
		desc        string
		req         *hubauth.AuthorizeUserRequest
		expectedErr error
	}{
		{
			desc: "unknown client",
			req:  &hubauth.AuthorizeUserRequest{},
		},
		{
			desc: "unknown client",
			req: &hubauth.AuthorizeUserRequest{
				ClientID: "unknown",
			},
		},
		{
			desc: "specified redirect_uri is not whitelisted for client",
			req: &hubauth.AuthorizeUserRequest{
				ClientID: clientID,
			},
		},
		{
			desc: "specified redirect_uri is not whitelisted for client",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:    clientID,
				RedirectURI: "invalid",
			},
		},
		{
			desc: "missing state parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:    clientID,
				RedirectURI: redirectURI,
			},
		},
		{
			desc: "missing nonce parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:    clientID,
				RedirectURI: oobRedirectURI,
			},
		},
		{
			desc: "missing nonce parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:    clientID,
				RedirectURI: redirectURI,
				ClientState: clientState,
			},
		},
		{
			desc: "missing code_challenge parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:    clientID,
				RedirectURI: redirectURI,
				ClientState: clientState,
				Nonce:       nonce,
			},
		},
		{
			desc: "invalid response_mode parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:      clientID,
				RedirectURI:   redirectURI,
				ClientState:   clientState,
				Nonce:         nonce,
				CodeChallenge: challenge,
			},
		},
		{
			desc: "invalid response_mode parameter",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:      clientID,
				RedirectURI:   redirectURI,
				ClientState:   clientState,
				Nonce:         nonce,
				CodeChallenge: challenge,
				ResponseMode:  "unknown",
			},
		},
		{
			desc: "rp error",
			req: &hubauth.AuthorizeUserRequest{
				ClientID:      clientID,
				RedirectURI:   redirectURI,
				ClientState:   clientState,
				Nonce:         nonce,
				CodeChallenge: challenge,
				ResponseMode:  hubauth.ResponseModeQuery,
			},
			expectedErr: errors.New("redirect error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			idpService := newTestIdPService(t)
			idpService.rp.(*mockAuthService).On("Redirect", mock.Anything).Return(&rp.AuthCodeRedirect{}, testCase.expectedErr)

			_, err := idpService.AuthorizeUserRedirect(context.Background(), testCase.req)
			if testCase.expectedErr == nil {
				require.EqualError(t, err, testCase.desc)
			} else {
				require.Equal(t, testCase.expectedErr, errors.Unwrap(err))
			}
		})
	}
}

func TestAuthorizeCodeRedirect(t *testing.T) {
	redirectURI := "http://redirect/uri"
	clientState := "clientState"
	signedCode := "signedCode"

	testCases := []struct {
		Desc             string
		RedirectURI      string
		ResponseMode     string
		ValidateResponse func(t *testing.T, resp *hubauth.AuthorizeResponse, err error)
	}{
		{
			Desc:         "returns code in fragment",
			RedirectURI:  redirectURI,
			ResponseMode: hubauth.ResponseModeFragment,
			ValidateResponse: func(t *testing.T, resp *hubauth.AuthorizeResponse, err error) {
				require.NoError(t, err)
				require.Empty(t, resp.DisplayCode)
				require.Empty(t, resp.RPState)
				require.Contains(t, resp.URL, redirectURI)
				require.False(t, resp.Interstitial)

				u, err := url.Parse(resp.URL)
				require.NoError(t, err)

				fragmentValues, err := url.ParseQuery(u.Fragment)
				require.NoError(t, err)
				require.Equal(t, clientState, fragmentValues.Get("state"))
				require.Equal(t, signedCode, fragmentValues.Get("code"))
			},
		},
		{
			Desc:         "returns code in query string",
			RedirectURI:  redirectURI,
			ResponseMode: hubauth.ResponseModeQuery,
			ValidateResponse: func(t *testing.T, resp *hubauth.AuthorizeResponse, err error) {
				require.NoError(t, err)
				require.Empty(t, resp.DisplayCode)
				require.Empty(t, resp.RPState)
				require.Contains(t, resp.URL, redirectURI)
				require.False(t, resp.Interstitial)

				u, err := url.Parse(resp.URL)
				require.NoError(t, err)

				require.Equal(t, clientState, u.Query().Get("state"))
				require.Equal(t, signedCode, u.Query().Get("code"))
			},
		},
		{
			Desc:         "returns DisplayCode when redirectURI is OOB",
			RedirectURI:  oobRedirectURI,
			ResponseMode: hubauth.ResponseModeQuery,
			ValidateResponse: func(t *testing.T, resp *hubauth.AuthorizeResponse, err error) {
				require.NoError(t, err)
				require.Empty(t, resp.RPState)
				require.Empty(t, resp.URL)
				require.Equal(t, signedCode, resp.DisplayCode)
				require.False(t, resp.Interstitial)
			},
		},
		{
			Desc:         "returns Interstitial when redirectURI is localhost",
			RedirectURI:  "http://localhost:8080/",
			ResponseMode: hubauth.ResponseModeQuery,
			ValidateResponse: func(t *testing.T, resp *hubauth.AuthorizeResponse, err error) {
				require.NoError(t, err)
				require.Empty(t, resp.DisplayCode)
				require.Empty(t, resp.RPState)
				require.Contains(t, resp.URL, "http://localhost:8080/")
				require.True(t, resp.Interstitial)

				u, err := url.Parse(resp.URL)
				require.NoError(t, err)

				require.Equal(t, clientState, u.Query().Get("state"))
				require.Equal(t, signedCode, u.Query().Get("code"))
			},
		},
		{
			Desc:         "returns Interstitial when redirectURI is 127.0.0.1",
			RedirectURI:  "http://127.0.0.1/",
			ResponseMode: hubauth.ResponseModeQuery,
			ValidateResponse: func(t *testing.T, resp *hubauth.AuthorizeResponse, err error) {
				require.NoError(t, err)
				require.Empty(t, resp.DisplayCode)
				require.Empty(t, resp.RPState)
				require.Contains(t, resp.URL, "http://127.0.0.1/")
				require.True(t, resp.Interstitial)

				u, err := url.Parse(resp.URL)
				require.NoError(t, err)

				require.Equal(t, clientState, u.Query().Get("state"))
				require.Equal(t, signedCode, u.Query().Get("code"))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			idpService := newTestIdPService(t)

			userID := "userID"
			userEmail := "user@email.com"

			req := &hubauth.AuthorizeCodeRequest{
				AuthorizeUserRequest: hubauth.AuthorizeUserRequest{
					ClientID:      "clientID",
					ClientState:   clientState,
					Nonce:         "nonce",
					CodeChallenge: "challenge",
					RedirectURI:   testCase.RedirectURI,
					ResponseMode:  testCase.ResponseMode,
				},
				RPState: "rpState",
				Params:  url.Values{"exchange": {"params"}},
			}

			redirectResult := &rp.RedirectResult{
				State:  req.RPState,
				Params: req.Params,
			}

			ctx := hubauth.InitClientInfo(context.Background())
			idpService.rp.(*mockAuthService).On("Exchange", mock.Anything, redirectResult).Return(&rp.Token{
				UserID: userID,
				Email:  userEmail,
			}, nil)

			now := time.Now()
			idpService.clock.(*mockClock).On("Now").Return(now)

			codeID := "codeID"
			codeSecret := "codeSecret"
			idpService.steps.(*mockSteps).On("CreateCode", mock.Anything, &hubauth.Code{
				ClientID:      req.ClientID,
				UserID:        userID,
				UserEmail:     userEmail,
				RedirectURI:   req.RedirectURI,
				Nonce:         req.Nonce,
				PKCEChallenge: req.CodeChallenge,
				ExpiryTime:    now.Add(codeExpiry),
			}).Return(codeID, codeSecret, nil)

			idpService.steps.(*mockSteps).On("SignCode", mock.Anything, idpService.codeKey, &signCodeData{
				Key:        codeID,
				Secret:     codeSecret,
				UserID:     userID,
				UserEmail:  userEmail,
				ExpiryTime: now.Add(codeExpiry),
			}).Return(signedCode, nil)

			idpService.steps.(*mockSteps).On("VerifyUserGroups", mock.Anything, userID).Return(nil)

			resp, err := idpService.AuthorizeCodeRedirect(ctx, req)
			testCase.ValidateResponse(t, resp, err)
		})
	}
}

func TestAuthorizeCodeRedirectExchangeErrors(t *testing.T) {
	testCases := []error{
		&hubauth.OAuthError{
			Code:        "access_denied",
			Description: "access_denied desc",
		},
		&hubauth.OAuthError{
			Code:        "temporarily_unavailable",
			Description: "temporarily_unavailable desc",
		},
		errors.New("test error"),
	}

	req := &hubauth.AuthorizeCodeRequest{
		RPState: "rpState",
		Params:  url.Values{"exchange": {"params"}},
	}

	for _, e := range testCases {
		t.Run(e.Error(), func(t *testing.T) {
			ctx := context.Background()
			idpService := newTestIdPService(t)
			idpService.rp.(*mockAuthService).On("Exchange", ctx, &rp.RedirectResult{
				State:  req.RPState,
				Params: req.Params,
			}).Return(&rp.Token{}, e)

			resp, err := idpService.AuthorizeCodeRedirect(ctx, req)
			if _, ok := err.(*hubauth.OAuthError); !ok {
				err = errors.Unwrap(err)
			}
			require.EqualError(t, err, e.Error())
			require.Nil(t, resp)
		})
	}
}

func TestAuthorizeCodeRedirectStepErrors(t *testing.T) {
	now := time.Now()

	expectedErr := errors.New("expected")
	testCases := []struct {
		Desc                string
		VerifyUserGroupsErr error
		CreateCodeErr       error
		SignCodeErr         error
		ExpectedErr         error
		IsUnwrapped         bool
	}{
		{
			Desc:                "VerifyUserGroups error",
			VerifyUserGroupsErr: expectedErr,
			ExpectedErr:         expectedErr,
			IsUnwrapped:         true,
		},
		{
			Desc:          "CreateCode error",
			CreateCodeErr: expectedErr,
			ExpectedErr:   expectedErr,
		},
		{
			Desc:        "SignCode error",
			SignCodeErr: expectedErr,
			ExpectedErr: expectedErr,
			IsUnwrapped: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			idpService := newTestIdPService(t)
			idpService.rp.(*mockAuthService).On("Exchange", mock.Anything, mock.Anything).Return(&rp.Token{}, nil)
			idpService.clock.(*mockClock).On("Now").Return(now)

			idpService.steps.(*mockSteps).On("CreateCode", mock.Anything, mock.Anything).Return("", "", testCase.CreateCodeErr)
			idpService.steps.(*mockSteps).On("SignCode", mock.Anything, mock.Anything, mock.Anything).Return("", testCase.SignCodeErr)
			idpService.steps.(*mockSteps).On("VerifyUserGroups", mock.Anything, mock.Anything).Return(testCase.VerifyUserGroupsErr)

			_, err := idpService.AuthorizeCodeRedirect(context.Background(), &hubauth.AuthorizeCodeRequest{})

			if !testCase.IsUnwrapped {
				err = errors.Unwrap(err)
			}
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}

}

func TestExchangeCode(t *testing.T) {
	clientID := "clientID"
	rtID := "rtID"

	userID := "userID"
	userEmail := "userEmail"

	audienceURL := "audienceURL"
	redirectURI := "http://redirect/uri"

	codeVerifier := "codeVerifier"
	codeID := []byte("codeID")
	b64CodeID := base64Encode(codeID)
	codeSecret := []byte("codeSecret")
	b64CodeSecret := base64Encode(codeSecret)

	nonce := "nonce"
	refreshToken := "refreshToken"
	accessToken := "accessToken"
	refreshTokenExpiry := time.Second * 42

	testCases := []struct {
		Desc        string
		AudienceURL string
		Want        *hubauth.AccessToken
	}{
		{
			Desc:        "returns an access token",
			AudienceURL: audienceURL,
			Want: &hubauth.AccessToken{
				RefreshToken:          refreshToken,
				AccessToken:           accessToken,
				TokenType:             "Bearer",
				ExpiresIn:             int(accessTokenDuration / time.Second),
				Nonce:                 nonce,
				Audience:              audienceURL,
				RefreshTokenExpiresIn: int(refreshTokenExpiry / time.Second),
				RedirectURI:           redirectURI,
			},
		},
		{
			Desc:        "returns a refresh token as access token",
			AudienceURL: "",
			Want: &hubauth.AccessToken{
				RefreshToken:          refreshToken,
				AccessToken:           refreshToken,
				TokenType:             "RefreshToken",
				ExpiresIn:             int(refreshTokenExpiry / time.Second),
				Nonce:                 nonce,
				Audience:              "",
				RefreshTokenExpiresIn: int(refreshTokenExpiry / time.Second),
				RedirectURI:           redirectURI,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {

			idpService := newTestIdPService(t)

			ctx := hubauth.InitClientInfo(context.Background())
			now := time.Now()

			expireTime, _ := ptypes.TimestampProto(now.Add(codeExpiry))
			signedCode, err := hmacpb.SignMarshal(idpService.codeKey, &pb.Code{
				Key:        codeID,
				Secret:     codeSecret,
				UserId:     userID,
				UserEmail:  userEmail,
				ExpireTime: expireTime,
			})
			require.NoError(t, err)

			verifiedCode := &hubauth.Code{
				Nonce: nonce,
			}

			client := &hubauth.Client{
				RefreshTokenExpiry: refreshTokenExpiry,
			}

			rtData := &refreshTokenData{
				Key:       rtID,
				IssueTime: now,
				UserID:    userID,
				UserEmail: userEmail,
				ClientID:  clientID,
			}

			signedRTData := &signedRefreshTokenData{
				refreshTokenData: rtData,
				ExpiryTime:       now.Add(refreshTokenExpiry),
			}

			idpService.clock.(*mockClock).On("Now").Return(now)
			idpService.steps.(*mockSteps).On("AllocateRefreshToken", mock.Anything, clientID).Return(rtID, nil)
			idpService.steps.(*mockSteps).On("VerifyAudience", mock.Anything, testCase.AudienceURL, clientID, userID).Return(nil)
			idpService.steps.(*mockSteps).On("VerifyCode", mock.Anything, &verifyCodeData{
				ClientID:     clientID,
				RedirectURI:  redirectURI,
				CodeVerifier: codeVerifier,
				CodeID:       b64CodeID,
				CodeSecret:   b64CodeSecret,
			}).Return(verifiedCode, nil)
			idpService.steps.(*mockSteps).On("SaveRefreshToken", mock.Anything, b64CodeID, redirectURI, rtData).Return(client, nil)
			idpService.steps.(*mockSteps).On("SignRefreshToken", mock.Anything, idpService.refreshKey, signedRTData).Return(refreshToken, nil)
			idpService.steps.(*mockSteps).On("SignAccessToken", mock.Anything, kmssign.NewPrivateKey(idpService.kms, audienceKeyNamer(audienceURL), crypto.SHA256), &accessTokenData{
				clientID:  clientID,
				userID:    userID,
				userEmail: userEmail,
			}, now).Return(accessToken, nil)

			req := &hubauth.ExchangeCodeRequest{
				ClientID:     clientID,
				Code:         base64Encode(signedCode),
				Audience:     testCase.AudienceURL,
				RedirectURI:  redirectURI,
				CodeVerifier: codeVerifier,
			}
			got, err := idpService.ExchangeCode(ctx, req)
			require.NoError(t, err)

			require.Equal(t, testCase.Want, got)
		})
	}
}

func TestExchangeCodeErrors(t *testing.T) {
	idpService := newTestIdPService(t)
	codeKey := idpService.codeKey
	now := time.Now()

	expiredTime, _ := ptypes.TimestampProto(now.Add(-1 * time.Second))
	expiredCode, err := hmacpb.SignMarshal(codeKey, &pb.Code{
		ExpireTime: expiredTime,
	})
	require.NoError(t, err)

	randomCodeKey := make(hmacpb.Key, 32)
	_, err = rand.Read(randomCodeKey)
	require.NoError(t, err)
	require.Equal(t, len(randomCodeKey), 32)
	wrongKeyCode, err := hmacpb.SignMarshal(randomCodeKey, &pb.Code{
		ExpireTime: expiredTime,
	})
	require.NoError(t, err)

	validTime, _ := ptypes.TimestampProto(now.Add(1 * time.Second))
	validCode, err := hmacpb.SignMarshal(codeKey, &pb.Code{
		ExpireTime: validTime,
	})
	require.NoError(t, err)

	expectedErr := errors.New("expected error")
	testCases := []struct {
		Desc              string
		Code              string
		ExpectedErr       error
		AllocateErr       error
		VerifyCodeErr     error
		VerifyAudienceErr error
		SaveErr           error
		SignRTErr         error
		SignATErr         error
		NeedUnwrap        bool
	}{
		{
			Desc: "invalid base64 code",
			Code: "not b64 valid",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "invalid code encoding",
			},
		},
		{
			Desc: "not a code",
			Code: base64Encode([]byte("not a code")),
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "invalid code",
			},
		},
		{
			Desc: "wrong signature",
			Code: base64Encode(wrongKeyCode),
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "invalid code",
			},
		},
		{
			Desc: "expired code",
			Code: base64Encode(expiredCode),
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "expired code",
			},
		},
		{
			Desc:        "AllocateRefreshToken error",
			Code:        base64Encode(validCode),
			AllocateErr: expectedErr,
			ExpectedErr: expectedErr,
			NeedUnwrap:  true,
		},
		{
			Desc:          "VerifyCode error",
			Code:          base64Encode(validCode),
			VerifyCodeErr: expectedErr,
			ExpectedErr:   expectedErr,
		},
		{
			Desc:        "SaveRefreshToken error",
			Code:        base64Encode(validCode),
			SaveErr:     expectedErr,
			ExpectedErr: expectedErr,
		},
		{
			Desc:        "SignRefreshToken error",
			Code:        base64Encode(validCode),
			SignRTErr:   expectedErr,
			ExpectedErr: expectedErr,
		},
		{
			Desc:        "SignAccessToken error",
			Code:        base64Encode(validCode),
			SignATErr:   expectedErr,
			ExpectedErr: expectedErr,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			idpService := newTestIdPService(t)
			idpService.codeKey = codeKey
			idpService.clock.(*mockClock).On("Now").Return(now)
			idpService.steps.(*mockSteps).On("AllocateRefreshToken", mock.Anything, mock.Anything).Return("", testCase.AllocateErr)
			idpService.steps.(*mockSteps).On("VerifyCode", mock.Anything, mock.Anything).Return(&hubauth.Code{}, testCase.VerifyCodeErr)
			idpService.steps.(*mockSteps).On("VerifyAudience", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(testCase.VerifyAudienceErr)
			idpService.steps.(*mockSteps).On("SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&hubauth.Client{}, testCase.SaveErr)
			idpService.steps.(*mockSteps).On("SignRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return("", testCase.SignRTErr)
			idpService.steps.(*mockSteps).On("SignAccessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", testCase.SignATErr)

			req := &hubauth.ExchangeCodeRequest{
				Code:     testCase.Code,
				Audience: "audience",
			}
			_, err := idpService.ExchangeCode(context.Background(), req)

			if testCase.NeedUnwrap {
				err = errors.Unwrap(err)
			}
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	now := time.Now()

	oldTokenID := []byte("rtID")
	b64OldTokenID := base64Encode(oldTokenID)
	issueTime := now.Add(-10 * time.Second)
	issueTimeProto, _ := ptypes.TimestampProto(issueTime)
	issueTimeFromProto, _ := ptypes.Timestamp(issueTimeProto)
	userID := "userID"
	userEmail := "userEmail"

	clientID := []byte("clientID")
	b64ClientID := base64Encode(clientID)

	audienceURL := "audienceURL"
	redirectURI := "http://redirect/uri"
	refreshTokenExpire := 60 * time.Second
	expireTimeProto, _ := ptypes.TimestampProto(issueTime.Add(refreshTokenExpire))

	newRefreshToken := &hubauth.RefreshToken{
		RedirectURI: redirectURI,
		ExpiryTime:  issueTime.Add(refreshTokenExpire),
	}
	newRefreshTokenStr := "newRefreshTokenStr"
	newAccessTokenStr := "newAccessToken"

	testCases := []struct {
		Desc        string
		AudienceURL string
		Want        *hubauth.AccessToken
	}{
		{
			Desc:        "returns a new access token",
			AudienceURL: audienceURL,
			Want: &hubauth.AccessToken{
				RefreshToken:          newRefreshTokenStr,
				AccessToken:           newAccessTokenStr,
				TokenType:             "Bearer",
				ExpiresIn:             int(accessTokenDuration / time.Second),
				Audience:              audienceURL,
				RefreshTokenExpiresIn: int(time.Until(issueTime.Add(refreshTokenExpire)) / time.Second),
				RedirectURI:           redirectURI,
			},
		},
		{
			Desc:        "returns a new refresh token as access token",
			AudienceURL: "",
			Want: &hubauth.AccessToken{
				RefreshToken:          newRefreshTokenStr,
				AccessToken:           newRefreshTokenStr,
				TokenType:             "RefreshToken",
				ExpiresIn:             int(time.Until(issueTime.Add(refreshTokenExpire)) / time.Second),
				Audience:              "",
				RefreshTokenExpiresIn: int(time.Until(issueTime.Add(refreshTokenExpire)) / time.Second),
				RedirectURI:           redirectURI,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			idpService := newTestIdPService(t)

			idpService.clock.(*mockClock).On("Now").Return(now)
			idpService.steps.(*mockSteps).On("VerifyAudience", mock.Anything, testCase.AudienceURL, b64ClientID, userID).Return(nil)
			idpService.steps.(*mockSteps).On("RenewRefreshToken", mock.Anything, b64ClientID, b64OldTokenID, issueTimeFromProto, now).Return(newRefreshToken, nil)
			idpService.steps.(*mockSteps).On("SignRefreshToken", mock.Anything, idpService.refreshKey, &signedRefreshTokenData{
				refreshTokenData: &refreshTokenData{
					Key:       b64OldTokenID,
					IssueTime: now,
					UserID:    userID,
					UserEmail: userEmail,
					ClientID:  b64ClientID,
				},
				ExpiryTime: expireTimeProto.AsTime(),
			}).Return(newRefreshTokenStr, nil)
			signKey := kmssign.NewPrivateKey(idpService.kms, audienceKeyNamer(testCase.AudienceURL), crypto.SHA256)
			idpService.steps.(*mockSteps).On("SignAccessToken", mock.Anything, signKey, &accessTokenData{
				clientID:  b64ClientID,
				userID:    userID,
				userEmail: userEmail,
			}, now).Return(newAccessTokenStr, nil)

			oldTokenSigned, err := signpb.SignMarshal(context.Background(), idpService.refreshKey, &pb.RefreshToken{
				Key:        oldTokenID,
				IssueTime:  issueTimeProto,
				UserId:     userID,
				UserEmail:  userEmail,
				ClientId:   clientID,
				ExpireTime: expireTimeProto,
			})
			require.NoError(t, err)

			ctx := hubauth.InitClientInfo(context.Background())

			req := &hubauth.RefreshTokenRequest{
				ClientID:     base64Encode(clientID),
				Audience:     testCase.AudienceURL,
				RefreshToken: base64Encode(oldTokenSigned),
			}

			got, err := idpService.RefreshToken(ctx, req)
			require.NoError(t, err)

			require.Equal(t, testCase.Want, got)
		})
	}
}

type invalidRefreshTokenTestCase struct {
	RefreshToken string
	Err          *hubauth.OAuthError
}

func TestRefreshTokenErrors(t *testing.T) {
	wrongKeyName := "wrongKey"
	idpService := newTestIdPService(t, wrongKeyName)
	testCases := prepareInvalidRefreshTokenTestCases(t, idpService, wrongKeyName)
	for _, testCase := range testCases {
		t.Run(testCase.Err.Description, func(t *testing.T) {
			req := &hubauth.RefreshTokenRequest{
				RefreshToken: testCase.RefreshToken,
			}
			_, err := idpService.RefreshToken(context.Background(), req)
			require.EqualError(t, err, testCase.Err.Error())
		})
	}
}

func TestRefreshTokenStepErrors(t *testing.T) {
	expectedErr := errors.New("expected error")
	now := time.Now()

	testCases := []struct {
		Desc              string
		VerifyAudienceErr error
		RenewRTErr        error
		SignRTErr         error
		SignATErr         error
		ExpectedErr       error
	}{
		{
			Desc:              "VerifyAudience error",
			VerifyAudienceErr: expectedErr,
			ExpectedErr:       expectedErr,
		},
		{
			Desc:        "RenewRefreshToken error",
			RenewRTErr:  expectedErr,
			ExpectedErr: expectedErr,
		},
		{
			Desc:        "SignRefreshToken error",
			SignRTErr:   expectedErr,
			ExpectedErr: expectedErr,
		},
		{
			Desc:        "SignAccessToken error",
			SignATErr:   expectedErr,
			ExpectedErr: expectedErr,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			idpService := newTestIdPService(t)

			iss, _ := ptypes.TimestampProto(now)
			expireTime := now.Add(5 * time.Second)
			expireTimeProto, _ := ptypes.TimestampProto(expireTime)
			validRT, err := signpb.SignMarshal(context.Background(), idpService.refreshKey, &pb.RefreshToken{
				IssueTime:  iss,
				ExpireTime: expireTimeProto,
			})
			require.NoError(t, err)

			req := &hubauth.RefreshTokenRequest{
				RefreshToken: base64Encode(validRT),
				Audience:     "audience",
			}

			idpService.clock.(*mockClock).On("Now").Return(now)
			idpService.steps.(*mockSteps).On("VerifyAudience", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(testCase.VerifyAudienceErr)
			idpService.steps.(*mockSteps).On("RenewRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&hubauth.RefreshToken{}, testCase.RenewRTErr)
			idpService.steps.(*mockSteps).On("SignRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return("", testCase.SignRTErr)
			idpService.steps.(*mockSteps).On("SignAccessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", testCase.SignATErr)

			_, err = idpService.RefreshToken(context.Background(), req)
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}
}

func prepareInvalidRefreshTokenTestCases(t *testing.T, idpService *idpService, wrongKeyName string) []*invalidRefreshTokenTestCase {
	wrongKey, err := kmssign.NewKey(context.Background(), idpService.kms, wrongKeyName)
	require.NoError(t, err)

	wrongKeyRefreshToken, err := signpb.SignMarshal(context.Background(), wrongKey, &pb.RefreshToken{})
	require.NoError(t, err)

	now := time.Now()
	expiredTime, _ := ptypes.TimestampProto(now.Add(-1 * time.Second))
	expiredRefreshToken, err := signpb.SignMarshal(context.Background(), idpService.refreshKey, &pb.RefreshToken{
		ExpireTime: expiredTime,
	})
	require.NoError(t, err)

	idpService.clock.(*mockClock).On("Now").Return(now)

	testCases := []*invalidRefreshTokenTestCase{
		{
			RefreshToken: "not b64 valid",
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "malformed refresh_token",
			},
		},
		{
			RefreshToken: base64Encode([]byte("not a refresh token")),
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "invalid refresh_token",
			},
		},
		{
			RefreshToken: base64Encode(wrongKeyRefreshToken),
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "invalid refresh_token",
			},
		},
		{
			RefreshToken: base64Encode(expiredRefreshToken),
			Err: &hubauth.OAuthError{
				Code:        "invalid_grant",
				Description: "expired refresh token",
			},
		},
	}

	return testCases
}

type audienceTestCase struct {
	ClientID  string
	UserID    string
	Audiences []*hubauth.Audience
}

func TestListAudience(t *testing.T) {
	testCases := prepareClientAudiencesDB(t)
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%s - %s", testCase.UserID, testCase.ClientID), func(t *testing.T) {
			idpService := newTestIdPService(t)
			now := time.Now()

			rtID := []byte(testCase.UserID)
			b64RtID := base64Encode(rtID)
			issueTime, _ := ptypes.TimestampProto(now)
			userID := testCase.UserID
			userEmail := testCase.UserID
			clientID, _ := base64Decode(testCase.ClientID)
			b64ClientID := testCase.ClientID

			expireTime := now.Add(5 * time.Second)
			expireTimeProto, _ := ptypes.TimestampProto(expireTime)
			rt, err := signpb.SignMarshal(context.Background(), idpService.refreshKey, &pb.RefreshToken{
				Key:        rtID,
				IssueTime:  issueTime,
				UserId:     userID,
				UserEmail:  userEmail,
				ClientId:   clientID,
				ExpireTime: expireTimeProto,
			})
			require.NoError(t, err)

			idpService.clock.(*mockClock).On("Now").Return(now)
			idpService.steps.(*mockSteps).On("VerifyRefreshToken", mock.Anything, &hubauth.RefreshToken{
				ID:         b64RtID,
				ClientID:   b64ClientID,
				UserID:     userID,
				UserEmail:  userEmail,
				IssueTime:  issueTime.AsTime(),
				ExpiryTime: expireTimeProto.AsTime(),
			}, now).Return(nil)

			ctx := hubauth.InitClientInfo(context.Background())
			req := &hubauth.ListAudiencesRequest{
				RefreshToken: base64Encode(rt),
			}

			want := &hubauth.ListAudiencesResponse{Audiences: testCase.Audiences}
			got, err := idpService.ListAudiences(ctx, req)
			require.NoError(t, err)

			// Unset time on response audiences to ease comparison
			for _, a := range got.Audiences {
				a.CreateTime = time.Time{}
				a.UpdateTime = time.Time{}
			}
			require.EqualValues(t, want, got)
		})
	}
}

// Create the following entities in db:
// user1
// user2
// user3
//
// client1
// client2
//
// group1
//   - user2
//   - user3
//
// group2
//   - user3
//
// audience1
//   - client1
//   - group1
//   - group2
//
// audience2
//  - client1
//  - client2
//  - group2
//
// So we expect the following access:
//
// user1 / client1 : no audience
// user1 / client2 : no audience
// user2 / client1 : audience1
// user2 / client2 : no audience
// user3 / client1 : audience1 audience2
// user3 / client2 : audience2
func prepareClientAudiencesDB(t *testing.T) []*audienceTestCase {
	dsc, err := gdatastore.NewClient(context.Background(), "test")
	require.NoError(t, err)
	db := datastore.New(dsc)

	user1 := "user1"
	user2 := "user2"
	user3 := "user3"

	client1 := &hubauth.Client{ID: "client1"}
	client2 := &hubauth.Client{ID: "client2"}

	client1ID, err := db.CreateClient(context.Background(), client1)
	require.NoError(t, err)
	client2ID, err := db.CreateClient(context.Background(), client2)
	require.NoError(t, err)

	group1 := &hubauth.CachedGroup{GroupID: "group1", Domain: "group1"}
	group1Members := []*hubauth.CachedGroupMember{
		{UserID: user2},
		{UserID: user3},
	}
	group2 := &hubauth.CachedGroup{GroupID: "group2", Domain: "group2"}
	group2Members := []*hubauth.CachedGroupMember{
		{UserID: user3},
	}
	_, err = db.SetCachedGroup(context.Background(), group1, group1Members)
	require.NoError(t, err)
	_, err = db.SetCachedGroup(context.Background(), group2, group2Members)
	require.NoError(t, err)

	audience1 := &hubauth.Audience{
		ClientIDs: []string{client1ID},
		Policies: []*hubauth.GoogleUserPolicy{
			{Groups: []string{group1.GroupID, group2.GroupID}},
		},
	}
	audience2 := &hubauth.Audience{
		ClientIDs: []string{client1ID, client2ID},
		Policies: []*hubauth.GoogleUserPolicy{
			{Groups: []string{group2.GroupID}},
		},
	}
	require.NoError(t, db.CreateAudience(context.Background(), audience1))
	require.NoError(t, db.CreateAudience(context.Background(), audience2))

	return []*audienceTestCase{
		{
			UserID:    user1,
			ClientID:  client1ID,
			Audiences: []*hubauth.Audience{},
		},
		{
			UserID:    user1,
			ClientID:  client2ID,
			Audiences: []*hubauth.Audience{},
		},
		{
			UserID:    user2,
			ClientID:  client1ID,
			Audiences: []*hubauth.Audience{audience1},
		},
		{
			UserID:    user2,
			ClientID:  client2ID,
			Audiences: []*hubauth.Audience{},
		},
		{
			UserID:    user3,
			ClientID:  client1ID,
			Audiences: []*hubauth.Audience{audience1, audience2},
		},
		{
			UserID:    user3,
			ClientID:  client2ID,
			Audiences: []*hubauth.Audience{audience2},
		},
	}
}

func TestListAudienceErrors(t *testing.T) {
	wrongKeyName := "wrongKey"
	idpService := newTestIdPService(t, wrongKeyName)
	testCases := prepareInvalidRefreshTokenTestCases(t, idpService, wrongKeyName)
	for _, testCase := range testCases {
		t.Run(testCase.Err.Description, func(t *testing.T) {
			req := &hubauth.ListAudiencesRequest{
				RefreshToken: testCase.RefreshToken,
			}
			_, err := idpService.ListAudiences(context.Background(), req)
			require.EqualError(t, err, testCase.Err.Error())
		})
	}
}
