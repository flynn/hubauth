package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors/fmt"
)

type mockIdP struct {
	mock.Mock
}

var _ hubauth.IdPService = (*mockIdP)(nil)

func (m *mockIdP) AuthorizeUserRedirect(ctx context.Context, req *hubauth.AuthorizeUserRequest) (*hubauth.AuthorizeResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*hubauth.AuthorizeResponse), args.Error(1)
}
func (m *mockIdP) AuthorizeCodeRedirect(ctx context.Context, req *hubauth.AuthorizeCodeRequest) (*hubauth.AuthorizeResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*hubauth.AuthorizeResponse), args.Error(1)
}
func (m *mockIdP) ExchangeCode(ctx context.Context, req *hubauth.ExchangeCodeRequest) (*hubauth.AccessToken, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*hubauth.AccessToken), args.Error(1)
}
func (m *mockIdP) RefreshToken(ctx context.Context, req *hubauth.RefreshTokenRequest) (*hubauth.AccessToken, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*hubauth.AccessToken), args.Error(1)
}
func (m *mockIdP) ListAudiences(ctx context.Context, req *hubauth.ListAudiencesRequest) (*hubauth.ListAudiencesResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*hubauth.ListAudiencesResponse), args.Error(1)
}

type mockClock struct {
	mock.Mock
}

var _ clock = (*mockClock)(nil)

func (m *mockClock) Now() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func newTestAPI(t *testing.T) *api {
	cookieKey := make(hmacpb.Key, 32)
	_, err := rand.Read(cookieKey)
	require.NoError(t, err)

	return &api{
		Config: Config{
			IdP:       &mockIdP{},
			CookieKey: cookieKey,
		},
		clock: &mockClock{},
	}
}

func TestAuthorizeUser(t *testing.T) {
	authUserReq := &hubauth.AuthorizeUserRequest{
		ClientID:      "clientID",
		RedirectURI:   "redirectURI",
		ClientState:   "state",
		Nonce:         "nonce",
		CodeChallenge: "challenge",
		ResponseMode:  "responseMode",
	}
	authResp := &hubauth.AuthorizeResponse{
		URL:         "http://response/url",
		RPState:     "rpState",
		DisplayCode: "displayCode",
	}

	now := time.Now()

	api := newTestAPI(t)
	api.Config.IdP.(*mockIdP).On("AuthorizeUserRedirect", mock.Anything, authUserReq).Return(authResp, nil)
	api.clock.(*mockClock).On("Now").Return(now)

	params := url.Values{
		"code_challenge_method": {"S256"},
		"response_type":         {"code"},
		"state":                 {authUserReq.ClientState},
		"nonce":                 {authUserReq.Nonce},
		"client_id":             {authUserReq.ClientID},
		"redirect_uri":          {authUserReq.RedirectURI},
		"code_challenge":        {authUserReq.CodeChallenge},
		"response_mode":         {authUserReq.ResponseMode},
	}

	req, err := http.NewRequest("GET", "/authorize", nil)
	require.NoError(t, err)

	req.URL.RawQuery = params.Encode()

	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	expiry, _ := ptypes.TimestampProto(now.Add(cookieExpiry))
	cookieData := &pb.AuthorizeCookie{
		RpState:       authResp.RPState,
		ClientState:   authUserReq.ClientState,
		ClientId:      authUserReq.ClientID,
		RedirectUri:   authUserReq.RedirectURI,
		Nonce:         authUserReq.Nonce,
		CodeChallenge: authUserReq.CodeChallenge,
		ResponseMode:  authUserReq.ResponseMode,
		ExpireTime:    expiry,
	}
	signedCookie, err := hmacpb.SignMarshal(api.CookieKey, cookieData)
	require.NoError(t, err)
	expectedCookie := &http.Cookie{
		Name:     authCookie,
		Value:    base64.URLEncoding.EncodeToString(signedCookie),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	r := rr.Result()
	require.Equal(t, authResp.URL, r.Header.Get("Location"))
	require.Equal(t, expectedCookie.String(), r.Header.Get("Set-Cookie"))
	require.Equal(t, fmt.Sprintf("<a href=\"%s\">Found</a>.\n\n", authResp.URL), rr.Body.String())
}

func TestAuthorizeUserInvalidParams(t *testing.T) {
	testCases := []struct {
		Desc           string
		Params         url.Values
		ExpectedErr    error
		ExpectedStatus int
	}{
		{
			Desc: "invalid code_challenge_method",
			Params: url.Values{
				"code_challenge_method": {"invalid"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "code_challenge_method should be S256",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "invalid response_type",
			Params: url.Values{
				"code_challenge_method": {"S256"},
				"response_type":         {"invalid"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "response_type should be code",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "idp error",
			Params: url.Values{
				"code_challenge_method": {"S256"},
				"response_type":         {"code"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "server_error",
				Description: "internal server error",
			},
			ExpectedStatus: http.StatusInternalServerError,
		},
	}

	for _, testCase := range testCases {
		expectedBody, err := json.Marshal(testCase.ExpectedErr)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/authorize", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.URL.RawQuery = testCase.Params.Encode()
		origin := "randomOrigin"
		req.Header.Set("Origin", origin)
		rr := httptest.NewRecorder()

		api := newTestAPI(t)
		api.clock.(*mockClock).On("Now").Return(time.Now())
		api.Config.IdP.(*mockIdP).On("AuthorizeUserRedirect", mock.Anything, mock.Anything).Return(&hubauth.AuthorizeResponse{}, errors.New("idp error"))

		api.ServeHTTP(rr, req)

		r := rr.Result()
		require.Equal(t, origin, r.Header.Get("Access-Control-Allow-Origin"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Equal(t, string(expectedBody)+"\n", rr.Body.String())
		require.Equal(t, testCase.ExpectedStatus, r.StatusCode)
	}
}

func TestAuthorizeCode(t *testing.T) {
	now := time.Now()
	api := newTestAPI(t)

	params := url.Values{
		"random": {"param"},
	}

	expiry, _ := ptypes.TimestampProto(now.Add(cookieExpiry))
	cookieData := &pb.AuthorizeCookie{
		RpState:       "rpState",
		ClientState:   "clientState",
		ClientId:      "clientID",
		RedirectUri:   "redirectURI",
		Nonce:         "nonce",
		CodeChallenge: "codeChallenge",
		ResponseMode:  "responseMode",
		ExpireTime:    expiry,
	}
	signedCookie, err := hmacpb.SignMarshal(api.CookieKey, cookieData)
	require.NoError(t, err)
	cookie := &http.Cookie{
		Name:     authCookie,
		Value:    base64.URLEncoding.EncodeToString(signedCookie),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	authCodeReq := &hubauth.AuthorizeCodeRequest{
		AuthorizeUserRequest: hubauth.AuthorizeUserRequest{
			ClientID:      cookieData.ClientId,
			RedirectURI:   cookieData.RedirectUri,
			ClientState:   cookieData.ClientState,
			Nonce:         cookieData.Nonce,
			CodeChallenge: cookieData.CodeChallenge,
			ResponseMode:  cookieData.ResponseMode,
		},
		RPState: cookieData.RpState,
		Params:  params,
	}

	authResp := &hubauth.AuthorizeResponse{
		URL: "http://authorize/response/url",
	}

	authRespCode := &hubauth.AuthorizeResponse{
		DisplayCode: "displayCode",
	}

	api.clock.(*mockClock).On("Now").Return(now)
	api.Config.IdP.(*mockIdP).On("AuthorizeCodeRedirect", mock.Anything, authCodeReq).Return(authResp, nil).Once()
	api.Config.IdP.(*mockIdP).On("AuthorizeCodeRedirect", mock.Anything, authCodeReq).Return(authRespCode, nil).Once()

	req, err := http.NewRequest("GET", "/rp/google", nil)
	require.NoError(t, err)

	req.URL.RawQuery = params.Encode()
	req.AddCookie(cookie)

	t.Run("redirect mode", func(t *testing.T) {
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)

		expectedCookie := &http.Cookie{
			Name:   authCookie,
			MaxAge: -1,
		}

		r := rr.Result()
		require.Equal(t, authResp.URL, r.Header.Get("Location"))
		require.Equal(t, expectedCookie.String(), r.Header.Get("Set-Cookie"))
		require.Equal(t, fmt.Sprintf("<a href=\"%s\">Found</a>.\n\n", authResp.URL), rr.Body.String())
	})

	t.Run("displayCode mode", func(t *testing.T) {
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)

		expectedCookie := &http.Cookie{
			Name:   authCookie,
			MaxAge: -1,
		}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, codeDisplayHTML(authRespCode.DisplayCode, buf))

		r := rr.Result()
		require.Equal(t, expectedCookie.String(), r.Header.Get("Set-Cookie"))
		require.Equal(t, buf.String(), rr.Body.String())
	})
}

func TestAuthorizeCodeErrors(t *testing.T) {
	now := time.Now()
	api := newTestAPI(t)

	cookieWrongSignature, err := hmacpb.SignMarshal(hmacpb.Key([]byte("wrong-key")), &pb.AuthorizeCookie{})
	require.NoError(t, err)

	invalidExpireCookie, err := hmacpb.SignMarshal(api.CookieKey, &pb.AuthorizeCookie{
		ExpireTime: nil,
	})
	require.NoError(t, err)

	expireTime, _ := ptypes.TimestampProto(now.Add(-1 * time.Millisecond))
	expiredCookie, err := hmacpb.SignMarshal(api.CookieKey, &pb.AuthorizeCookie{
		ExpireTime: expireTime,
	})
	require.NoError(t, err)

	validExpireTime, _ := ptypes.TimestampProto(now.Add(1 * time.Millisecond))
	validCookie, err := hmacpb.SignMarshal(api.CookieKey, &pb.AuthorizeCookie{
		ExpireTime: validExpireTime,
	})
	require.NoError(t, err)

	testCases := []struct {
		Desc           string
		ExpectedErr    error
		Cookie         *http.Cookie
		ExpectedStatus int
	}{
		{
			Desc: "missing cookie",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "missing auth cookie",
			},
			Cookie:         &http.Cookie{},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "invalid b64 cookie",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "malformed auth cookie",
			},
			Cookie: &http.Cookie{
				Name:  authCookie,
				Value: "not valid b64",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "invalid cookie signature",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid auth cookie",
			},
			Cookie: &http.Cookie{
				Name:  authCookie,
				Value: base64.URLEncoding.EncodeToString(cookieWrongSignature),
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "invalid cookie expiry",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid auth cookie expiry",
			},
			Cookie: &http.Cookie{
				Name:  authCookie,
				Value: base64.URLEncoding.EncodeToString(invalidExpireCookie),
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "expired cookie",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "expired auth cookie",
			},
			Cookie: &http.Cookie{
				Name:  authCookie,
				Value: base64.URLEncoding.EncodeToString(expiredCookie),
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "idp error",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "server_error",
				Description: "internal server error",
			},
			Cookie: &http.Cookie{
				Name:  authCookie,
				Value: base64.URLEncoding.EncodeToString(validCookie),
			},
			ExpectedStatus: http.StatusInternalServerError,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			expectedBody, err := json.Marshal(testCase.ExpectedErr)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/rp/google", nil)
			require.NoError(t, err)

			origin := "randomOrigin"
			req.Header.Set("Origin", origin)
			req.AddCookie(testCase.Cookie)

			api.clock.(*mockClock).On("Now").Return(now)
			api.Config.IdP.(*mockIdP).On("AuthorizeCodeRedirect", mock.Anything, mock.Anything).Return(&hubauth.AuthorizeResponse{}, errors.New("idp error"))

			rr := httptest.NewRecorder()
			api.ServeHTTP(rr, req)

			r := rr.Result()
			require.Equal(t, origin, r.Header.Get("Access-Control-Allow-Origin"))
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Equal(t, string(expectedBody)+"\n", rr.Body.String())
			require.Equal(t, testCase.ExpectedStatus, r.StatusCode)
		})
	}
}

func TestTokenAuthorizationCode(t *testing.T) {
	api := newTestAPI(t)

	now := time.Now()

	audienceURLFull := "https://audience:1234"
	expectedAudienceURL := "https://audience"

	redirectURLFull := "http://redirect/url"
	expectedAccessControl := "http://redirect"

	exchangeReq := &hubauth.ExchangeCodeRequest{
		ClientID:     "clientID",
		Audience:     expectedAudienceURL,
		RedirectURI:  redirectURLFull,
		Code:         "code",
		CodeVerifier: "codeVerifier",
	}

	accessToken := &hubauth.AccessToken{
		RefreshToken:          "refreshToken",
		AccessToken:           "accessToken",
		TokenType:             "Bearer",
		ExpiresIn:             60,
		Nonce:                 "nonce",
		Audience:              exchangeReq.Audience,
		RefreshTokenExpiresIn: 120,
		RefreshTokenIssueTime: now,
		RedirectURI:           exchangeReq.RedirectURI,
	}

	api.clock.(*mockClock).On("Now").Return(now)
	api.Config.IdP.(*mockIdP).On("ExchangeCode", mock.Anything, exchangeReq).Return(accessToken, nil).Once()

	req, err := http.NewRequest("POST", "/token", nil)
	require.NoError(t, err)
	req.PostForm = url.Values{
		"audience":      {audienceURLFull},
		"client_id":     {exchangeReq.ClientID},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {exchangeReq.RedirectURI},
		"code":          {exchangeReq.Code},
		"code_verifier": {exchangeReq.CodeVerifier},
	}

	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	r := rr.Result()
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, expectedAccessControl, r.Header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "application/json", r.Header.Get("Content-Type"))

	want := *accessToken
	want.RedirectURI = ""

	got := new(hubauth.AccessToken)
	require.NoError(t, json.NewDecoder(r.Body).Decode(got))
	r.Body.Close()

	// require.Equal doesn't work with timestamps that have been deserialized
	require.WithinDuration(t, want.RefreshTokenIssueTime, got.RefreshTokenIssueTime, 0)
	want.RefreshTokenIssueTime = time.Time{}
	got.RefreshTokenIssueTime = time.Time{}

	require.Equal(t, &want, got)
}

func TestTokenRefreshToken(t *testing.T) {
	api := newTestAPI(t)

	now := time.Now()

	audienceURLFull := "https://audience:1234"
	expectedAudienceURL := "https://audience"

	redirectURLFull := "http://redirect/url"
	expectedAccessControl := "http://redirect"

	refreshReq := &hubauth.RefreshTokenRequest{
		ClientID:     "clientID",
		Audience:     expectedAudienceURL,
		RefreshToken: "refreshToken",
	}

	accessToken := &hubauth.AccessToken{
		RefreshToken:          "refreshToken",
		AccessToken:           "accessToken",
		TokenType:             "Bearer",
		ExpiresIn:             60,
		Nonce:                 "nonce",
		Audience:              refreshReq.Audience,
		RefreshTokenExpiresIn: 120,
		RefreshTokenIssueTime: now,
		RedirectURI:           redirectURLFull,
	}

	api.clock.(*mockClock).On("Now").Return(now)
	api.Config.IdP.(*mockIdP).On("RefreshToken", mock.Anything, refreshReq).Return(accessToken, nil).Once()

	req, err := http.NewRequest("POST", "/token", nil)
	require.NoError(t, err)
	req.PostForm = url.Values{
		"audience":      {audienceURLFull},
		"client_id":     {refreshReq.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshReq.RefreshToken},
	}

	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	r := rr.Result()
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, expectedAccessControl, r.Header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "application/json", r.Header.Get("Content-Type"))

	want := *accessToken
	want.RedirectURI = ""

	got := new(hubauth.AccessToken)
	require.NoError(t, json.NewDecoder(r.Body).Decode(got))
	r.Body.Close()

	// require.Equal doesn't work with timestamps that have been deserialized
	require.WithinDuration(t, want.RefreshTokenIssueTime, got.RefreshTokenIssueTime, 0)
	want.RefreshTokenIssueTime = time.Time{}
	got.RefreshTokenIssueTime = time.Time{}

	require.Equal(t, &want, got)
}

func TestTokenErrors(t *testing.T) {
	api := newTestAPI(t)

	now := time.Now()
	api.clock.(*mockClock).On("Now").Return(now)

	origin := "someOrigin"

	invalidAudiences := map[string]string{
		"invalid url":    "://invalid",
		"not https":      "http://invalid",
		"path not empty": "https://invalid/path",
		"relative url":   "/relative",
	}

	type testCase struct {
		Desc           string
		Form           url.Values
		ExpectedErr    error
		ExpectedStatus int
	}

	testCases := []testCase{
		{
			Desc: "invalid form",
			Form: nil,
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid form POST",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "empty client_id",
			Form: url.Values{
				"client_id": {""},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "missing client_id",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "unknown grant_type",
			Form: url.Values{
				"client_id":  {"notEmpty"},
				"grant_type": {"invalid"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid grant_type",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc: "idp ExchangeCode returns error",
			Form: url.Values{
				"client_id":  {"notEmpty"},
				"grant_type": {"authorization_code"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "server_error",
				Description: "internal server error",
			},
			ExpectedStatus: http.StatusInternalServerError,
		},
		{
			Desc: "idp RefreshToken returns error",
			Form: url.Values{
				"client_id":  {"notEmpty"},
				"grant_type": {"refresh_token"},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "server_error",
				Description: "internal server error",
			},
			ExpectedStatus: http.StatusInternalServerError,
		},
	}

	for desc, invalidAudience := range invalidAudiences {
		testCases = append(testCases, testCase{
			Desc: fmt.Sprintf("audience: %s", desc),
			Form: url.Values{
				"audience": {invalidAudience},
			},
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid audience",
			},
			ExpectedStatus: http.StatusBadRequest,
		})
	}

	api.Config.IdP.(*mockIdP).On("ExchangeCode", mock.Anything, mock.Anything).Return(&hubauth.AccessToken{}, errors.New("EchangeCode error"))
	api.Config.IdP.(*mockIdP).On("RefreshToken", mock.Anything, mock.Anything).Return(&hubauth.AccessToken{}, errors.New("RefreshToken error"))

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			expectedBody, err := json.Marshal(testCase.ExpectedErr)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/token", nil)
			require.NoError(t, err)
			req.PostForm = testCase.Form
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			api.ServeHTTP(rr, req)

			r := rr.Result()
			require.Equal(t, origin, r.Header.Get("Access-Control-Allow-Origin"))
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Equal(t, string(expectedBody)+"\n", rr.Body.String())
			require.Equal(t, testCase.ExpectedStatus, r.StatusCode)
		})
	}
}

func TestAudiences(t *testing.T) {
	api := newTestAPI(t)

	req, err := http.NewRequest("GET", "/audiences", nil)
	require.NoError(t, err)

	refreshToken := "someRefreshToken"
	req.Header.Set("Authorization", fmt.Sprintf("RefreshToken %s", refreshToken))

	now := time.Now()
	api.clock.(*mockClock).On("Now").Return(now)

	audience1 := &hubauth.Audience{
		URL:        "audURL",
		Name:       "audName",
		Type:       "audType",
		ClientIDs:  []string{"client1", "client2"},
		UserGroups: []*hubauth.GoogleUserGroups{{Domain: "domain"}},
		CreateTime: now,
		UpdateTime: now,
	}

	audience2 := &hubauth.Audience{
		URL:        "anotherAudURL",
		Name:       "anotherAudName",
		Type:       "anotherAudType",
		ClientIDs:  []string{"client1", "client2"},
		UserGroups: []*hubauth.GoogleUserGroups{{Domain: "domain"}},
		CreateTime: now,
		UpdateTime: now,
	}

	api.Config.IdP.(*mockIdP).On("ListAudiences", mock.Anything, &hubauth.ListAudiencesRequest{
		RefreshToken: refreshToken,
	}).Return(&hubauth.ListAudiencesResponse{
		Audiences: []*hubauth.Audience{audience1, audience2},
	}, nil)

	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	r := rr.Result()
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, "*", r.Header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "application/json", r.Header.Get("Content-Type"))

	want := &hubauth.ListAudiencesResponse{
		Audiences: []*hubauth.Audience{
			{
				URL:  audience1.URL,
				Name: audience1.Name,
				Type: audience1.Type,
			},
			{
				URL:  audience2.URL,
				Name: audience2.Name,
				Type: audience2.Type,
			},
		},
	}

	got := new(hubauth.ListAudiencesResponse)
	require.NoError(t, json.NewDecoder(r.Body).Decode(got))

	require.Equal(t, want, got)
}

func TestAudiencesErrors(t *testing.T) {
	api := newTestAPI(t)

	now := time.Now()
	api.clock.(*mockClock).On("Now").Return(now)

	origin := "someOrigin"

	testCases := []struct {
		Desc           string
		Authorization  string
		ExpectedErr    error
		ExpectedStatus int
	}{
		{
			Desc:          "missing authorization header",
			Authorization: "",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "missing refresh token authorization",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc:          "invalid authorization header",
			Authorization: "Bearer someAccessToken",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "missing refresh token authorization",
			},
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Desc:          "idp ListAudiences returns error",
			Authorization: "RefreshToken validRefreshToken",
			ExpectedErr: &hubauth.OAuthError{
				Code:        "server_error",
				Description: "internal server error",
			},
			ExpectedStatus: http.StatusInternalServerError,
		},
	}

	api.Config.IdP.(*mockIdP).On("ListAudiences", mock.Anything, mock.Anything).Return(&hubauth.ListAudiencesResponse{}, errors.New("idp error"))

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			expectedBody, err := json.Marshal(testCase.ExpectedErr)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/audiences", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", testCase.Authorization)
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			api.ServeHTTP(rr, req)

			r := rr.Result()
			require.Equal(t, origin, r.Header.Get("Access-Control-Allow-Origin"))
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Equal(t, string(expectedBody)+"\n", rr.Body.String())
			require.Equal(t, testCase.ExpectedStatus, r.StatusCode)
		})
	}
}

func TestAPIAudiencesOptions(t *testing.T) {
	origin := "someOrigin"

	api := newTestAPI(t)
	now := time.Now()
	api.clock.(*mockClock).On("Now").Return(now)

	req, err := http.NewRequest("OPTIONS", "/audiences", nil)
	req.Header.Set("Origin", origin)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	r := rr.Result()
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, origin, r.Header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "Authorization", r.Header.Get("Access-Control-Allow-Headers"))
	require.Equal(t, "GET", r.Header.Get("Access-Control-Allow-Methods"))
	require.Equal(t, "86400", r.Header.Get("Access-Control-Max-Age"))
}

func TestAPIOtherEndpoints(t *testing.T) {
	testCases := []struct {
		Desc             string
		Endpoint         string
		Method           string
		ExpectedLocation string
		ExpectedStatus   int
	}{
		{
			Desc:             "/ redirect to https://flynn.io/",
			Endpoint:         "/",
			Method:           "GET",
			ExpectedLocation: "https://flynn.io/",
			ExpectedStatus:   http.StatusFound,
		},
		{
			Desc:             "/privacy redirect to https://flynn.io/legal/privacy",
			Endpoint:         "/privacy",
			Method:           "GET",
			ExpectedLocation: "https://flynn.io/legal/privacy",
			ExpectedStatus:   http.StatusFound,
		},
		{
			Desc:           "PUT are rejected",
			Endpoint:       "/authorize",
			Method:         "PUT",
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
		{
			Desc:           "POST are rejected",
			Endpoint:       "/rp/google",
			Method:         "POST",
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
		{
			Desc:           "DELETE are rejected",
			Endpoint:       "/token",
			Method:         "DELETE",
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
		{
			Desc:           "PATCH are rejected",
			Endpoint:       "/token",
			Method:         "PATCH",
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
		{
			Desc:           "unmapped GET returns 404",
			Endpoint:       "/unknow",
			Method:         "GET",
			ExpectedStatus: http.StatusNotFound,
		},
	}

	api := newTestAPI(t)
	now := time.Now()
	api.clock.(*mockClock).On("Now").Return(now)

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			req, err := http.NewRequest(testCase.Method, testCase.Endpoint, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			api.ServeHTTP(rr, req)

			r := rr.Result()
			require.Equal(t, testCase.ExpectedStatus, r.StatusCode)
			if testCase.ExpectedLocation != "" {
				require.Equal(t, testCase.ExpectedLocation, r.Header.Get("Location"))
			}
		})
	}
}
