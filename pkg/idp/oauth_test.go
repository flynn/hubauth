package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	ctx := context.Background()
	refreshKey, err := kmssign.NewKey(ctx, kms, refreshKeyName)
	require.NoError(t, err)

	return New(db, authService, kms, codeKey, refreshKey, audienceKeyNamer).(*idpService)
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
		desc string
		req  *hubauth.AuthorizeUserRequest
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
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			_, err := idpService.AuthorizeUserRedirect(context.Background(), testCase.req)
			require.EqualError(t, err, testCase.desc)
		})
	}
}

func TestAuthorizeCodeRedirect(t *testing.T) {
	idpService := newTestIdPService(t)

	redirectURI := "http://redirect/url"
	clientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID: "clientID123",
		RedirectURIs: []string{
			redirectURI,
			oobRedirectURI,
		},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)

	userID := "userID"
	userEmail := "user@email.com"
	idpService.db.SetCachedGroup(context.Background(), &hubauth.CachedGroup{
		Domain:  "group1Domain",
		GroupID: "group1",
		Email:   "group1@group1Domain",
	}, []*hubauth.CachedGroupMember{{UserID: userID, Email: userEmail}})

	req := &hubauth.AuthorizeCodeRequest{
		AuthorizeUserRequest: hubauth.AuthorizeUserRequest{
			ClientID:      clientID,
			ClientState:   "clientState",
			Nonce:         "nonce",
			CodeChallenge: "challenge",
		},
		RPState: "rpState",
		Params:  url.Values{"exchange": {"params"}},
	}

	redirectResult := &rp.RedirectResult{
		State:  req.RPState,
		Params: req.Params,
	}

	ctx := hubauth.InitClientInfo(context.Background())
	idpService.rp.(*mockAuthService).On("Exchange", ctx, redirectResult).Return(&rp.Token{
		UserID: userID,
		Email:  userEmail,
	}, nil)

	t.Run("AuthorizeCodeRedirect returns a valid code in fragment", func(t *testing.T) {
		req.RedirectURI = redirectURI
		req.ResponseMode = hubauth.ResponseModeFragment

		resp, err := idpService.AuthorizeCodeRedirect(ctx, req)
		require.NoError(t, err)
		require.Empty(t, resp.DisplayCode)
		require.Empty(t, resp.RPState)
		require.Contains(t, resp.URL, req.RedirectURI)

		u, err := url.Parse(resp.URL)
		require.NoError(t, err)

		fragmentValues, err := url.ParseQuery(u.Fragment)
		require.NoError(t, err)
		require.Equal(t, req.ClientState, fragmentValues.Get("state"))

		assertValidCode(t, idpService.codeKey, fragmentValues.Get("code"), userID, userEmail)
	})

	t.Run("AuthorizeCodeRedirect returns a valid code in query string", func(t *testing.T) {
		req.RedirectURI = redirectURI
		req.ResponseMode = hubauth.ResponseModeQuery

		resp, err := idpService.AuthorizeCodeRedirect(ctx, req)
		require.NoError(t, err)
		require.Empty(t, resp.DisplayCode)
		require.Empty(t, resp.RPState)
		require.Contains(t, resp.URL, req.RedirectURI)

		u, err := url.Parse(resp.URL)
		require.NoError(t, err)

		require.Equal(t, req.ClientState, u.Query().Get("state"))
		assertValidCode(t, idpService.codeKey, u.Query().Get("code"), userID, userEmail)
	})

	t.Run("AuthorizeCodeRedirect returns DisplayCode when redirectURI is OOB", func(t *testing.T) {
		req.RedirectURI = oobRedirectURI
		resp, err := idpService.AuthorizeCodeRedirect(ctx, req)
		require.NoError(t, err)
		require.NotEmpty(t, resp.DisplayCode)
		require.Empty(t, resp.RPState)
		require.Empty(t, resp.URL)

		assertValidCode(t, idpService.codeKey, resp.DisplayCode, userID, userEmail)
	})
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

func TestAuthorizeCodeRedirectUserWithoutGroup(t *testing.T) {
	idpService := newTestIdPService(t)

	redirectURI := "http://redirect/uri"
	clientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID: "clientID123",
		RedirectURIs: []string{
			redirectURI,
		},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)

	req := &hubauth.AuthorizeCodeRequest{
		AuthorizeUserRequest: hubauth.AuthorizeUserRequest{
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			ClientState:   "clientState",
			Nonce:         "nonce",
			CodeChallenge: "challenge",
			ResponseMode:  hubauth.ResponseModeFragment,
		},
		RPState: "rp_state",
		Params:  url.Values{"req": {"params"}},
	}

	ctx := hubauth.InitClientInfo(context.Background())
	redirectResult := &rp.RedirectResult{
		State:  req.RPState,
		Params: req.Params,
	}

	idpService.rp.(*mockAuthService).On("Exchange", ctx, redirectResult).Return(&rp.Token{
		UserID: "userIDNoGroup",
		Email:  "userEmailNoGroup",
	}, nil)

	_, err = idpService.AuthorizeCodeRedirect(ctx, req)
	require.EqualError(t, err, hubauth.OAuthError{
		Code:        "access_denied",
		Description: "unknown user",
	}.Error())
}

func TestExchangeCode(t *testing.T) {
	audienceURL := "testAudienceURL"

	idpService := newTestIdPService(t, audienceKeyNamer(audienceURL))

	redirectURI := "http://redirect/uri"
	client := &hubauth.Client{
		ID:                 "clientID123",
		RedirectURIs:       []string{redirectURI},
		RefreshTokenExpiry: time.Second * 60,
	}
	clientID, err := idpService.db.CreateClient(context.Background(), client)
	require.NoError(t, err)

	userID := "userID"
	userEmail := "user@email.com"

	group := &hubauth.CachedGroup{
		Domain:  "group1Domain",
		GroupID: "group1",
		Email:   "group1@group1Domain",
	}
	_, err = idpService.db.SetCachedGroup(context.Background(), group, []*hubauth.CachedGroupMember{{UserID: userID, Email: userEmail}})
	require.NoError(t, err)

	err = idpService.db.CreateAudience(context.Background(), &hubauth.Audience{
		URL:       audienceURL,
		Name:      "testAudience",
		ClientIDs: []string{clientID},
		Policies:  []*hubauth.GoogleUserPolicy{{Groups: []string{group.GroupID}}},
	})
	require.NoError(t, err)

	codeVerifier := "pkceChallenge"
	chall := sha256.Sum256([]byte(codeVerifier))
	challenge := base64Encode(chall[:])

	expiryTime := time.Now().Add(codeExpiry)
	nonce := "nonce"

	code := &hubauth.Code{
		ClientID:      clientID,
		UserID:        userID,
		UserEmail:     userEmail,
		RedirectURI:   redirectURI,
		Nonce:         nonce,
		PKCEChallenge: challenge,
		ExpiryTime:    expiryTime,
	}
	codeID, codeSecret, err := idpService.db.CreateCode(context.Background(), code)
	require.NoError(t, err)

	keyBytes, err := base64Decode(codeID)
	require.NoError(t, err)

	secretBytes, err := base64Decode(codeSecret)
	require.NoError(t, err)

	signedCode, err := hmacpb.SignMarshal(idpService.codeKey, &pb.Code{
		Key:       keyBytes,
		Secret:    secretBytes,
		UserId:    code.UserID,
		UserEmail: code.UserEmail,
	})
	require.NoError(t, err)

	ctx := hubauth.InitClientInfo(context.Background())
	req := &hubauth.ExchangeCodeRequest{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Audience:     audienceURL,
		Code:         base64Encode(signedCode),
		CodeVerifier: codeVerifier,
	}

	t.Run("ExchangeCode returns valid AccessToken and RefreshToken", func(t *testing.T) {
		got, err := idpService.ExchangeCode(ctx, req)
		require.NoError(t, err)

		assertValidHubauthAccessToken(t, idpService, got, &expectedAccessTokenData{
			clientID:           clientID,
			audienceURL:        audienceURL,
			userID:             userID,
			userEmail:          userEmail,
			redirectURI:        redirectURI,
			codeID:             codeID,
			refreshTokenExpiry: client.RefreshTokenExpiry,
			tokenType:          "Bearer",
			nonce:              nonce,
		})

		// Exchanging same code must fail, and delete the refresh token from DB
		rt, err := idpService.decodeRefreshToken(context.Background(), got.RefreshToken)
		require.NoError(t, err)

		_, err = idpService.ExchangeCode(ctx, req)
		require.Error(t, err)
		_, err = idpService.db.GetRefreshToken(context.Background(), rt.ID)
		require.EqualError(t, errors.Unwrap(err), hubauth.ErrNotFound.Error())
	})

	t.Run("ExchangeCode with no audience returns the refreshToken as accessToken", func(t *testing.T) {
		codeID, codeSecret, err := idpService.db.CreateCode(context.Background(), &hubauth.Code{
			ClientID:      clientID,
			PKCEChallenge: challenge,
			RedirectURI:   redirectURI,
			Nonce:         nonce,
		})
		require.NoError(t, err)

		validCode, err := idpService.signCode(&codeData{
			Key:       codeID,
			Secret:    codeSecret,
			UserID:    "userID",
			UserEmail: "userEmail",
		})
		require.NoError(t, err)

		req.Code = validCode
		req.Audience = ""

		got, err := idpService.ExchangeCode(ctx, req)
		require.NoError(t, err)

		assertValidHubauthAccessToken(t, idpService, got, &expectedAccessTokenData{
			clientID:           clientID,
			userID:             "userID",
			userEmail:          "userEmail",
			redirectURI:        redirectURI,
			codeID:             codeID,
			refreshTokenExpiry: client.RefreshTokenExpiry,
			tokenType:          "RefreshToken",
			nonce:              nonce,
		})
	})
}

func TestExchangeCodeErrors(t *testing.T) {
	ctx := hubauth.InitClientInfo(context.Background())
	idpService := newTestIdPService(t)

	redirectURI := "http://redirect/uri"

	clientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID:                 "clientID123",
		RedirectURIs:       []string{redirectURI},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)
	mismatchedClientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID:                 "clientID456",
		RedirectURIs:       []string{redirectURI},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)

	deletedClientID, err := idpService.db.CreateClient(context.Background(), &hubauth.Client{
		ID:                 "deletedClientID",
		RedirectURIs:       []string{redirectURI},
		RefreshTokenExpiry: time.Second * 60,
	})
	require.NoError(t, err)
	require.NoError(t, idpService.db.DeleteClient(context.Background(), deletedClientID))

	codeKey := make(hmacpb.Key, 32)
	_, err = rand.Read(codeKey)
	require.NoError(t, err)

	signedCodeWrongKey, err := hmacpb.SignMarshal(codeKey, &pb.Code{
		Key:       []byte("codeID"),
		Secret:    []byte("codeSecret"),
		UserId:    "userID",
		UserEmail: "userEmail",
	})
	require.NoError(t, err)

	signedCodeNotStored, err := hmacpb.SignMarshal(idpService.codeKey, &pb.Code{
		Key:       []byte("codeID"),
		Secret:    []byte("codeSecret"),
		UserId:    "userID",
		UserEmail: "userEmail",
	})
	require.NoError(t, err)

	verifier := "verifier_code"
	chall := sha256.Sum256([]byte(verifier))
	challenge := base64Encode(chall[:])

	randomValidCode := func() string {
		codeID, codeSecret, err := idpService.db.CreateCode(context.Background(), &hubauth.Code{
			ClientID:      clientID,
			PKCEChallenge: challenge,
			RedirectURI:   redirectURI,
		})
		require.NoError(t, err)
		validCode, err := idpService.signCode(&codeData{
			Key:       codeID,
			Secret:    codeSecret,
			UserID:    "userID",
			UserEmail: "userEmail",
		})
		require.NoError(t, err)

		return validCode
	}

	audienceNoClient := "audienceNoClient"
	err = idpService.db.CreateAudience(context.Background(), &hubauth.Audience{
		URL:       audienceNoClient,
		Name:      "audienceNoClient",
		ClientIDs: []string{},
		Policies:  []*hubauth.GoogleUserPolicy{{Groups: []string{}}},
	})
	require.NoError(t, err)

	audienceNoPolicy := "audienceNoPolicy"
	err = idpService.db.CreateAudience(context.Background(), &hubauth.Audience{
		URL:       audienceNoPolicy,
		Name:      "audienceNoPolicy",
		ClientIDs: []string{clientID},
		Policies:  []*hubauth.GoogleUserPolicy{{Groups: []string{}}},
	})
	require.NoError(t, err)

	testCases := []struct {
		Code string
		Desc string
		Req  *hubauth.ExchangeCodeRequest
	}{
		{
			Code: "invalid_grant",
			Desc: "invalid code encoding",
			Req:  &hubauth.ExchangeCodeRequest{Code: "not base64"},
		},
		{
			Code: "invalid_grant",
			Desc: "invalid code",
			Req:  &hubauth.ExchangeCodeRequest{Code: base64Encode([]byte("not base64"))},
		},
		{
			Code: "invalid_grant",
			Desc: "invalid code",
			Req:  &hubauth.ExchangeCodeRequest{Code: base64Encode(signedCodeWrongKey)},
		},
		{
			Code: "invalid_grant",
			Desc: "code is malformed or has already been exchanged",
			Req:  &hubauth.ExchangeCodeRequest{Code: base64Encode(signedCodeNotStored), ClientID: clientID},
		},
		{
			Code: "invalid_client",
			Desc: "unknown client",
			Req:  &hubauth.ExchangeCodeRequest{Code: randomValidCode(), ClientID: deletedClientID},
		},
		{
			Code: "invalid_grant",
			Desc: "client_id mismatch",
			Req:  &hubauth.ExchangeCodeRequest{Code: randomValidCode(), ClientID: mismatchedClientID},
		},
		{
			Code: "invalid_grant",
			Desc: "redirect_uri mismatch",
			Req:  &hubauth.ExchangeCodeRequest{Code: randomValidCode(), ClientID: clientID, RedirectURI: "mismatched"},
		},
		{
			Code: "invalid_request",
			Desc: "code_verifier mismatch",
			Req:  &hubauth.ExchangeCodeRequest{Code: randomValidCode(), ClientID: clientID, RedirectURI: redirectURI, CodeVerifier: "invalid"},
		},
		{
			Code: "invalid_request",
			Desc: "unknown audience",
			Req: &hubauth.ExchangeCodeRequest{
				Code:         randomValidCode(),
				ClientID:     clientID,
				RedirectURI:  redirectURI,
				CodeVerifier: verifier,
				Audience:     "unknown",
			},
		},
		{
			Code: "invalid_client",
			Desc: "unknown client for audience",
			Req: &hubauth.ExchangeCodeRequest{
				Code:         randomValidCode(),
				ClientID:     clientID,
				RedirectURI:  redirectURI,
				CodeVerifier: verifier,
				Audience:     audienceNoClient,
			},
		},
		{
			Code: "invalid_client",
			Desc: "user is not authorized for access",
			Req: &hubauth.ExchangeCodeRequest{
				Code:         randomValidCode(),
				ClientID:     clientID,
				RedirectURI:  redirectURI,
				CodeVerifier: verifier,
				Audience:     audienceNoPolicy,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			_, err := idpService.ExchangeCode(ctx, testCase.Req)
			require.EqualError(t, err, hubauth.OAuthError{
				Code:        testCase.Code,
				Description: testCase.Desc,
			}.Error())
		})
	}
}

func assertValidCode(t *testing.T, codeKey []byte, b64code, userID, userEmail string) {
	code, err := base64Decode(b64code)
	require.NoError(t, err)

	codeInfo := &pb.Code{}
	require.NoError(t, hmacpb.VerifyUnmarshal(codeKey, code, codeInfo))
	require.Equal(t, userID, codeInfo.UserId)
	require.Equal(t, userEmail, codeInfo.UserEmail)
}

func assertValidAccessToken(t *testing.T, key signpb.PublicKey, b64AccessToken, clientID, userID, userEmail string) {
	accessToken, err := base64Decode(b64AccessToken)
	require.NoError(t, err)

	verified := new(pb.AccessToken)
	err = signpb.VerifyUnmarshal(key, accessToken, verified)
	require.NoError(t, err)

	require.Equal(t, clientID, verified.ClientId)
	require.Equal(t, userID, verified.UserId)
	require.Equal(t, userEmail, verified.UserEmail)

	require.Equal(t, time.Now().Unix(), verified.IssueTime.Seconds)
	require.Equal(t, time.Now().Add(accessTokenDuration).Unix(), verified.ExpireTime.Seconds)
}

func assertValidRefreshToken(t *testing.T, key signpb.PublicKey, b64RefreshToken, clientID, userID, userEmail string) string {
	refreshToken, err := base64Decode(b64RefreshToken)
	require.NoError(t, err)

	verified := new(pb.RefreshToken)
	err = signpb.VerifyUnmarshal(key, refreshToken, verified)
	require.NoError(t, err)

	require.NotEmpty(t, verified.Key)
	require.Equal(t, clientID, base64Encode(verified.ClientId))
	require.Equal(t, userID, verified.UserId)
	require.Equal(t, userEmail, verified.UserEmail)

	require.Equal(t, time.Now().Unix(), verified.IssueTime.Seconds)

	return base64Encode(verified.Key)
}

type expectedAccessTokenData struct {
	clientID    string
	audienceURL string

	userID      string
	userEmail   string
	redirectURI string

	codeID string

	tokenType          string
	nonce              string
	refreshTokenExpiry time.Duration
}

func assertValidHubauthAccessToken(t *testing.T, idpService *idpService, got *hubauth.AccessToken, e *expectedAccessTokenData) {
	require.Equal(t, e.tokenType, got.TokenType)
	switch e.tokenType {
	case "Bearer":
		require.Equal(t, int(accessTokenDuration/time.Second), got.ExpiresIn)
		k, err := kmssign.NewKey(context.Background(), idpService.kms, audienceKeyNamer(e.audienceURL))
		require.NoError(t, err)

		assertValidAccessToken(t, k, got.AccessToken, e.clientID, e.userID, e.userEmail)
	case "RefreshToken":
		require.Equal(t, got.RefreshToken, got.AccessToken)
		require.Equal(t, got.RefreshTokenExpiresIn, got.ExpiresIn)
	}

	require.Equal(t, e.nonce, got.Nonce)
	require.Equal(t, e.audienceURL, got.Audience)
	require.Equal(t, int(e.refreshTokenExpiry/time.Second), got.RefreshTokenExpiresIn)
	require.Equal(t, e.redirectURI, got.RedirectURI)

	rtID := assertValidRefreshToken(t, idpService.refreshKey, got.RefreshToken, e.clientID, e.userID, e.userEmail)

	gotRT, err := idpService.db.GetRefreshToken(context.Background(), rtID)
	require.NoError(t, err)

	require.Equal(t, rtID, gotRT.ID)
	require.Equal(t, e.clientID, gotRT.ClientID)
	require.Equal(t, e.codeID, gotRT.CodeID)
	require.Equal(t, e.redirectURI, gotRT.RedirectURI)
	require.Equal(t, e.userID, gotRT.UserID)
	require.Equal(t, e.userEmail, gotRT.UserEmail)
	require.Equal(t, time.Now().Unix(), gotRT.CreateTime.Unix())
	require.Equal(t, time.Now().Add(e.refreshTokenExpiry).Unix(), gotRT.ExpiryTime.Unix())
}
