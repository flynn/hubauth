package idp

import (
	"context"
	"crypto/rand"
	"errors"
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

func newTestIdPService(t *testing.T) *idpService {
	dsc, err := gdatastore.NewClient(context.Background(), "test")
	require.NoError(t, err)
	db := datastore.New(dsc)
	authService := new(mockAuthService)

	refreshKeyName := "refreshKey"
	kmsKeys := []string{refreshKeyName}
	kms := kmssim.NewClient(kmsKeys)

	codeKey := make(hmacpb.Key, 32)
	_, err = rand.Read(codeKey)
	require.NoError(t, err)
	require.Equal(t, len(codeKey), 32)

	ctx := context.Background()
	refreshKey, err := kmssign.NewKey(ctx, kms, refreshKeyName)
	require.NoError(t, err)

	audienceKey := func(s string) string {
		return s
	}

	return New(db, authService, kms, codeKey, refreshKey, audienceKey).(*idpService)
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

func assertValidCode(t *testing.T, codeKey []byte, b64code, userID, userEmail string) {
	code, err := base64Decode(b64code)
	require.NoError(t, err)

	codeInfo := &pb.Code{}
	require.NoError(t, hmacpb.VerifyUnmarshal(codeKey, code, codeInfo))
	require.Equal(t, userID, codeInfo.UserId)
	require.Equal(t, userEmail, codeInfo.UserEmail)
}
