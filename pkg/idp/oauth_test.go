package idp

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	gdatastore "cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
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

	codeKey := make(hmacpb.Key, 0, 32)
	n, err := rand.Read(codeKey)
	require.Equal(t, len(codeKey), n)
	require.NoError(t, err)

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
