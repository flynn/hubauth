package google

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/rp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirect(t *testing.T) {
	s := New("client1", "clientSecret", "https://localhost:8080").(*service)
	res, err := s.Redirect(context.Background())
	if err != nil {
		t.Fatal("unexpected error generating redirect:", err)
	}
	u, err := url.Parse(res.URL)
	if err != nil {
		t.Fatal("unexpected error parsing URL:", err)
	}
	if n := u.Query().Get("nonce"); n != res.State {
		t.Errorf("unexpected nonce: have %s, want %s", n, res.State)
	}
	if s := u.Query().Get("state"); s != res.State {
		t.Errorf("unexpected nonce: have %s, want %s", s, res.State)
	}
}

var endpointAuth = "/auth"
var endpointToken = "/token"

func newTestAuthService(clientID, clientSecret, redirectURI string, h http.HandlerFunc) (rp.AuthService, func()) {
	server := httptest.NewServer(http.HandlerFunc(h))

	s := New(clientID, clientSecret, redirectURI).(*service)
	s.conf.Endpoint = oauth2.Endpoint{
		AuthURL:   fmt.Sprintf("%s%s", server.URL, endpointAuth),
		TokenURL:  fmt.Sprintf("%s%s", server.URL, endpointToken),
		AuthStyle: oauth2.AuthStyleInParams,
	}

	return s, func() {
		server.Close()
	}
}

func TestExchange(t *testing.T) {
	clientID := "client1"
	clientSecret := "clientSecret"
	redirectURI := "https://localhost:8080"
	grantType := "authorization_code"
	accessToken := "accessToken"
	nonce := "randomNonce"
	code := "randomCode"

	sub := "10769150350006150715113082367"
	email := "jsmith@example.com"
	name := "John Smith"
	picture := "userPicture"

	// sample id_token structure from
	// https://developers.google.com/identity/protocols/oauth2/openid-connect#an-id-tokens-payload
	jsonToken := []byte(fmt.Sprintf(`{
		"iss": "https://accounts.google.com",
		"azp": "1234987819200.apps.googleusercontent.com",
		"aud": "1234987819200.apps.googleusercontent.com",
		"sub": "%s",
		"at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
		"hd": "example.com",
		"email": "%s",
		"email_verified": true,
		"iat": 1353601026,
		"exp": 1353604926,
		"nonce": "%s",
		"name": "%s",
		"picture": "%s"
	}`, sub, email, nonce, name, picture))

	// signature isn't checked so we can forge only the claims part
	fakeJWT := fmt.Sprintf("x.%s.x", base64.URLEncoding.EncodeToString(jsonToken))
	tokenExtra := url.Values{
		"access_token": {accessToken},
		"id_token":     {fakeJWT},
	}

	wantParams := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"grant_type":    {grantType},
		"redirect_uri":  {redirectURI},
	}

	s, tearDown := newTestAuthService(clientID, clientSecret, redirectURI, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, endpointToken, r.RequestURI)

		params, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)
		got, err := url.ParseQuery(string(params))
		assert.NoError(t, err)

		assert.EqualValues(t, wantParams, got)

		w.Write([]byte(tokenExtra.Encode()))
	})
	defer tearDown()

	got, err := s.Exchange(context.Background(), &rp.RedirectResult{
		State: nonce,
		Params: url.Values{
			"state": {nonce},
			"code":  {code},
		},
	})
	require.NoError(t, err)

	expectedOAuthToken := &oauth2.Token{
		AccessToken: accessToken,
	}
	expectedOAuthToken = expectedOAuthToken.WithExtra(tokenExtra)

	want := &rp.Token{
		Token:   expectedOAuthToken,
		UserID:  sub,
		Email:   email,
		Name:    name,
		Picture: picture,
	}

	require.EqualValues(t, want, got)
}

func TestExchangeParameters(t *testing.T) {
	invalidParams := []struct {
		Desc             string
		Error            string
		ErrorDescription string
		State            string
		ParamState       string
		Code             string
	}{
		{Desc: "error present", Error: "some error", ErrorDescription: "some error description", State: "valid state", ParamState: "valid state", Code: "valid code"},
		{Desc: "state mismatch", Error: "", ErrorDescription: "", State: "state 1", ParamState: "state 2", Code: "valid code"},
		{Desc: "missing state", Error: "", ErrorDescription: "", State: "", ParamState: "", Code: "valid code"},
		{Desc: "missing code", Error: "", ErrorDescription: "", State: "valid state", ParamState: "valid state", Code: ""},
	}

	s, tearDown := newTestAuthService("clientID", "clientSecret", "http://localhost:8888", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("did not expect call to server endpoint")
	})
	defer tearDown()

	for _, p := range invalidParams {
		_, err := s.Exchange(context.Background(), &rp.RedirectResult{
			State: p.State,
			Params: url.Values{
				"state":             {p.ParamState},
				"code":              {p.Code},
				"error":             {p.Error},
				"error_description": {p.ErrorDescription},
			},
		})

		require.Error(t, err, p.Desc)
	}
}

func TestExchangeInvalidServerResponse(t *testing.T) {
	type testCase struct {
		ErrorMsg string
		Handler  func(w http.ResponseWriter, r *http.Request)
	}

	validNonce := "validNonce"

	serverHandlers := []testCase{
		{
			ErrorMsg: "",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			ErrorMsg: "missing id_token",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// access_token field is handled by the oauth2 lib so we don't test it here
				w.Write([]byte("access_token=accessToken"))
			},
		},
		{
			ErrorMsg: "invalid id_token",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("access_token=accessToken&id_token=invalid.token"))
			},
		},
		{
			ErrorMsg: "invalid id_token encoding",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("access_token=accessToken&id_token=invalid.token.encoding"))
			},
		},
		{
			ErrorMsg: "invalid id_token json",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)

				b64Token := base64.URLEncoding.EncodeToString([]byte("token"))
				w.Write([]byte(fmt.Sprintf("access_token=accessToken&id_token=invalid.%s.encoding", b64Token)))
			},
		},
	}

	invalidIDTokens := []struct {
		ErrorMsg string
		idt      idToken
	}{
		{
			ErrorMsg: "id_token missing nonce",
			idt: idToken{
				Nonce:         "",
				Sub:           "sub",
				Email:         "foo@bar.com",
				EmailVerified: true,
			},
		},
		{
			ErrorMsg: "id_token missing nonce",
			idt: idToken{
				Nonce:         "bad nonce",
				Sub:           "sub",
				Email:         "foo@bar.com",
				EmailVerified: true,
			},
		},
		{
			ErrorMsg: "id_token missing user",
			idt: idToken{
				Nonce:         validNonce,
				Sub:           "sub",
				Email:         "foo@bar.com",
				EmailVerified: false,
			},
		},
		{
			ErrorMsg: "id_token missing user",
			idt: idToken{
				Nonce:         validNonce,
				Sub:           "sub",
				Email:         "",
				EmailVerified: true,
			},
		},
		{
			ErrorMsg: "id_token missing user",
			idt: idToken{
				Nonce:         validNonce,
				Sub:           "",
				Email:         "foo@bar.com",
				EmailVerified: true,
			},
		},
	}

	for _, it := range invalidIDTokens {
		cit := it // without this copy, only the last element from invalidIDTokens will appear in serverHandlers
		serverHandlers = append(serverHandlers, testCase{
			ErrorMsg: cit.ErrorMsg,
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)

				b, err := json.Marshal(cit.idt)
				if err != nil {
					t.Fatal(err)
				}
				b64Token := base64.URLEncoding.EncodeToString(b)
				w.Write([]byte(fmt.Sprintf("access_token=accessToken&id_token=invalid.%s.encoding", b64Token)))
			},
		})
	}

	for _, h := range serverHandlers {
		t.Run(h.ErrorMsg, func(t *testing.T) {
			s, tearDown := newTestAuthService("id", "secret", "http://localhost", h.Handler)
			defer tearDown()

			_, err := s.Exchange(context.Background(), &rp.RedirectResult{
				State: validNonce,
				Params: url.Values{
					"state": {validNonce},
					"code":  {"code"},
				},
			})

			require.Error(t, err)
			if h.ErrorMsg != "" {
				require.Equal(t, hubauth.OAuthError{Description: h.ErrorMsg, Code: codeInvalid}, err)
			}
		})
	}
}
