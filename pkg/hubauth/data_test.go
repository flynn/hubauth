package hubauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectURI(t *testing.T) {
	testCases := []struct {
		Desc                string
		Base                string
		Fragment            bool
		Data                map[string]string
		ExpectedURI         string
		ExpectedIsLocalHost bool
	}{
		{
			Desc:                "can't parse base",
			Base:                "://invalid",
			ExpectedURI:         "",
			ExpectedIsLocalHost: false,
		},
		{
			Desc:                "fragment off",
			Base:                "http://hubauth.flynn.io/path/to/endpoint",
			Fragment:            false,
			Data:                map[string]string{"param1": "value1", "param2": "value2"},
			ExpectedURI:         "http://hubauth.flynn.io/path/to/endpoint?param1=value1&param2=value2",
			ExpectedIsLocalHost: false,
		},
		{
			Desc:                "fragment off with existing params",
			Base:                "http://hubauth.flynn.io?existing=param",
			Fragment:            false,
			Data:                map[string]string{"param1": "value1", "param2": "value2"},
			ExpectedURI:         "http://hubauth.flynn.io?existing=param&param1=value1&param2=value2",
			ExpectedIsLocalHost: false,
		},
		{
			Desc:                "fragment on",
			Base:                "http://hubauth.flynn.io/path/to/endpoint",
			Fragment:            true,
			Data:                map[string]string{"param1": "value1", "param2": "value2"},
			ExpectedURI:         "http://hubauth.flynn.io/path/to/endpoint#param1=value1&param2=value2",
			ExpectedIsLocalHost: false,
		},
		{
			Desc:                "fragment on with existing params",
			Base:                "http://hubauth.flynn.io#existing=param",
			Fragment:            true,
			Data:                map[string]string{"param1": "value1", "param2": "value2"},
			ExpectedURI:         "http://hubauth.flynn.io#existing=param&param1=value1&param2=value2",
			ExpectedIsLocalHost: false,
		},
		{
			Desc:                "base is localhost ip",
			Base:                "http://127.0.0.1",
			Fragment:            true,
			ExpectedURI:         "http://127.0.0.1",
			ExpectedIsLocalHost: true,
		},
		{
			Desc:                "base is localhost hostname",
			Base:                "http://localhost",
			Fragment:            true,
			ExpectedURI:         "http://localhost",
			ExpectedIsLocalHost: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			uri, isLocalhost := RedirectURI(testCase.Base, testCase.Fragment, testCase.Data)
			require.Equal(t, testCase.ExpectedURI, uri)
			require.Equal(t, testCase.ExpectedIsLocalHost, isLocalhost)
		})
	}
}

func TestClientInfo(t *testing.T) {
	ctx := context.Background()
	require.Nil(t, ctx.Value(&ctxKeyClientInfo{}))
	require.Nil(t, GetClientInfo(ctx))

	clientInfoCtx := InitClientInfo(ctx)
	require.NotNil(t, clientInfoCtx.Value(ctxKeyClientInfo{}))

	require.Equal(t, clientInfoCtx.Value(ctxKeyClientInfo{}), GetClientInfo(clientInfoCtx))
}

func TestOAuthError(t *testing.T) {
	e := OAuthError{Code: "code", Description: "description"}
	require.Equal(t, "description", e.Error())
	require.Equal(t, "http://base.url/path?error=code&error_description=description&state=state1", e.RedirectURI("http://base.url/path", "state1", false))

	e2 := OAuthError{Code: "code"}
	require.Equal(t, "oauth error: code", e2.Error())
	require.Equal(t, "http://base.url/path#error=code&error_description=&state=state2", e2.RedirectURI("http://base.url/path", "state2", true))
	
	
	require.Empty(t, e2.RedirectURI("://invalid", "state", false))
}
