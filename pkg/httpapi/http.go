package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
)

type api struct {
	idp hubauth.IdPService
	key signpb.Key
}

func (a *api) AuthorizeCode(ctx context.Context, req *http.Request, w http.ResponseWriter) {
	cookie, err := req.Cookie(authCookie)
	if err != nil {
		// TODO: error
	}
	data := &pb.AuthorizeCookie{}
	cookieBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		// TODO: error
	}
	if err := signpb.VerifyUnmarshal(a.key, cookieBytes, data); err != nil {
		// TODO: error
	}

	authReq := &hubauth.AuthorizeCodeRequest{
		AuthorizeUserRequest: hubauth.AuthorizeUserRequest{
			ClientState:   data.ClientState,
			Nonce:         data.Nonce,
			ClientID:      data.ClientId,
			RedirectURI:   data.RedirectUri,
			CodeChallenge: data.CodeChallenge,
			ResponseMode:  data.ResponseMode,
		},
		RPState: data.RpState,
		Params:  req.URL.Query(),
	}
	res, err := a.idp.AuthorizeCodeRedirect(ctx, authReq)
	if err != nil {
		// TODO: error
	}
	http.SetCookie(w, &http.Cookie{
		Name:   authCookie,
		MaxAge: -1,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, res.URL, http.StatusTemporaryRedirect)
}

const authCookie = "hubauth_authorize"

func (a *api) AuthorizeUser(ctx context.Context, req *http.Request, w http.ResponseWriter) {
	params := req.URL.Query()
	if params.Get("code_challenge_method") != "S256" {
		// TODO: error
	}
	if params.Get("response_type") != "code" {
		// TODO: error
	}
	authReq := &hubauth.AuthorizeUserRequest{
		ClientState:   params.Get("state"),
		Nonce:         params.Get("nonce"),
		ClientID:      params.Get("client_id"),
		RedirectURI:   params.Get("redirect_uri"),
		CodeChallenge: params.Get("code_challenge"),
		ResponseMode:  params.Get("response_mode"),
	}
	res, err := a.idp.AuthorizeUserRedirect(ctx, authReq)
	if err != nil {
		// log error
		// return error response
	}

	cookieData := &pb.AuthorizeCookie{
		RpState:       res.RPState,
		ClientState:   authReq.ClientState,
		ClientId:      authReq.ClientID,
		RedirectUri:   authReq.RedirectURI,
		Nonce:         authReq.Nonce,
		CodeChallenge: authReq.CodeChallenge,
		ResponseMode:  authReq.ResponseMode,
	}
	signedCookie, err := signpb.SignMarshal(ctx, a.key, cookieData)
	if err != nil {
		// log error
		// return 500
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookie,
		Value:    base64.URLEncoding.EncodeToString(signedCookie),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, res.URL, http.StatusTemporaryRedirect)
}

func (a *api) Token(ctx context.Context, req *http.Request, w http.ResponseWriter) {
	if err := req.ParseForm(); err != nil {
		// TODO: error
	}

	var res *hubauth.AccessToken
	var err error
	switch req.Form.Get("grant_type") {
	case "authorization_code":
		res, err = a.idp.ExchangeCode(ctx, &hubauth.ExchangeCodeRequest{
			ClientID:     req.Form.Get("client_id"),
			RedirectURI:  req.Form.Get("redirect_uri"),
			Code:         req.Form.Get("code"),
			CodeVerifier: req.Form.Get("code_verifier"),
		})
	case "refresh_token":
		res, err = a.idp.RefreshToken(ctx, &hubauth.RefreshTokenRequest{
			ClientID:     req.Form.Get("client_id"),
			RefreshToken: req.Form.Get("refresh_token"),
		})
	}
	if err != nil {
		// TODO: error
	}

	redirectURI, err := url.Parse(res.RedirectURI)
	if err != nil {
		// TODO: error
	}
	if redirectURI.Scheme == "https" {
		w.Header().Set("Access-Control-Allow-Origin", "https://"+redirectURI.Host)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
