package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type api struct {
	idp hubauth.IdPService
	key signpb.Key
}

const authCookie = "hubauth_authorize"

func (a *api) AuthorizeUser(req *http.Request, w http.ResponseWriter) {
	req = req.WithContext(hubauth.InitClientInfo(req.Context()))
	params := req.URL.Query()
	clog.Set(req.Context(), zap.Object("params", zapURLValuesMarshaler{params}))
	if params.Get("code_challenge_method") != "S256" {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "code_challenge_method should be S256",
		})
		return
	}
	if params.Get("response_type") != "code" {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "response_type should be code",
		})
		return
	}
	authReq := &hubauth.AuthorizeUserRequest{
		ClientState:   params.Get("state"),
		Nonce:         params.Get("nonce"),
		ClientID:      params.Get("client_id"),
		RedirectURI:   params.Get("redirect_uri"),
		CodeChallenge: params.Get("code_challenge"),
		ResponseMode:  params.Get("response_mode"),
	}
	res, err := a.idp.AuthorizeUserRedirect(req.Context(), authReq)
	if err != nil {
		handleErr(req, w, err)
		return
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
	signedCookie, err := signpb.SignMarshal(req.Context(), a.key, cookieData)
	if err != nil {
		handleErr(req, w, err)
		return
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

func (a *api) AuthorizeCode(req *http.Request, w http.ResponseWriter) {
	params := req.URL.Query()
	clog.Set(req.Context(), zap.Object("params", zapURLValuesMarshaler{params}))
	req = req.WithContext(hubauth.InitClientInfo(req.Context()))
	cookie, err := req.Cookie(authCookie)
	if err != nil {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing auth cookie",
		})
		return
	}
	data := &pb.AuthorizeCookie{}
	cookieBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "malformed auth cookie",
		})
		return
	}
	if err := signpb.VerifyUnmarshal(a.key, cookieBytes, data); err != nil {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid auth cookie",
		})
		return
	}
	clog.Set(req.Context(), zap.Reflect("cookie", map[string]string{
		"client_state":   data.ClientState,
		"nonce":          data.Nonce,
		"client_id":      data.ClientId,
		"redirect_uri":   data.RedirectUri,
		"code_challenge": data.CodeChallenge,
		"response_mode":  data.ResponseMode,
		"rp_state":       data.RpState,
	}))

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
		Params:  params,
	}
	res, err := a.idp.AuthorizeCodeRedirect(req.Context(), authReq)
	if err != nil {
		handleErr(req, w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   authCookie,
		MaxAge: -1,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, res.URL, http.StatusTemporaryRedirect)
}

func (a *api) Token(req *http.Request, w http.ResponseWriter) {
	if err := req.ParseForm(); err != nil {
		handleErr(req, w, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid form POST",
		})
		return
	}

	clog.Set(req.Context(), zap.Object("params", zapURLValuesMarshaler{req.PostForm}))

	var res *hubauth.AccessToken
	var err error
	switch req.Form.Get("grant_type") {
	case "authorization_code":
		res, err = a.idp.ExchangeCode(req.Context(), &hubauth.ExchangeCodeRequest{
			ClientID:     req.PostForm.Get("client_id"),
			RedirectURI:  req.PostForm.Get("redirect_uri"),
			Code:         req.PostForm.Get("code"),
			CodeVerifier: req.PostForm.Get("code_verifier"),
		})
	case "refresh_token":
		res, err = a.idp.RefreshToken(req.Context(), &hubauth.RefreshTokenRequest{
			ClientID:     req.PostForm.Get("client_id"),
			RefreshToken: req.PostForm.Get("refresh_token"),
		})
	}
	if err != nil {
		handleErr(req, w, err)
		return
	}

	redirectURI, err := url.Parse(res.RedirectURI)
	if err != nil {
		handleErr(req, w, err)
		return
	}
	if redirectURI.Scheme == "https" {
		w.Header().Set("Access-Control-Allow-Origin", "https://"+redirectURI.Host)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleErr(req *http.Request, w http.ResponseWriter, err error) {
	oe, ok := err.(*hubauth.OAuthError)
	if !ok {
		oe = &hubauth.OAuthError{
			Code:        "server_error",
			Description: "internal server error",
		}
	}
	clog.Set(req.Context(), zap.String("error_code", oe.Code))
	clog.Set(req.Context(), zap.Error(err))
	ci := hubauth.GetClientInfo(req.Context())
	if ci != nil && ci.RedirectURI != "" {
		http.Redirect(w, req, oe.RedirectURI(ci.RedirectURI, ci.State, ci.Fragment), http.StatusTemporaryRedirect)
		return
	}
	if oe.Code == "server_error" {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(oe)
}

type zapURLValuesMarshaler struct {
	url.Values
}

func (m zapURLValuesMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, vs := range m.Values {
		if len(vs) > 0 {
			enc.AddString(k, vs[0])
		}
	}
	return nil
}
