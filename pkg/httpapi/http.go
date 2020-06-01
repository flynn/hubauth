package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"cloud.google.com/go/errorreporting"
	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/errstack"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/flynn/hubauth/pkg/signpb"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const authCookie = "hubauth_authorize"

func New(idp hubauth.IdPService, errClient *errorreporting.Client, cookieKey signpb.Key) http.Handler {
	return &api{
		idp:       idp,
		errClient: errClient,
		key:       cookieKey,
	}
}

type api struct {
	idp       hubauth.IdPService
	errClient *errorreporting.Client
	key       signpb.Key
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	l.status = status
	l.ResponseWriter.WriteHeader(status)
}

func (a *api) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req = req.WithContext(clog.Context(req.Context()))
	ctx := req.Context()
	w := &loggingResponseWriter{ResponseWriter: rw}

	startTime := time.Now()
	switch {
	case req.Method == "GET" && req.URL.Path == "/authorize":
		a.AuthorizeUser(w, req)
	case req.Method == "GET" && req.URL.Path == "/rp/google":
		a.AuthorizeCode(w, req)
	case req.Method == "POST" && req.URL.Path == "/token":
		a.Token(w, req)
	case req.Method == "GET" && req.URL.Path == "/":
		http.Redirect(w, req, "https://flynn.io/", http.StatusFound)
	case req.Method == "GET" && req.URL.Path == "/privacy":
		http.Redirect(w, req, "https://flynn.io/legal/privacy", http.StatusFound)
	case req.Method != "GET":
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}
	duration := time.Since(startTime)

	if w.status == 0 {
		w.status = 200
	}

	clog.Set(ctx, zap.String("request_path", req.URL.Path))
	clog.Set(ctx, zap.String("request_method", req.Method))
	clog.Set(ctx, zap.String("request_ip", req.Header.Get("X-Forwarded-For")))
	clog.Set(ctx, zap.String("request_user_agent", req.Header.Get("User-Agent")))
	clog.Set(ctx, zap.String("request_content_type", req.Header.Get("Content-Type")))
	clog.Set(ctx, zap.Int("response_status", w.status))
	if l := w.Header().Get("Location"); l != "" {
		clog.Set(ctx, zap.String("response_location", l))
	}
	clog.Set(ctx, zap.Duration("response_duration", duration))

	clog.Log(ctx, "request")
}

func (a *api) AuthorizeUser(w http.ResponseWriter, req *http.Request) {
	req = req.WithContext(hubauth.InitClientInfo(req.Context()))
	params := req.URL.Query()
	clog.Set(req.Context(), zap.Object("params", zapURLValuesMarshaler{params}))
	if params.Get("code_challenge_method") != "S256" {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "code_challenge_method should be S256",
		})
		return
	}
	if params.Get("response_type") != "code" {
		a.handleErr(w, req, &hubauth.OAuthError{
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
	if authReq.ResponseMode == "" {
		authReq.ResponseMode = "query"
	}
	res, err := a.idp.AuthorizeUserRedirect(req.Context(), authReq)
	if err != nil {
		a.handleErr(w, req, err)
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
		a.handleErr(w, req, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookie,
		Value:    base64.URLEncoding.EncodeToString(signedCookie),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, res.URL, http.StatusFound)
}

func (a *api) AuthorizeCode(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()
	clog.Set(req.Context(), zap.Object("params", zapURLValuesMarshaler{params}))
	req = req.WithContext(hubauth.InitClientInfo(req.Context()))
	cookie, err := req.Cookie(authCookie)
	if err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing auth cookie",
		})
		return
	}
	data := &pb.AuthorizeCookie{}
	cookieBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "malformed auth cookie",
		})
		return
	}
	if err := signpb.VerifyUnmarshal(a.key, cookieBytes, data); err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
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
		a.handleErr(w, req, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   authCookie,
		MaxAge: -1,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, res.URL, http.StatusFound)
}

func (a *api) Token(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
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
			Audience:     req.PostForm.Get("audience"),
			RedirectURI:  req.PostForm.Get("redirect_uri"),
			Code:         req.PostForm.Get("code"),
			CodeVerifier: req.PostForm.Get("code_verifier"),
		})
	case "refresh_token":
		res, err = a.idp.RefreshToken(req.Context(), &hubauth.RefreshTokenRequest{
			ClientID:     req.PostForm.Get("client_id"),
			Audience:     req.PostForm.Get("audience"),
			RefreshToken: req.PostForm.Get("refresh_token"),
		})
	default:
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid grant_type",
		})
		return
	}
	span := trace.FromContext(req.Context())
	if span != nil {
		span.AddAttributes(trace.StringAttribute("grant_type", req.Form.Get("grant_type")))
	}
	if err != nil {
		a.handleErr(w, req, err)
		return
	}

	redirectURI, err := url.Parse(res.RedirectURI)
	if err != nil {
		a.handleErr(w, req, err)
		return
	}
	if redirectURI.Scheme == "https" || redirectURI.Scheme == "http" { // TODO: remove http
		w.Header().Set("Access-Control-Allow-Origin", redirectURI.Scheme+"://"+redirectURI.Host)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (a *api) handleErr(w http.ResponseWriter, req *http.Request, err error) {
	oe, ok := err.(*hubauth.OAuthError)
	if !ok {
		if a.errClient != nil {
			a.errClient.Report(errorreporting.Entry{
				Error: err,
				Req:   req,
				Stack: errstack.Format(err),
			})
		}
		oe = &hubauth.OAuthError{
			Code:        "server_error",
			Description: "internal server error",
		}
	}
	clog.Set(req.Context(), zap.String("error_code", oe.Code))
	clog.Set(req.Context(), zap.Error(err))
	ci := hubauth.GetClientInfo(req.Context())
	if ci != nil && ci.RedirectURI != "" {
		http.Redirect(w, req, oe.RedirectURI(ci.RedirectURI, ci.State, ci.Fragment), http.StatusFound)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	if oe.Code == "server_error" {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
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
