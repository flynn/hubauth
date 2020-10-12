package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hmacpb"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/pb"
	"github.com/golang/protobuf/ptypes"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/errors/fmt"
)

const authCookie = "hubauth_authorize"

type clock interface {
	Now() time.Time
}

type clockImpl struct{}

func (clockImpl) Now() time.Time {
	return time.Now()
}

type Config struct {
	IdP        hubauth.IdPService
	CookieKey  hmacpb.Key
	ProjectID  string
	Repository string
	Revision   string
}

func New(conf Config) http.Handler {
	return &api{Config: conf, clock: clockImpl{}}
}

type api struct {
	Config
	clock clock
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	err    error
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	l.status = status
	l.ResponseWriter.WriteHeader(status)
}

func (l *loggingResponseWriter) SetErr(err error) {
	l.err = err
}

func (a *api) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req = req.WithContext(clog.Context(req.Context()))
	ctx := req.Context()
	w := &loggingResponseWriter{ResponseWriter: rw}

	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	startTime := a.clock.Now()
	switch {
	case req.Method == "GET" && req.URL.Path == "/authorize":
		a.AuthorizeUser(w, req)
	case req.Method == "GET" && req.URL.Path == "/rp/google":
		a.AuthorizeCode(w, req)
	case req.Method == "POST" && req.URL.Path == "/token":
		a.Token(w, req)
	case req.Method == "GET" && req.URL.Path == "/audiences":
		a.Audiences(w, req)
	case req.Method == "OPTIONS" && req.URL.Path == "/audiences":
		w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusOK)
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

	traceHeader := req.Header.Get("X-Cloud-Trace-Context")
	traceParts := strings.Split(traceHeader, "/")
	if len(traceParts) > 0 && len(traceParts[0]) > 0 {
		clog.Set(ctx, zap.String("logging.googleapis.com/trace", fmt.Sprintf("projects/%s/traces/%s", a.ProjectID, traceParts[0])))
	}

	clog.Set(ctx,
		zap.String("request_path", req.URL.Path),
		zap.String("request_method", req.Method),
		zap.String("request_ip", req.Header.Get("X-Forwarded-For")),
		zap.String("request_user_agent", req.Header.Get("User-Agent")),
		zap.Int("response_status", w.status),
		zap.Duration("response_duration", duration),
	)
	if t := req.Header.Get("Content-Type"); t != "" {
		clog.Set(ctx, zap.String("request_content_type", t))
	}
	if l := w.Header().Get("Location"); l != "" {
		clog.Set(ctx, zap.String("response_location", l))
	}

	if w.status >= 500 && w.status <= 599 {
		clog.Error(ctx, w.err, &clog.ErrInfo{
			Request:      req,
			ResponseCode: w.status,
			Revision:     a.Revision,
			Repository:   a.Repository,
		})
	} else {
		clog.Log(ctx, fmt.Sprintf("%s %s %d %v", req.Method, req.URL.Path, w.status, duration))
	}
}

const cookieExpiry = 5 * time.Minute

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
	res, err := a.IdP.AuthorizeUserRedirect(req.Context(), authReq)
	if err != nil {
		a.handleErr(w, req, err)
		return
	}

	expiry, _ := ptypes.TimestampProto(a.clock.Now().Add(cookieExpiry))

	cookieData := &pb.AuthorizeCookie{
		RpState:       res.RPState,
		ClientState:   authReq.ClientState,
		ClientId:      authReq.ClientID,
		RedirectUri:   authReq.RedirectURI,
		Nonce:         authReq.Nonce,
		CodeChallenge: authReq.CodeChallenge,
		ResponseMode:  authReq.ResponseMode,
		ExpireTime:    expiry,
	}
	signedCookie, err := hmacpb.SignMarshal(a.CookieKey, cookieData)
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
	if err := hmacpb.VerifyUnmarshal(a.CookieKey, cookieBytes, data); err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid auth cookie",
		})
		return
	}
	exp, err := ptypes.Timestamp(data.ExpireTime)
	if err != nil {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "invalid auth cookie expiry",
		})
		return
	}
	if a.clock.Now().After(exp) {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "expired auth cookie",
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
	res, err := a.IdP.AuthorizeCodeRedirect(req.Context(), authReq)
	if err != nil {
		a.handleErr(w, req, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   authCookie,
		MaxAge: -1,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")

	if res.DisplayCode != "" || res.Interstitial {
		w.Header().Set("Content-Type", "text/html; charset=utf8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'")
		if res.Interstitial {
			redirectInterstitialHTML(res.URL, w)
		} else {
			codeDisplayHTML(res.DisplayCode, w)
		}
		return
	}

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

	var aud string
	if u := req.PostForm.Get("audience"); u != "" {
		audURL, err := url.Parse(u)
		if err != nil || audURL.Scheme != "https" || audURL.Path != "" || audURL.Host == "" {
			a.handleErr(w, req, &hubauth.OAuthError{
				Code:        "invalid_request",
				Description: "invalid audience",
			})
			return
		}
		aud = "https://" + strings.SplitN(audURL.Host, ":", 2)[0]
	}

	if req.PostForm.Get("client_id") == "" {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing client_id",
		})
		return
	}

	var res *hubauth.AccessToken
	var err error
	switch req.Form.Get("grant_type") {
	case "authorization_code":
		res, err = a.IdP.ExchangeCode(req.Context(), &hubauth.ExchangeCodeRequest{
			ClientID:      req.PostForm.Get("client_id"),
			Audience:      aud,
			RedirectURI:   req.PostForm.Get("redirect_uri"),
			Code:          req.PostForm.Get("code"),
			CodeVerifier:  req.PostForm.Get("code_verifier"),
			UserPublicKey: req.PostForm.Get("user_public_key"),
		})
	case "refresh_token":
		res, err = a.IdP.RefreshToken(req.Context(), &hubauth.RefreshTokenRequest{
			ClientID:     req.PostForm.Get("client_id"),
			Audience:     aud,
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

func (a *api) Audiences(w http.ResponseWriter, req *http.Request) {
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "RefreshToken ") {
		a.handleErr(w, req, &hubauth.OAuthError{
			Code:        "invalid_request",
			Description: "missing refresh token authorization",
		})
		return
	}
	rt := strings.TrimPrefix(auth, "RefreshToken ")

	res, err := a.IdP.ListAudiences(req.Context(), &hubauth.ListAudiencesRequest{RefreshToken: rt})
	if err != nil {
		a.handleErr(w, req, err)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(res)
}

func (a *api) handleErr(w http.ResponseWriter, req *http.Request, err error) {
	oe, ok := err.(*hubauth.OAuthError)
	if !ok {
		w.(*loggingResponseWriter).SetErr(err)
		oe = &hubauth.OAuthError{
			Code:        "server_error",
			Description: "internal server error",
		}
	}
	clog.Set(req.Context(), zap.String("error_code", oe.Code))
	clog.Set(req.Context(), zap.Error(err))

	if span := trace.FromContext(req.Context()); span != nil {
		span.AddAttributes(
			trace.StringAttribute("error", err.Error()),
			trace.StringAttribute("error_code", oe.Code),
		)
	}

	ci := hubauth.GetClientInfo(req.Context())
	if ci != nil && ci.RedirectURI != "" {
		http.Redirect(w, req, oe.RedirectURI(ci.RedirectURI, ci.State, ci.Fragment), http.StatusFound)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
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
