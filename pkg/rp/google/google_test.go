package google

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"
)

func TestRedirect(t *testing.T) {
	s := New("client1", "clientSecret", "https://localhost:8080", []byte{0}).(*service)
	res := s.Redirect()
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
	if !s.checkNonce(res.State) {
		t.Errorf("nonce is invalid")
	}
}

var testSecret = []byte{0}

func TestCheckNonce(t *testing.T) {
	s := &service{secret: []byte{0}}
	exp := time.Now().Add(time.Minute)
	b64 := base64.URLEncoding.EncodeToString
	for _, test := range []struct {
		n    string
		desc string
	}{
		{"", "empty"},
		{
			func() string { return b64(genNonce(testSecret, exp)[:48]) }(),
			"short",
		},
		{
			func() string {
				n := genNonce(testSecret, exp)
				n[0] = 2
				return b64(n)
			}(),
			"wrong version",
		},
		{
			func() string {
				n := genNonce([]byte{1}, exp)
				return b64(n)
			}(),
			"invalid signature",
		},
		{
			func() string { return b64(genNonce(testSecret, time.Now().Add(-time.Second))) }(),
			"expired",
		},
	} {
		if s.checkNonce(test.n) {
			t.Errorf("failed nonce test: %s", test.desc)
		}
	}
}
