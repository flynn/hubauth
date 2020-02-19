package google

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
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

func genNonce(expiry time.Time, secret []byte) []byte {
	if secret == nil {
		secret = []byte{0}
	}

	// version (1 byte) | expiry unix seconds (8 bytes) | random (8 bytes) | HMAC-SHA256 (32 bytes)
	data := make([]byte, 17, nonceLen)
	binary.BigEndian.PutUint64(data[1:], uint64(expiry.Unix()))
	if _, err := io.ReadFull(rand.Reader, data[9:]); err != nil {
		panic(err)
	}
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(data)
}

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
			func() string { return b64(genNonce(exp, nil)[:48]) }(),
			"short",
		},
		{
			func() string {
				n := genNonce(exp, nil)
				n[0] = 2
				return b64(n)
			}(),
			"wrong version",
		},
		{
			func() string {
				n := genNonce(exp, []byte{1})
				return b64(n)
			}(),
			"invalid signature",
		},
		{
			func() string { return b64(genNonce(time.Now().Add(-time.Second), nil)) }(),
			"expired",
		},
	} {
		if s.checkNonce(test.n) {
			t.Errorf("failed nonce test: %s", test.desc)
		}
	}
}
