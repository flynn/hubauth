package google

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/flynn/hubauth/pkg/signpb"
	"golang.org/x/net/context"
)

func newKey() signpb.Key {
	c := kmssim.NewClient([]string{"1"})
	k, err := kmssign.NewKey(context.Background(), c, "1")
	if err != nil {
		panic(err)
	}
	return k
}

func TestRedirect(t *testing.T) {
	s := New("client1", "clientSecret", "https://localhost:8080", newKey()).(*service)
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
	if !s.checkNonce(res.State) {
		t.Errorf("nonce is invalid")
	}
}

func TestCheckNonce(t *testing.T) {
	s := &service{sigKey: newKey()}
	exp := time.Now().Add(time.Minute)
	gen := func(k signpb.Key, exp time.Time) string {
		b, err := genNonce(context.Background(), k, exp)
		if err != nil {
			t.Fatal(err)
		}
		return base64.URLEncoding.EncodeToString(b)
	}

	for _, test := range []struct {
		n    string
		desc string
	}{
		{"", "empty"},
		{
			func() string { return gen(s.sigKey, exp)[:48] }(),
			"short",
		},
		{
			func() string { return gen(newKey(), exp) }(),
			"wrong key",
		},
		{
			func() string { return gen(s.sigKey, time.Now().Add(-time.Second)) }(),
			"expired",
		},
	} {
		if s.checkNonce(test.n) {
			t.Errorf("failed nonce test: %s", test.desc)
		}
	}
}
