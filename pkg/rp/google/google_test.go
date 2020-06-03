package google

import (
	"net/url"
	"testing"

	"golang.org/x/net/context"
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
