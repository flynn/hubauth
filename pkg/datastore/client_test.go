package datastore

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors"
)

func newTestService(t *testing.T) *service {
	c, err := datastore.NewClient(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return &service{db: c}
}

func TestClientCRD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	c := &hubauth.Client{
		RefreshTokenExpiry: 24 * time.Hour,
		RedirectURIs:       []string{"http://localhost:8000"},
	}
	id, err := s.CreateClient(ctx, c)
	require.NoError(t, err)

	res, err := s.GetClient(ctx, id)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	require.Equal(t, res.CreateTime, res.UpdateTime)
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	c.ID = id
	require.Equal(t, c, res)

	clients, err := s.ListClients(ctx)
	require.NoError(t, err)
	for _, res = range clients {
		if res.ID == id {
			break
		}
	}
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	require.Equal(t, c, res)

	err = s.DeleteClient(ctx, id)
	require.NoError(t, err)

	_, err = s.GetClient(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestClientMutate(t *testing.T) {
	type test struct {
		desc   string
		mut    []*hubauth.ClientMutation
		before *hubauth.Client
		after  *hubauth.Client
	}
	tests := []test{
		{
			desc: "add redirect existing",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpAddRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://example.com"},
			},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://example.com"},
			},
		},
		{
			desc: "add redirect new empty",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpAddRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://example.com"},
			},
		},
		{
			desc: "add redirect new others",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpAddRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com"},
			},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com", "https://example.com"},
			},
		},
		{
			desc: "delete redirect existing",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpDeleteRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://example.com", "https://b.com"},
			},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com"},
			},
		},
		{
			desc: "delete redirect only",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpDeleteRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://example.com"},
			},
			after: &hubauth.Client{},
		},
		{
			desc: "delete redirect nonexistent",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpDeleteRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com"},
			},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com"},
			},
		},
		{
			desc: "delete redirect empty",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpDeleteRedirectURI, RedirectURI: "https://example.com"},
			},
			before: &hubauth.Client{},
			after:  &hubauth.Client{},
		},
		{
			desc: "multiple",
			mut: []*hubauth.ClientMutation{
				{Op: hubauth.ClientMutationOpAddRedirectURI, RedirectURI: "https://example.com"},
				{Op: hubauth.ClientMutationOpAddRedirectURI, RedirectURI: "https://1.example.com"},
				{Op: hubauth.ClientMutationOpDeleteRedirectURI, RedirectURI: "https://b.com"},
			},
			before: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://b.com"},
			},
			after: &hubauth.Client{
				RedirectURIs: []string{"https://a.com", "https://1.example.com", "https://example.com"},
			},
		},
	}

	s := newTestService(t)
	ctx := context.Background()
	for _, tt := range tests {
		id, err := s.CreateClient(ctx, tt.before)
		require.NoError(t, err, tt.desc)
		before, err := s.GetClient(ctx, id)
		require.NoError(t, err)

		err = s.MutateClient(ctx, id, tt.mut)
		require.NoError(t, err, tt.desc)

		res, err := s.GetClient(ctx, id)
		require.NoError(t, err, tt.desc)
		res.ID = ""
		require.Equal(t, before.CreateTime, res.CreateTime)

		res.CreateTime = time.Time{}
		res.UpdateTime = time.Time{}
		require.Equal(t, tt.after, res, tt.desc)

		s.DeleteClient(ctx, id)
	}
}
