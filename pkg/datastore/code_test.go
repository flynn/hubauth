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

func TestCodeCRD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	c := &hubauth.Code{
		ClientID:      datastore.NameKey(kindClient, newRandomID(), nil).Encode(),
		RedirectURI:   "https://example.com",
		Nonce:         "asdf",
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		ExpiryTime:    time.Now().Add(time.Minute).Truncate(time.Millisecond),
	}
	id, err := s.CreateCode(ctx, c)
	require.NoError(t, err)

	res, err := s.GetCode(ctx, id)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	res.CreateTime = time.Time{}
	c.Code = id
	require.Equal(t, c, res)

	err = s.DeleteCode(ctx, id)
	require.NoError(t, err)

	_, err = s.GetCode(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestCodeDeleteExpired(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	c := &hubauth.Code{
		ClientID:      datastore.NameKey(kindClient, newRandomID(), nil).Encode(),
		RedirectURI:   "https://example.com",
		Nonce:         "asdf",
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	}

	c.ExpiryTime = time.Now().Add(time.Minute)
	keep, err := s.CreateCode(ctx, c)
	require.NoError(t, err)

	c.ExpiryTime = time.Now().Add(-time.Minute)
	expired1, err := s.CreateCode(ctx, c)
	require.NoError(t, err)

	c.ExpiryTime = time.Now().Add(-time.Second)
	expired2, err := s.CreateCode(ctx, c)
	require.NoError(t, err)

	deleted, err := s.DeleteExpiredCodes(ctx)
	require.NoError(t, err)
	var found1, found2, foundKeep bool
	for _, id := range deleted {
		switch id {
		case expired1:
			found1 = true
		case expired2:
			found2 = true
		case keep:
			foundKeep = true
		}
	}
	require.True(t, found1)
	require.True(t, found2)
	require.False(t, foundKeep)

	_, err = s.GetCode(ctx, keep)
	require.NoError(t, err)
	_, err = s.GetCode(ctx, expired1)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
	_, err = s.GetCode(ctx, expired2)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}
