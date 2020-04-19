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

func TestRefreshTokenCRUD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	rt := &hubauth.RefreshToken{
		ClientID:   datastore.NameKey(kindClient, newRandomID(), nil).Encode(),
		User:       "foo@example.com",
		ExpiryTime: time.Now().Add(time.Hour).Truncate(time.Millisecond),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	res, err := s.GetRefreshToken(ctx, id)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	require.Equal(t, res.CreateTime, res.RenewTime)
	rt.CreateTime = res.CreateTime
	rt.RenewTime = res.RenewTime
	rt.ID = id
	require.Equal(t, rt, res)

	renewed, err := s.RenewRefreshToken(ctx, id)
	require.NoError(t, err)
	require.Equal(t, res.CreateTime, renewed.CreateTime)
	require.Truef(t, renewed.RenewTime.After(renewed.CreateTime), "%v renewal time not after %v", renewed.RenewTime, renewed.CreateTime)
	require.WithinDuration(t, time.Now(), renewed.RenewTime, time.Second)
	require.Equal(t, int64(1), renewed.Version)

	gotRenewed, err := s.GetRefreshToken(ctx, id)
	require.NoError(t, err)
	require.Equal(t, renewed, gotRenewed)

	err = s.DeleteRefreshToken(ctx, id)
	require.NoError(t, err)
	_, err = s.GetRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)

	_, err = s.RenewRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestRefreshTokenRenewExpired(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	rt := &hubauth.RefreshToken{
		ClientID:   datastore.NameKey(kindClient, newRandomID(), nil).Encode(),
		User:       "foo@example.com",
		ExpiryTime: time.Now().Add(-time.Minute),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	_, err = s.RenewRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrExpired), "wrong err %v", err)

	err = s.DeleteRefreshToken(ctx, id)
	require.NoError(t, err)
}

func TestRefreshTokenDeleteExpired(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	rt := &hubauth.RefreshToken{
		ClientID:   datastore.NameKey(kindClient, newRandomID(), nil).Encode(),
		User:       "foo@example.com",
		ExpiryTime: time.Now().Add(time.Hour).Truncate(time.Millisecond),
	}

	rt.ExpiryTime = time.Now().Add(time.Minute)
	keep, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	rt.ExpiryTime = time.Now().Add(-time.Minute)
	expired1, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	rt.ExpiryTime = time.Now().Add(-time.Second)
	expired2, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	deleted, err := s.DeleteExpiredRefreshTokens(ctx)
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

	_, err = s.GetRefreshToken(ctx, keep)
	require.NoError(t, err)
	_, err = s.GetRefreshToken(ctx, expired1)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
	_, err = s.GetRefreshToken(ctx, expired2)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}
