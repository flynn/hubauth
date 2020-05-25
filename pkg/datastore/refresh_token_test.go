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

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "123",
		UserEmail:  "foo@example.com",
		ExpiryTime: time.Now().Add(time.Hour).Truncate(time.Millisecond),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	res, err := s.GetRefreshToken(ctx, id)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	require.Equal(t, res.CreateTime, res.RenewTime)
	rt.CreateTime = res.CreateTime
	rt.RenewTime = res.RenewTime
	rt.ID = id
	require.Equal(t, rt, res)

	renewed, err := s.RenewRefreshToken(ctx, rt.ClientID, id, 0)
	require.NoError(t, err)
	require.Equal(t, res.CreateTime, renewed.CreateTime)
	require.Truef(t, renewed.RenewTime.After(renewed.CreateTime), "%v renewal time not after %v", renewed.RenewTime, renewed.CreateTime)
	require.WithinDuration(t, time.Now(), renewed.RenewTime, time.Second)
	require.Equal(t, 1, renewed.Version)

	gotRenewed, err := s.GetRefreshToken(ctx, id)
	require.NoError(t, err)
	require.Equal(t, renewed, gotRenewed)

	err = s.DeleteRefreshToken(ctx, id)
	require.NoError(t, err)
	_, err = s.GetRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)

	_, err = s.RenewRefreshToken(ctx, rt.ClientID, id, 0)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestRefreshTokenRenewExpired(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "123",
		UserEmail:  "foo@example.com",
		ExpiryTime: time.Now().Add(-time.Minute),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	_, err = s.RenewRefreshToken(ctx, rt.ClientID, id, 0)
	require.Truef(t, errors.Is(err, hubauth.ErrExpired), "wrong err %v", err)

	err = s.DeleteRefreshToken(ctx, id)
	require.NoError(t, err)
}

func TestRefreshTokenRenewWrongVersion(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "foo@example.com",
		ExpiryTime: time.Now().Add(time.Minute),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	_, err = s.RenewRefreshToken(ctx, rt.ClientID, id, 1)
	require.Truef(t, errors.Is(err, hubauth.ErrRefreshTokenVersionMismatch), "wrong err %v", err)

	_, err = s.GetRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestRefreshTokenRenewWrongClientID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "123",
		UserEmail:  "foo@example.com",
		ExpiryTime: time.Now().Add(time.Minute),
	}
	id, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	_, err = s.RenewRefreshToken(ctx, "a", id, 0)
	require.Truef(t, errors.Is(err, hubauth.ErrClientIDMismatch), "wrong err %v", err)

	_, err = s.GetRefreshToken(ctx, id)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestRefreshTokenDeleteExpired(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "123",
		UserEmail:  "foo@example.com",
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

	deleted, err = s.DeleteExpiredRefreshTokens(ctx)
	require.NoError(t, err)
	require.Len(t, deleted, 0)
}

func TestRefreshTokenDeleteWithCode(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	clientID := datastore.NameKey(kindClient, newRandomID(), nil)
	rt := &hubauth.RefreshToken{
		ClientID:   clientID.Encode(),
		CodeID:     datastore.NameKey(kindCode, newRandomID(), clientID).Encode(),
		UserID:     "123",
		UserEmail:  "foo@example.com",
		ExpiryTime: time.Now().Add(time.Hour).Truncate(time.Millisecond),
	}
	deleteCode := rt.CodeID

	delete1, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	delete2, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	rt.CodeID = datastore.NameKey(kindCode, newRandomID(), clientID).Encode()
	keep, err := s.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)

	deleted, err := s.DeleteRefreshTokensWithCode(ctx, deleteCode)
	require.NoError(t, err)
	var found1, found2, foundKeep bool
	for _, id := range deleted {
		switch id {
		case delete1:
			found1 = true
		case delete2:
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
	_, err = s.GetRefreshToken(ctx, delete1)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
	_, err = s.GetRefreshToken(ctx, delete2)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)

	deleted, err = s.DeleteRefreshTokensWithCode(ctx, deleteCode)
	require.NoError(t, err)
	require.Len(t, deleted, 0)
}
