package datastore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"golang.org/x/exp/errors/fmt"
)

func buildRefreshToken(t *hubauth.RefreshToken) (*refreshToken, error) {
	parentKey, err := clientKey(t.ClientID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &refreshToken{
		Key:        datastore.NameKey(kindRefreshToken, newRandomID(), parentKey),
		User:       t.User,
		Version:    0,
		CreateTime: now,
		RenewTime:  now,
		ExpiryTime: t.ExpiryTime,
	}, nil
}

type refreshToken struct {
	Key        *datastore.Key `datastore:"__key__"`
	User       string
	Version    int64 `datastore:",noindex"`
	CreateTime time.Time
	RenewTime  time.Time
	ExpiryTime time.Time
}

func (t *refreshToken) Export() *hubauth.RefreshToken {
	return &hubauth.RefreshToken{
		ID:         t.Key.Encode(),
		ClientID:   t.Key.Parent.Encode(),
		User:       t.User,
		Version:    t.Version,
		CreateTime: t.CreateTime,
		RenewTime:  t.RenewTime,
		ExpiryTime: t.ExpiryTime,
	}
}

func refreshTokenKey(id string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, err
	}
	if k.Kind != kindRefreshToken {
		return nil, fmt.Errorf("datastore: refresh token key kind is unexpected: %q", k.Kind)
	}
	if k.Parent == nil || k.Parent.Kind != kindClient {
		return nil, fmt.Errorf("datastore: refresh token key parent is invalid")
	}
	return k, nil
}

func (s *Service) GetRefreshToken(ctx context.Context, id string) (*hubauth.RefreshToken, error) {
	k, err := refreshTokenKey(id)
	if err != nil {
		return nil, err
	}
	res := &refreshToken{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching refresh token %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *Service) CreateRefreshToken(ctx context.Context, token *hubauth.RefreshToken) (string, error) {
	data, err := buildRefreshToken(token)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Put(ctx, data.Key, data); err != nil {
		return "", fmt.Errorf("datastore: error creating refresh token: %w", err)
	}
	return data.Key.Encode(), nil
}

func (s *Service) RenewRefreshToken(ctx context.Context, id string) (*hubauth.RefreshToken, error) {
	k, err := refreshTokenKey(id)
	if err != nil {
		return nil, err
	}
	t := &refreshToken{}
	_, err = s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		if err := tx.Get(k, t); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return err
		}
		now := time.Now()
		if now.After(t.ExpiryTime) {
			return hubauth.ErrExpired
		}
		t.Version++
		t.RenewTime = now
		_, err = tx.Put(k, t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("datastore: error renewing refresh token %s: %w", id, err)
	}
	return t.Export(), nil
}

func (s *Service) DeleteRefreshToken(ctx context.Context, id string) error {
	k, err := refreshTokenKey(id)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting refresh token %s: %w", id, err)
	}
	return nil
}

func (s *Service) DeleteExpiredRefreshTokens(ctx context.Context) ([]string, error) {
	return s.deleteExpired(ctx, kindRefreshToken)
}
