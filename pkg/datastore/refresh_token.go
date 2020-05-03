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
	codeKey, err := codeKey(t.CodeID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &refreshToken{
		Key:        datastore.NameKey(kindRefreshToken, newRandomID(), parentKey),
		UserID:     t.UserID,
		Code:       codeKey,
		Version:    0,
		CreateTime: now,
		RenewTime:  now,
		ExpiryTime: t.ExpiryTime,
	}, nil
}

type refreshToken struct {
	Key        *datastore.Key `datastore:"__key__"`
	UserID     string
	Code       *datastore.Key
	Version    int `datastore:",noindex"`
	CreateTime time.Time
	RenewTime  time.Time
	ExpiryTime time.Time
}

func (t *refreshToken) Export() *hubauth.RefreshToken {
	return &hubauth.RefreshToken{
		ID:         t.Key.Encode(),
		ClientID:   t.Key.Parent.Encode(),
		UserID:     t.UserID,
		CodeID:     t.Code.Encode(),
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

func (s *Service) RenewRefreshToken(ctx context.Context, id string, version int) (*hubauth.RefreshToken, error) {
	k, err := refreshTokenKey(id)
	if err != nil {
		return nil, err
	}
	t := &refreshToken{}
	versionMismatch := false
	_, err = s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		if err := tx.Get(k, t); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return err
		}
		now := time.Now().Truncate(time.Millisecond)
		if now.After(t.ExpiryTime) {
			return hubauth.ErrExpired
		}
		if t.Version != version {
			if err := tx.Delete(k); err != nil {
				return err
			}
			versionMismatch = true
			return nil
		}
		t.Version++
		t.RenewTime = now
		_, err = tx.Put(k, t)
		return err
	})
	if versionMismatch {
		err = hubauth.ErrRefreshTokenVersionMismatch
	}
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

func (s *Service) DeleteRefreshTokensWithCode(ctx context.Context, c string) ([]string, error) {
	parsedCodeKey, err := codeKey(c)
	if err != nil {
		return nil, err
	}
	q := datastore.NewQuery(kindRefreshToken).Filter("Code = ", parsedCodeKey).KeysOnly()
	keys, err := s.db.GetAll(ctx, q, nil)
	if err != nil {
		return nil, fmt.Errorf("datastore: error listing refresh tokens with code %s: %w", c, err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	if err := s.db.DeleteMulti(ctx, keys); err != nil {
		return nil, fmt.Errorf("datastore: error deleting refresh tokens with code %s: %w", c, err)
	}
	res := make([]string, len(keys))
	for i, k := range keys {
		res[i] = k.Encode()
	}
	return res, nil
}

func (s *Service) DeleteExpiredRefreshTokens(ctx context.Context) ([]string, error) {
	return s.deleteExpired(ctx, kindRefreshToken)
}
