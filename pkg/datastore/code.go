package datastore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"golang.org/x/exp/errors/fmt"
)

func buildCode(c *hubauth.Code) (*code, error) {
	parentKey, err := clientKey(c.ClientID)
	if err != nil {
		return nil, err
	}
	return &code{
		Key:           datastore.NameKey(kindCode, newRandomID(), parentKey),
		RedirectURI:   c.RedirectURI,
		Nonce:         c.Nonce,
		PKCEChallenge: c.PKCEChallenge,
		CreateTime:    time.Now(),
		ExpiryTime:    c.ExpiryTime,
	}, nil
}

type code struct {
	Key           *datastore.Key `datastore:"__key__"`
	RedirectURI   string
	Nonce         string `datastore:",noindex"`
	PKCEChallenge string `datastore:",noindex"`
	CreateTime    time.Time
	ExpiryTime    time.Time
}

func (c *code) Export() *hubauth.Code {
	return &hubauth.Code{
		Code:          c.Key.Encode(),
		ClientID:      c.Key.Parent.Encode(),
		RedirectURI:   c.RedirectURI,
		Nonce:         c.Nonce,
		PKCEChallenge: c.PKCEChallenge,
		CreateTime:    c.CreateTime,
		ExpiryTime:    c.ExpiryTime,
	}
}

func codeKey(code string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(code)
	if err != nil {
		return nil, err
	}
	if k.Kind != kindCode {
		return nil, fmt.Errorf("datastore: code key kind is unexpected: %q", k.Kind)
	}
	if k.Parent == nil || k.Parent.Kind != kindClient {
		return nil, fmt.Errorf("datastore: code key parent is invalid")
	}
	return k, nil
}

func (s *Service) GetCode(ctx context.Context, c string) (*hubauth.Code, error) {
	k, err := codeKey(c)
	if err != nil {
		return nil, err
	}
	res := &code{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching code %s: %w", c, err)
	}
	return res.Export(), nil
}

func (s *Service) CreateCode(ctx context.Context, code *hubauth.Code) (string, error) {
	data, err := buildCode(code)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Put(ctx, data.Key, data); err != nil {
		return "", fmt.Errorf("datastore: error creating code: %w", err)
	}
	return data.Key.Encode(), nil
}

func (s *Service) DeleteCode(ctx context.Context, code string) error {
	k, err := codeKey(code)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting code %s: %w", code, err)
	}
	return nil
}

func (s *Service) DeleteExpiredCodes(ctx context.Context) ([]string, error) {
	return s.deleteExpired(ctx, kindCode)
}
