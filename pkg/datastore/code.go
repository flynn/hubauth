package datastore

import (
	"context"
	"crypto/hmac"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"golang.org/x/exp/errors/fmt"
)

func buildCode(c *hubauth.Code) (*code, error) {
	parentKey, err := clientKey(c.ClientID)
	if err != nil {
		return nil, err
	}
	return &code{
		Key:           datastore.IncompleteKey(kindCode, parentKey),
		Secret:        newRandomID(),
		UserID:        c.UserID,
		UserEmail:     c.UserEmail,
		RedirectURI:   c.RedirectURI,
		Nonce:         c.Nonce,
		PKCEChallenge: c.PKCEChallenge,
		CreateTime:    time.Now(),
		ExpiryTime:    c.ExpiryTime,
	}, nil
}

type code struct {
	Key           *datastore.Key `datastore:"__key__"`
	Secret        string
	UserID        string
	UserEmail     string
	RedirectURI   string
	Nonce         string `datastore:",noindex"`
	PKCEChallenge string `datastore:",noindex"`
	CreateTime    time.Time
	ExpiryTime    time.Time
}

func (c *code) Export() *hubauth.Code {
	return &hubauth.Code{
		ID:            c.Key.Encode(),
		Secret:        c.Secret,
		ClientID:      c.Key.Parent.Encode(),
		UserID:        c.UserID,
		UserEmail:     c.UserEmail,
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
		return nil, hubauth.ErrNotFound
	}
	if k.Kind != kindCode {
		return nil, hubauth.ErrNotFound
	}
	if k.Parent == nil || k.Parent.Kind != kindClient {
		return nil, hubauth.ErrNotFound
	}
	return k, nil
}

func (s *service) GetCode(ctx context.Context, id string) (*hubauth.Code, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetCode")
	span.AddAttributes(trace.StringAttribute("code_id", id))
	defer span.End()

	k, err := codeKey(id)
	if err != nil {
		return nil, err
	}
	res := &code{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching code %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *service) VerifyAndDeleteCode(ctx context.Context, id, secret string) (*hubauth.Code, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.VerifyAndDeleteCode")
	span.AddAttributes(trace.StringAttribute("code_id", id))
	defer span.End()

	k, err := codeKey(id)
	if err != nil {
		return nil, err
	}
	res := &code{}
	_, err = s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		if err := tx.Get(k, res); err != nil {
			return err
		}
		return tx.Delete(k)
	})
	// constant time compare is overkill here because this should only run once, but do it anyway
	if err == nil && !hmac.Equal([]byte(res.Secret), []byte(secret)) {
		err = hubauth.ErrIncorrectCodeSecret
	}
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error verifying and deleting code %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *service) CreateCode(ctx context.Context, code *hubauth.Code) (string, string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.CreateCode")
	defer span.End()

	data, err := buildCode(code)
	if err != nil {
		return "", "", err
	}
	key, err := s.db.Put(ctx, data.Key, data)
	if err != nil {
		return "", "", fmt.Errorf("datastore: error creating code: %w", err)
	}
	encodedKey := key.Encode()
	span.AddAttributes(trace.StringAttribute("code_id", encodedKey))
	return encodedKey, data.Secret, nil
}

func (s *service) DeleteCode(ctx context.Context, code string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteCode")
	span.AddAttributes(trace.StringAttribute("code_id", code))
	defer span.End()

	k, err := codeKey(code)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting code %s: %w", code, err)
	}
	return nil
}

func (s *service) DeleteExpiredCodes(ctx context.Context) ([]string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteExpiredCodes")
	defer span.End()

	res, err := s.deleteExpired(ctx, kindCode)
	span.AddAttributes(trace.Int64Attribute("codes_deleted", int64(len(res))))

	return res, err
}
