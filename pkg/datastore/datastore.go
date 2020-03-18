package datastore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"golang.org/x/exp/errors/fmt"
)

const (
	kindClient            = "Client"
	kindCode              = "Code"
	kindRefreshToken      = "RefreshToken"
	kindDomain            = "GoogleDomain"
	kindCachedGroup       = "CachedGoogleGroup"
	kindCachedGroupMember = "CachedGoogleGroupMember"
)

type Service struct {
	db *datastore.Client
}

func newRandomID() string {
	data := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, data)
	if err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func (s *Service) deleteExpired(ctx context.Context, kind string) ([]string, error) {
	var deleted []string
	q := datastore.NewQuery(kind).Filter("ExpiryTime <", time.Now()).Limit(500).KeysOnly()
	for {
		done := len(deleted)
		_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
			keys, err := s.db.GetAll(ctx, q.Transaction(tx), nil)
			if err != nil {
				return fmt.Errorf("datastore: error listing expired %s: %w", kind, err)
			}
			if err := tx.DeleteMulti(keys); err != nil {
				return err
			}
			for _, k := range keys {
				deleted = append(deleted, k.Encode())
			}
			return nil
		})
		if err != nil {
			return deleted, fmt.Errorf("datastore: error deleting expired %s: %w", kind, err)
		}
		if len(deleted) == done {
			break
		}
	}
	return deleted, nil
}
