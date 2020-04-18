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
		keys, err := s.db.GetAll(ctx, q, nil)
		if err != nil {
			return nil, fmt.Errorf("datastore: error listing expired %s: %w", kind, err)
		}
		if err := s.db.DeleteMulti(ctx, keys); err != nil {
			return nil, err
		}
		for _, k := range keys {
			deleted = append(deleted, k.Encode())
		}
		if err != nil {
			return deleted, fmt.Errorf("datastore: error deleting expired %s: %w", kind, err)
		}
		if len(deleted) == done {
			break
		}
	}
	return deleted, nil
}
