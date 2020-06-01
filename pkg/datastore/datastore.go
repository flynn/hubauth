package datastore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"golang.org/x/exp/errors/fmt"
)

const (
	kindClient            = "Client"
	kindCluster           = "Cluster"
	kindCode              = "Code"
	kindRefreshToken      = "RefreshToken"
	kindDomain            = "GoogleDomain"
	kindCachedGroup       = "CachedGoogleGroup"
	kindCachedGroupMember = "CachedGoogleGroupMember"
)

func New(db *datastore.Client) hubauth.DataStore {
	return &service{db: db}
}

type service struct {
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

func (s *service) deleteExpired(ctx context.Context, kind string) ([]string, error) {
	var deleted []string
	q := datastore.NewQuery(kind).Filter("ExpiryTime <", time.Now()).KeysOnly()
	keys, err := s.db.GetAll(ctx, q, nil)
	if err != nil {
		return nil, fmt.Errorf("datastore: error listing expired %s: %w", kind, err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	for _, keyChunk := range chunkKeys(keys, 500) {
		if err := s.db.DeleteMulti(ctx, keyChunk); err != nil {
			return deleted, fmt.Errorf("datastore: error deleting expired %s: %w", kind, err)
		}
		for _, k := range keys {
			deleted = append(deleted, k.Encode())
		}
	}
	return deleted, nil
}

func chunkKeys(keys []*datastore.Key, lim int) [][]*datastore.Key {
	var chunk []*datastore.Key
	chunks := make([][]*datastore.Key, 0, len(keys)/lim+1)
	for len(keys) >= lim {
		chunk, keys = keys[:lim], keys[lim:]
		chunks = append(chunks, chunk)
	}
	if len(keys) > 0 {
		chunks = append(chunks, keys)
	}
	return chunks
}
