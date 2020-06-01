package datastore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"golang.org/x/exp/errors/fmt"
)

func buildClient(c *hubauth.Client) *client {
	now := time.Now()
	return &client{
		RedirectURIs:       c.RedirectURIs,
		RefreshTokenExpiry: c.RefreshTokenExpiry,
		CreateTime:         now,
		UpdateTime:         now,
	}
}

type client struct {
	ID                 *datastore.Key `datastore:"__key__"`
	RedirectURIs       []string
	RefreshTokenExpiry time.Duration
	CreateTime         time.Time
	UpdateTime         time.Time
}

func (c *client) Export() *hubauth.Client {
	return &hubauth.Client{
		ID:                 c.ID.Encode(),
		RedirectURIs:       c.RedirectURIs,
		RefreshTokenExpiry: c.RefreshTokenExpiry,
		CreateTime:         c.CreateTime,
		UpdateTime:         c.UpdateTime,
	}
}

func clientKey(id string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, hubauth.ErrNotFound
	}
	if k.Kind != kindClient {
		return nil, hubauth.ErrNotFound
	}
	return k, nil
}

func (s *service) GetClient(ctx context.Context, id string) (*hubauth.Client, error) {
	k, err := clientKey(id)
	if err != nil {
		return nil, err
	}
	res := &client{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching client %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *service) CreateClient(ctx context.Context, client *hubauth.Client) (string, error) {
	k, err := s.db.Put(ctx, datastore.IncompleteKey(kindClient, nil), buildClient(client))
	if err != nil {
		return "", fmt.Errorf("datastore: error creating client: %w", err)
	}
	return k.Encode(), nil
}

func (s *service) MutateClient(ctx context.Context, id string, mut []*hubauth.ClientMutation) error {
	k, err := clientKey(id)
	if err != nil {
		return err
	}
	_, err = s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		client := &client{}
		if err := tx.Get(k, client); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return fmt.Errorf("datastore: error fetching client %s: %w", id, err)
		}
		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.ClientMutationOpAddRedirectURI:
				for _, u := range client.RedirectURIs {
					if u == m.RedirectURI {
						continue outer
					}
				}
				client.RedirectURIs = append(client.RedirectURIs, m.RedirectURI)
				modified = true
			case hubauth.ClientMutationOpDeleteRedirectURI:
				for i, u := range client.RedirectURIs {
					if u != m.RedirectURI {
						continue
					}
					client.RedirectURIs[i] = client.RedirectURIs[len(client.RedirectURIs)-1]
					client.RedirectURIs = client.RedirectURIs[:len(client.RedirectURIs)-1]
					modified = true
				}
			default:
				return fmt.Errorf("datastore: unknown client mutation op %s", m.Op)
			}
		}
		if !modified {
			return nil
		}
		client.UpdateTime = time.Now()
		_, err := tx.Put(k, client)
		return err
	})
	if err != nil {
		return fmt.Errorf("datastore: error mutating client %s: %w", id, err)
	}
	return nil
}

func (s *service) ListClients(ctx context.Context) ([]*hubauth.Client, error) {
	var clients []*client
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindClient), &clients); err != nil {
		return nil, fmt.Errorf("datastore: error listing clients: %w", err)
	}
	res := make([]*hubauth.Client, len(clients))
	for i, c := range clients {
		res[i] = c.Export()
	}
	return res, nil
}

func (s *service) DeleteClient(ctx context.Context, id string) error {
	k, err := clientKey(id)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting client %s: %w", id, err)
	}
	return nil
}
