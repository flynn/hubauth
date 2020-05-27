package datastore

import (
	"context"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"golang.org/x/exp/errors/fmt"
)

func buildClient(c *hubauth.Client) *client {
	now := time.Now()
	policies := make([]googleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = buildGoogleUserPolicy(p)
	}
	return &client{
		RedirectURIs:       c.RedirectURIs,
		RefreshTokenExpiry: c.RefreshTokenExpiry,
		Policies:           policies,
		CreateTime:         now,
		UpdateTime:         now,
	}
}

type client struct {
	ID                 *datastore.Key `datastore:"__key__"`
	RedirectURIs       []string
	RefreshTokenExpiry time.Duration
	Policies           []googleUserPolicy `datastore:",flatten"`
	CreateTime         time.Time
	UpdateTime         time.Time
}

func buildGoogleUserPolicy(p *hubauth.GoogleUserPolicy) googleUserPolicy {
	return googleUserPolicy{
		Domain:  p.Domain,
		APIUser: p.APIUser,
		Groups:  strings.Join(p.Groups, ","),
	}
}

type googleUserPolicy struct {
	Domain  string
	APIUser string
	Groups  string // datastore doesn't take nested lists, so encode by comma-separating
}

func (c *client) Export() *hubauth.Client {
	policies := make([]*hubauth.GoogleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = &hubauth.GoogleUserPolicy{
			Domain:  p.Domain,
			APIUser: p.APIUser,
			Groups:  strings.Split(p.Groups, ","),
		}
	}
	return &hubauth.Client{
		ID:                 c.ID.Encode(),
		RedirectURIs:       c.RedirectURIs,
		RefreshTokenExpiry: c.RefreshTokenExpiry,
		Policies:           policies,
		CreateTime:         c.CreateTime,
		UpdateTime:         c.UpdateTime,
	}
}

func clientKey(id string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, err
	}
	if k.Kind != kindClient {
		return nil, fmt.Errorf("datastore: client key kind is unexpected: %q", k.Kind)
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
			case hubauth.ClientMutationOpSetPolicy:
				for i, p := range client.Policies {
					if p.Domain == m.Policy.Domain {
						client.Policies[i] = buildGoogleUserPolicy(&m.Policy)
						modified = true
						continue outer
					}
				}
				client.Policies = append(client.Policies, buildGoogleUserPolicy(&m.Policy))
				modified = true
			case hubauth.ClientMutationOpDeletePolicy:
				for i, p := range client.Policies {
					if p.Domain != m.Policy.Domain {
						continue
					}
					client.Policies[i] = client.Policies[len(client.Policies)-1]
					client.Policies = client.Policies[:len(client.Policies)-1]
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
