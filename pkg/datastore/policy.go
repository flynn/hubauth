package datastore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"golang.org/x/exp/errors/fmt"
)

func buildBiscuitPolicy(p *hubauth.BiscuitPolicy) *biscuitPolicy {
	now := time.Now()
	return &biscuitPolicy{
		Content:    p.Content,
		Groups:     p.Groups,
		CreateTime: now,
		UpdateTime: now,
	}
}

type biscuitPolicy struct {
	ID         *datastore.Key `datastore:"__key__"`
	Content    string
	Groups     []string
	CreateTime time.Time
	UpdateTime time.Time
}

func (c *biscuitPolicy) Export() *hubauth.BiscuitPolicy {
	return &hubauth.BiscuitPolicy{
		ID:         c.ID.Encode(),
		Content:    c.Content,
		Groups:     c.Groups,
		CreateTime: c.CreateTime,
		UpdateTime: c.UpdateTime,
	}
}

func biscuitPolicyKey(id string) (*datastore.Key, error) {
	k, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, hubauth.ErrNotFound
	}
	if k.Kind != kindBiscuitPolicy {
		return nil, hubauth.ErrNotFound
	}
	return k, nil
}

func (s *service) GetBiscuitPolicy(ctx context.Context, id string) (*hubauth.BiscuitPolicy, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetBiscuitPolicy")
	span.AddAttributes(trace.StringAttribute("biscuit_policy_id", id))
	defer span.End()

	k, err := biscuitPolicyKey(id)
	if err != nil {
		return nil, err
	}
	res := &biscuitPolicy{}
	if err := s.db.Get(ctx, k, res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching biscuit policy %s: %w", id, err)
	}
	return res.Export(), nil
}

func (s *service) CreateBiscuitPolicy(ctx context.Context, policy *hubauth.BiscuitPolicy) (string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.CreateBiscuitPolicy")
	defer span.End()

	k, err := s.db.Put(ctx, datastore.IncompleteKey(kindBiscuitPolicy, nil), buildBiscuitPolicy(policy))
	if err != nil {
		return "", fmt.Errorf("datastore: error creating biscuit policy: %w", err)
	}
	id := k.Encode()
	span.AddAttributes(trace.StringAttribute("biscuit_policy_id", id))
	return id, nil
}

func (s *service) MutateBiscuitPolicy(ctx context.Context, id string, mut []*hubauth.BiscuitPolicyMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateBiscuitPolicy")
	span.AddAttributes(
		trace.StringAttribute("biscuit_policy_id", id),
		trace.Int64Attribute("biscuit_policy_mutation_count", int64(len(mut))),
	)
	defer span.End()

	k, err := biscuitPolicyKey(id)
	if err != nil {
		return err
	}
	_, err = s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		policy := &biscuitPolicy{}
		if err := tx.Get(k, policy); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return fmt.Errorf("datastore: error fetching biscuit policy %s: %w", id, err)
		}
		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.BiscuitPolicyMutationOpAddGroup:
				for _, g := range policy.Groups {
					if g == m.Group {
						continue outer
					}
				}
				policy.Groups = append(policy.Groups, m.Group)
				modified = true
			case hubauth.BiscuitPolicyMutationOpDeleteGroup:
				for i, u := range policy.Groups {
					if u != m.Group {
						continue
					}
					policy.Groups[i] = policy.Groups[len(policy.Groups)-1]
					policy.Groups = policy.Groups[:len(policy.Groups)-1]
					modified = true
				}
			default:
				return fmt.Errorf("datastore: unknown biscuit policy mutation op %s", m.Op)
			}
		}
		if !modified {
			return nil
		}
		policy.UpdateTime = time.Now()
		_, err := tx.Put(k, policy)
		return err
	})
	if err != nil {
		return fmt.Errorf("datastore: error mutating biscuit policy %s: %w", id, err)
	}
	return nil
}

func (s *service) ListBiscuitPolicies(ctx context.Context) ([]*hubauth.BiscuitPolicy, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListBiscuitPolicies")
	defer span.End()

	var policies []*biscuitPolicy
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindBiscuitPolicy), &policies); err != nil {
		return nil, fmt.Errorf("datastore: error listing biscuit policies: %w", err)
	}
	res := make([]*hubauth.BiscuitPolicy, len(policies))
	for i, c := range policies {
		res[i] = c.Export()
	}
	return res, nil
}

func (s *service) DeleteBiscuitPolicy(ctx context.Context, id string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteBiscuitPolicy")
	span.AddAttributes(trace.StringAttribute("biscuit_policy_id", id))
	defer span.End()

	k, err := biscuitPolicyKey(id)
	if err != nil {
		return err
	}
	if err := s.db.Delete(ctx, k); err != nil {
		return fmt.Errorf("datastore: error deleting biscuit policy %s: %w", id, err)
	}
	return nil
}
