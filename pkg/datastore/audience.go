package datastore

import (
	"context"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"golang.org/x/exp/errors/fmt"
)

func buildAudience(c *hubauth.Audience) *audience {
	now := time.Now()
	policies := make([]googleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = buildGoogleUserPolicy(p)
	}
	return &audience{
		Key:        audienceKey(c.URL),
		Name:       c.Name,
		Type:       c.Type,
		ClientIDs:  c.ClientIDs,
		Policies:   policies,
		CreateTime: now,
		UpdateTime: now,
	}
}

type audience struct {
	Key        *datastore.Key `datastore:"__key__"`
	Name       string
	Type       string
	ClientIDs  []string
	Policies   []googleUserPolicy `datastore:",flatten"`
	CreateTime time.Time
	UpdateTime time.Time
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

func (c *audience) Export() *hubauth.Audience {
	policies := make([]*hubauth.GoogleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		var grps []string
		if p.Groups != "" {
			grps = strings.Split(p.Groups, ",")
		}

		policies[i] = &hubauth.GoogleUserPolicy{
			Domain:  p.Domain,
			APIUser: p.APIUser,
			Groups:  grps,
		}
	}
	return &hubauth.Audience{
		URL:        c.Key.Name,
		Name:       c.Name,
		Type:       c.Type,
		ClientIDs:  c.ClientIDs,
		Policies:   policies,
		CreateTime: c.CreateTime,
		UpdateTime: c.UpdateTime,
	}
}

func audienceKey(url string) *datastore.Key {
	return datastore.NameKey(kindAudience, url, nil)
}

func (s *service) GetAudience(ctx context.Context, url string) (*hubauth.Audience, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetAudience")
	span.AddAttributes(trace.StringAttribute("audience_url", url))
	defer span.End()

	res := &audience{}
	if err := s.db.Get(ctx, audienceKey(url), res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching audience %s: %w", url, err)
	}
	return res.Export(), nil
}

func (s *service) CreateAudience(ctx context.Context, audience *hubauth.Audience) error {
	ctx, span := trace.StartSpan(ctx, "datastore.CreateAudience")
	span.AddAttributes(trace.StringAttribute("audience_url", audience.URL))
	defer span.End()

	c := buildAudience(audience)
	if _, err := s.db.Put(ctx, c.Key, c); err != nil {
		return fmt.Errorf("datastore: error creating audience: %w", err)
	}
	return nil
}

func (s *service) MutateAudience(ctx context.Context, url string, mut []*hubauth.AudienceMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateAudience")
	span.AddAttributes(
		trace.StringAttribute("audience_url", url),
		trace.Int64Attribute("audience_mutation_count", int64(len(mut))),
	)
	defer span.End()

	k := audienceKey(url)
	_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		aud := &audience{}
		if err := tx.Get(k, aud); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return fmt.Errorf("datastore: error fetching audience %s: %w", url, err)
		}
		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.AudienceMutationOpAddClientID:
				for _, id := range aud.ClientIDs {
					if id == m.ClientID {
						continue outer
					}
				}
				aud.ClientIDs = append(aud.ClientIDs, m.ClientID)
				modified = true
			case hubauth.AudienceMutationOpDeleteClientID:
				for i, u := range aud.ClientIDs {
					if u != m.ClientID {
						continue
					}
					aud.ClientIDs[i] = aud.ClientIDs[len(aud.ClientIDs)-1]
					aud.ClientIDs = aud.ClientIDs[:len(aud.ClientIDs)-1]
					modified = true
				}
			case hubauth.AudienceMutationOpSetPolicy:
				for i, p := range aud.Policies {
					if p.Domain == m.Policy.Domain {
						aud.Policies[i] = buildGoogleUserPolicy(&m.Policy)
						modified = true
						continue outer
					}
				}
				aud.Policies = append(aud.Policies, buildGoogleUserPolicy(&m.Policy))
				modified = true
			case hubauth.AudienceMutationOpDeletePolicy:
				for i, p := range aud.Policies {
					if p.Domain != m.Policy.Domain {
						continue
					}
					aud.Policies[i] = aud.Policies[len(aud.Policies)-1]
					aud.Policies = aud.Policies[:len(aud.Policies)-1]
					modified = true
				}
			case hubauth.AudienceMutationSetType:
				if aud.Type == m.Type {
					continue
				}
				aud.Type = m.Type
				modified = true
			default:
				return fmt.Errorf("datastore: unknown audience mutation op %s", m.Op)
			}
		}
		if !modified {
			return nil
		}
		aud.UpdateTime = time.Now()
		_, err := tx.Put(k, aud)
		return err
	})
	if err != nil {
		return fmt.Errorf("datastore: error mutating audience %s: %w", url, err)
	}
	return nil
}

func (s *service) MutateAudiencePolicy(ctx context.Context, url string, domain string, mut []*hubauth.AudiencePolicyMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateAudiencePolicy")
	span.AddAttributes(
		trace.StringAttribute("audience_url", url),
		trace.StringAttribute("audience_policy_domain", domain),
		trace.Int64Attribute("audience_policy_mutation_count", int64(len(mut))),
	)
	defer span.End()

	k := audienceKey(url)
	_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		aud := &audience{}
		if err := tx.Get(k, aud); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return fmt.Errorf("datastore: error fetching audience %s: %w", url, err)
		}

		var policy *googleUserPolicy
		for i := range aud.Policies {
			if aud.Policies[i].Domain == domain {
				policy = &aud.Policies[i]
				break
			}
		}
		if policy == nil {
			return hubauth.ErrNotFound
		}

		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.AudiencePolicyMutationOpAddGroup:
				groups := strings.Split(policy.Groups, ",")
				for _, g := range groups {
					if g == m.Group {
						continue outer
					}
				}
				policy.Groups = strings.Join(append(groups, m.Group), ",")
				modified = true
			case hubauth.AudiencePolicyMutationOpDeleteGroup:
				groups := strings.Split(policy.Groups, ",")
				for i, g := range groups {
					if g != m.Group {
						continue
					}
					groups[i] = groups[len(groups)-1]
					groups = groups[:len(groups)-1]
				}
				policy.Groups = strings.Join(groups, ",")
				modified = true
			case hubauth.AudiencePolicyMutationOpSetAPIUser:
				if policy.APIUser == m.APIUser {
					continue
				}
				policy.APIUser = m.APIUser
				modified = true
			default:
				return fmt.Errorf("datastore: unknown audience policy mutation op %s", m.Op)
			}
		}
		if !modified {
			return nil
		}
		aud.UpdateTime = time.Now()
		_, err := tx.Put(k, aud)
		return err
	})
	if err != nil {
		return fmt.Errorf("datastore: error mutating audience %s: %w", url, err)
	}
	return nil
}

func (s *service) ListAudiences(ctx context.Context) ([]*hubauth.Audience, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListAudiences")
	defer span.End()

	var audiences []*audience
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindAudience), &audiences); err != nil {
		return nil, fmt.Errorf("datastore: error listing audiences: %w", err)
	}
	res := make([]*hubauth.Audience, len(audiences))
	for i, c := range audiences {
		res[i] = c.Export()
	}
	return res, nil
}

func (s *service) ListAudiencesForClient(ctx context.Context, clientID string) ([]*hubauth.Audience, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListAudiencesForClient")
	span.AddAttributes(trace.StringAttribute("client_id", clientID))
	defer span.End()

	var audiences []*audience
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindAudience).Filter("ClientIDs =", clientID), &audiences); err != nil {
		return nil, fmt.Errorf("datastore: error listing audiences for clientID %s: %w", clientID, err)
	}
	res := make([]*hubauth.Audience, len(audiences))
	for i, c := range audiences {
		res[i] = c.Export()
	}
	span.AddAttributes(trace.Int64Attribute("audience_count", int64(len(res))))
	return res, nil
}

func (s *service) DeleteAudience(ctx context.Context, url string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteAudience")
	span.AddAttributes(trace.StringAttribute("audience_url", url))
	defer span.End()

	if err := s.db.Delete(ctx, audienceKey(url)); err != nil {
		return fmt.Errorf("datastore: error deleting audience %s: %w", url, err)
	}
	return nil
}
