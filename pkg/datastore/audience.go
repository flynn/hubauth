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
	userGroups := make([]googleUserGroups, len(c.UserGroups))
	for i, p := range c.UserGroups {
		userGroups[i] = buildGoogleUserGroups(p)
	}

	policies := make([]biscuitPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = buildBiscuitPolicy(p)
	}

	return &audience{
		Key:        audienceKey(c.URL),
		Name:       c.Name,
		Type:       c.Type,
		ClientIDs:  c.ClientIDs,
		UserGroups: userGroups,
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
	UserGroups []googleUserGroups `datastore:",flatten"`
	Policies   []biscuitPolicy    `datastore:",flatten"`
	CreateTime time.Time
	UpdateTime time.Time
}

func buildGoogleUserGroups(p *hubauth.GoogleUserGroups) googleUserGroups {
	return googleUserGroups{
		Domain:  p.Domain,
		APIUser: p.APIUser,
		Groups:  strings.Join(p.Groups, ","),
	}
}

func buildBiscuitPolicy(p *hubauth.BiscuitPolicy) biscuitPolicy {
	return biscuitPolicy{
		Name:    p.Name,
		Content: p.Content,
		Groups:  strings.Join(p.Groups, ","),
	}
}

type googleUserGroups struct {
	Domain  string
	APIUser string
	Groups  string // datastore doesn't take nested lists, so encode by comma-separating
}

type biscuitPolicy struct {
	Name    string
	Content string
	Groups  string // datastore doesn't take nested lists, so encode by comma-separating
}

func (c *audience) Export() *hubauth.Audience {
	var userGroups []*hubauth.GoogleUserGroups
	if len(c.UserGroups) > 0 {
		userGroups = make([]*hubauth.GoogleUserGroups, len(c.UserGroups))
		for i, p := range c.UserGroups {
			var grps []string
			if p.Groups != "" {
				grps = strings.Split(p.Groups, ",")
			}

			userGroups[i] = &hubauth.GoogleUserGroups{
				Domain:  p.Domain,
				APIUser: p.APIUser,
				Groups:  grps,
			}
		}
	}
	var policies []*hubauth.BiscuitPolicy
	if len(c.Policies) > 0 {
		policies = make([]*hubauth.BiscuitPolicy, len(c.Policies))
		for i, p := range c.Policies {
			var grps []string
			if p.Groups != "" {
				grps = strings.Split(p.Groups, ",")
			}

			policies[i] = &hubauth.BiscuitPolicy{
				Name:    p.Name,
				Content: p.Content,
				Groups:  grps,
			}
		}
	}

	return &hubauth.Audience{
		URL:        c.Key.Name,
		Name:       c.Name,
		Type:       c.Type,
		ClientIDs:  c.ClientIDs,
		UserGroups: userGroups,
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
			case hubauth.AudienceMutationOpSetUserGroups:
				for i, p := range aud.UserGroups {
					if p.Domain == m.UserGroups.Domain {
						aud.UserGroups[i] = buildGoogleUserGroups(&m.UserGroups)
						modified = true
						continue outer
					}
				}
				aud.UserGroups = append(aud.UserGroups, buildGoogleUserGroups(&m.UserGroups))
				modified = true
			case hubauth.AudienceMutationOpDeleteUserGroups:
				for i, p := range aud.UserGroups {
					if p.Domain != m.UserGroups.Domain {
						continue
					}
					aud.UserGroups[i] = aud.UserGroups[len(aud.UserGroups)-1]
					aud.UserGroups = aud.UserGroups[:len(aud.UserGroups)-1]
					modified = true
				}
			case hubauth.AudienceMutationSetType:
				if aud.Type == m.Type {
					continue
				}
				aud.Type = m.Type
				modified = true
			case hubauth.AudienceMutationSetPolicy:
				for i, p := range aud.Policies {
					if p.Name == m.Policy.Name {
						aud.Policies[i] = buildBiscuitPolicy(&m.Policy)
						modified = true
						continue outer
					}
				}
				aud.Policies = append(aud.Policies, buildBiscuitPolicy(&m.Policy))
				modified = true
			case hubauth.AudienceMutationDeletePolicy:
				for i, p := range aud.Policies {
					if p.Name != m.Policy.Name {
						continue
					}
					aud.Policies[i] = aud.Policies[len(aud.Policies)-1]
					aud.Policies = aud.Policies[:len(aud.Policies)-1]
					modified = true
				}
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

func (s *service) MutateAudienceUserGroups(ctx context.Context, url string, domain string, mut []*hubauth.AudienceUserGroupsMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateAudienceUserGroups")
	span.AddAttributes(
		trace.StringAttribute("audience_url", url),
		trace.StringAttribute("audience_usergroups_domain", domain),
		trace.Int64Attribute("audience_usergroups_mutation_count", int64(len(mut))),
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

		var userGroups *googleUserGroups
		for i := range aud.UserGroups {
			if aud.UserGroups[i].Domain == domain {
				userGroups = &aud.UserGroups[i]
				break
			}
		}
		if userGroups == nil {
			return hubauth.ErrNotFound
		}

		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.AudienceUserGroupsMutationOpAddGroup:
				var groups []string
				if userGroups.Groups != "" {
					groups = strings.Split(userGroups.Groups, ",")
				}
				for _, g := range groups {
					if g == m.Group {
						continue outer
					}
				}
				userGroups.Groups = strings.Join(append(groups, m.Group), ",")
				modified = true
			case hubauth.AudienceUserGroupsMutationOpDeleteGroup:
				var groups []string
				if userGroups.Groups != "" {
					groups = strings.Split(userGroups.Groups, ",")
				}
				for i, g := range groups {
					if g != m.Group {
						continue
					}
					groups[i] = groups[len(groups)-1]
					groups = groups[:len(groups)-1]
				}
				userGroups.Groups = strings.Join(groups, ",")
				modified = true
			case hubauth.AudienceUserGroupsMutationOpSetAPIUser:
				if userGroups.APIUser == m.APIUser {
					continue
				}
				userGroups.APIUser = m.APIUser
				modified = true
			default:
				return fmt.Errorf("datastore: unknown audience usergroups mutation op %s", m.Op)
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

func (s *service) MutateAudiencePolicy(ctx context.Context, url string, policyName string, mut []*hubauth.AudiencePolicyMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateAudiencePolicy")
	span.AddAttributes(
		trace.StringAttribute("audience_url", url),
		trace.StringAttribute("audience_policy_name", policyName),
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

		var policy *biscuitPolicy
		for i := range aud.Policies {
			if aud.Policies[i].Name == policyName {
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
				var groups []string
				if policy.Groups != "" {
					groups = strings.Split(policy.Groups, ",")
				}
				for _, g := range groups {
					if g == m.Group {
						continue outer
					}
				}
				policy.Groups = strings.Join(append(groups, m.Group), ",")
				modified = true
			case hubauth.AudiencePolicyMutationOpDeleteGroup:
				var groups []string
				if policy.Groups != "" {
					groups = strings.Split(policy.Groups, ",")
				}
				for i, g := range groups {
					if g != m.Group {
						continue
					}
					groups[i] = groups[len(groups)-1]
					groups = groups[:len(groups)-1]
				}
				policy.Groups = strings.Join(groups, ",")
				modified = true
			case hubauth.AudiencePolicyMutationOpSetContent:
				if policy.Content == m.Content {
					continue
				}
				policy.Content = m.Content
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
