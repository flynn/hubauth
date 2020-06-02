package datastore

import (
	"context"
	"sort"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"golang.org/x/exp/errors/fmt"
)

type cachedGroup struct {
	Key        *datastore.Key `datastore:"__key__"`
	Email      string
	UpdateTime time.Time
	CreateTime time.Time
}

func (g *cachedGroup) Export() *hubauth.CachedGroup {
	return &hubauth.CachedGroup{
		Domain:     g.Key.Parent.Name,
		GroupID:    g.Key.Name,
		Email:      g.Email,
		UpdateTime: g.UpdateTime,
		CreateTime: g.CreateTime,
	}
}

type cachedGroupMember struct {
	Key        *datastore.Key `datastore:"__key__"`
	UserID     string
	Email      string
	UpdateTime time.Time
	CreateTime time.Time
}

func (s *service) ListCachedGroups(ctx context.Context) ([]*hubauth.CachedGroup, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListCachedGroups")
	defer span.End()

	var data []*cachedGroup
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindCachedGroup), &data); err != nil {
		return nil, fmt.Errorf("datastore: error listing cached groups: %w", err)
	}
	res := make([]*hubauth.CachedGroup, len(data))
	for i, g := range data {
		res[i] = g.Export()
	}
	return res, nil
}

func (s *service) SetCachedGroup(ctx context.Context, group *hubauth.CachedGroup, members []*hubauth.CachedGroupMember) (*hubauth.SetCachedGroupResult, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.SetCachedGroup")
	span.AddAttributes(
		trace.StringAttribute("group_id", group.GroupID),
		trace.StringAttribute("group_domain", group.Domain),
		trace.StringAttribute("group_email", group.Email),
		trace.Int64Attribute("group_member_count", int64(len(members))),
	)
	defer span.End()

	if len(members) > 249 {
		return nil, fmt.Errorf("datastore: groups must not have more than 249 members")
	}
	k := datastore.NameKey(kindCachedGroup, group.GroupID, datastore.NameKey(kindDomain, group.Domain, nil))
	newSet := make(map[string]*hubauth.CachedGroupMember, len(members))
	for _, m := range members {
		newSet[m.UserID] = m
	}
	var res *hubauth.SetCachedGroupResult

	_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		res = &hubauth.SetCachedGroupResult{}
		existingGroup := &cachedGroup{}
		if err := tx.Get(k, existingGroup); err != nil && err != datastore.ErrNoSuchEntity {
			return fmt.Errorf("failed to get existing cached group: %w", err)
		}
		var existingMembers []*cachedGroupMember
		if existingGroup != nil {
			q := datastore.NewQuery(kindCachedGroupMember).Ancestor(k).Transaction(tx)
			if _, err := s.db.GetAll(ctx, q, &existingMembers); err != nil {
				return fmt.Errorf("failed to get existing members: %w", err)
			}
		}

		existingSet := make(map[string]struct{}, len(existingMembers))
		now := time.Now()
		for _, m := range existingMembers {
			newData, ok := newSet[m.UserID]
			if !ok {
				if err := tx.Delete(m.Key); err != nil {
					return fmt.Errorf("failed to delete member %s: %w", m.Key.Encode(), err)
				}
				res.DeletedMembers = append(res.DeletedMembers, m.Email)
				continue
			}
			if newData.Email != m.Email {
				m.Email = newData.Email
				m.UpdateTime = now
				if _, err := tx.Put(m.Key, m); err != nil {
					return fmt.Errorf("failed to put update member %s: %w", m.Key.Encode(), err)
				}
				res.UpdatedMembers = append(res.UpdatedMembers, m.Email)
			}
			existingSet[m.UserID] = struct{}{}
		}
		for _, m := range newSet {
			_, exists := existingSet[m.UserID]
			if exists {
				continue
			}
			memberKey := datastore.NameKey(kindCachedGroupMember, m.UserID, k)
			_, err := tx.Put(
				memberKey,
				&cachedGroupMember{
					UserID:     m.UserID,
					Email:      m.Email,
					CreateTime: now,
					UpdateTime: now,
				},
			)
			if err != nil {
				return fmt.Errorf("failed to put create member %s: %w", memberKey.Encode(), err)
			}
			res.AddedMembers = append(res.AddedMembers, m.Email)
		}

		if existingGroup.Email != group.Email {
			existingGroup.Email = group.Email
			existingGroup.UpdateTime = now
			if existingGroup.CreateTime.IsZero() {
				existingGroup.CreateTime = now
			}
			if _, err := tx.Put(k, existingGroup); err != nil {
				return fmt.Errorf("failed to put group %s: %w", k.Encode(), err)
			}
			res.UpdatedGroup = true
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("datastore: error setting cached group %s (%s) for domain %s: %w", group.Email, group.GroupID, group.Domain, err)
	}
	sort.Strings(res.AddedMembers)
	sort.Strings(res.DeletedMembers)
	sort.Strings(res.UpdatedMembers)
	span.AddAttributes(
		trace.Int64Attribute("group_members_added", int64(len(res.AddedMembers))),
		trace.Int64Attribute("group_members_deleted", int64(len(res.DeletedMembers))),
		trace.Int64Attribute("group_members_updated", int64(len(res.UpdatedMembers))),
		trace.BoolAttribute("group_updated", res.UpdatedGroup),
	)
	return res, nil
}

func (s *service) GetCachedMemberGroups(ctx context.Context, userID string) ([]string, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetCachedMemberGroups")
	span.AddAttributes(trace.StringAttribute("user_id", userID))
	defer span.End()

	keys, err := s.db.GetAll(
		ctx,
		datastore.NewQuery(kindCachedGroupMember).KeysOnly().Filter("UserID =", userID),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("datastore: error getting groups for user %s: %w", userID, err)
	}
	res := make([]string, len(keys))
	for i, k := range keys {
		res[i] = k.Parent.Name
	}
	span.AddAttributes(trace.Int64Attribute("group_count", int64(len(res))))
	return res, nil
}

func (s *service) DeleteCachedGroup(ctx context.Context, domain, groupID string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteCachedGroup")
	span.AddAttributes(
		trace.StringAttribute("group_id", groupID),
		trace.StringAttribute("group_domain", domain),
	)
	defer span.End()

	k := datastore.NameKey(kindCachedGroup, groupID, datastore.NameKey(kindDomain, domain, nil))
	q := datastore.NewQuery(kindCachedGroupMember).Ancestor(k).KeysOnly()
	_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		keys, err := s.db.GetAll(ctx, q.Transaction(tx), nil)
		if err != nil {
			return err
		}
		if err := tx.DeleteMulti(keys); err != nil {
			return err
		}
		return tx.Delete(k)
	})
	if err != nil {
		return fmt.Errorf("datastore: error deleting cached group %s in domain %s: %w", groupID, domain, err)
	}
	return nil
}
