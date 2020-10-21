package datastore

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors"
)

func TestAudienceCRD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	a := &hubauth.Audience{
		URL:       "https://controller.example.com",
		Name:      "Test Cluster",
		Type:      "flynn_controller",
		ClientIDs: []string{"a"},
		Policies: []*hubauth.GoogleUserPolicy{
			{
				Domain:  "example.com",
				APIUser: "user@example.com",
				Groups:  []string{"admin@example.com"},
			},
		},
	}
	err := s.CreateAudience(ctx, a)
	require.NoError(t, err)

	res, err := s.GetAudience(ctx, a.URL)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	require.Equal(t, res.CreateTime, res.UpdateTime)
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	require.Equal(t, a, res)

	audiences, err := s.ListAudiences(ctx)
	require.NoError(t, err)
	for _, res = range audiences {
		if res.URL == a.URL {
			break
		}
	}
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	require.Equal(t, a, res)

	err = s.DeleteAudience(ctx, a.URL)
	require.NoError(t, err)

	_, err = s.GetAudience(ctx, a.URL)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}

func TestAudienceEmptyGroups(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	a := &hubauth.Audience{
		URL:       "https://controller.nogrp.example.com",
		Name:      "Test Cluster",
		Type:      "flynn_controller",
		ClientIDs: []string{"a"},
		Policies: []*hubauth.GoogleUserPolicy{
			{
				Domain:  "example.com",
				APIUser: "user@example.com",
				Groups:  []string{},
			},
		},
	}
	err := s.CreateAudience(ctx, a)
	require.NoError(t, err)

	got, err := s.GetAudience(ctx, a.URL)
	require.NoError(t, err)
	require.Equal(t, 0, len(got.Policies[0].Groups))
}

func TestAudienceListForClientID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	a1 := &hubauth.Audience{
		URL:       "https://controller.1.example.com",
		ClientIDs: []string{"a", "b"},
	}
	err := s.CreateAudience(ctx, a1)
	require.NoError(t, err)

	a2 := &hubauth.Audience{
		URL:       "https://controller.2.example.com",
		ClientIDs: []string{"b", "c"},
	}
	err = s.CreateAudience(ctx, a2)
	require.NoError(t, err)

	audiences, err := s.ListAudiencesForClient(ctx, "b")
	require.NoError(t, err)
	found1 := false
	found2 := false
	for _, res := range audiences {
		if res.URL == a1.URL {
			found1 = true
		}
		if res.URL == a2.URL {
			found2 = true
		}
	}
	require.Len(t, audiences, 2)
	require.True(t, found1, "didn't find audience1")
	require.True(t, found2, "didn't find audience2")

	err = s.DeleteAudience(ctx, a1.URL)
	require.NoError(t, err)
	err = s.DeleteAudience(ctx, a2.URL)
	require.NoError(t, err)

	audiences, err = s.ListAudiencesForClient(ctx, "b")
	require.NoError(t, err)
	require.Len(t, audiences, 0)
}

func TestAudienceMutate(t *testing.T) {
	type test struct {
		desc   string
		mut    []*hubauth.AudienceMutation
		before *hubauth.Audience
		after  *hubauth.Audience
	}
	tests := []test{
		{
			desc: "add audience existing",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpAddClientID, ClientID: "a"},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"a"},
			},
			after: &hubauth.Audience{
				ClientIDs: []string{"a"},
			},
		},
		{
			desc: "add audience new empty",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpAddClientID, ClientID: "a"},
			},
			before: &hubauth.Audience{},
			after: &hubauth.Audience{
				ClientIDs: []string{"a"},
			},
		},
		{
			desc: "add audience new others",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpAddClientID, ClientID: "c"},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Audience{
				ClientIDs: []string{"a", "b", "c"},
			},
		},
		{
			desc: "delete redirect existing",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"a", "c", "b"},
			},
			after: &hubauth.Audience{
				ClientIDs: []string{"a", "b"},
			},
		},
		{
			desc: "delete redirect only",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"c"},
			},
			after: &hubauth.Audience{},
		},
		{
			desc: "delete redirect nonexistent",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Audience{
				ClientIDs: []string{"a", "b"},
			},
		},
		{
			desc: "delete redirect empty",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Audience{},
			after:  &hubauth.Audience{},
		},
		{
			desc: "set policy existing",
			mut: []*hubauth.AudienceMutation{
				{
					Op: hubauth.AudienceMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "set policy new empty",
			mut: []*hubauth.AudienceMutation{
				{
					Op: hubauth.AudienceMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Audience{},
			after: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "set policy new existing",
			mut: []*hubauth.AudienceMutation{
				{
					Op: hubauth.AudienceMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
				},
			},
			after: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "delete policy existing",
			mut: []*hubauth.AudienceMutation{
				{
					Op:     hubauth.AudienceMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "example.com"},
				},
			},
			before: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
				},
			},
		},
		{
			desc: "delete policy only",
			mut: []*hubauth.AudienceMutation{
				{
					Op:     hubauth.AudienceMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "example.com"},
				},
			},
			before: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Audience{},
		},
		{
			desc: "delete policy nonexistent",
			mut: []*hubauth.AudienceMutation{
				{
					Op:     hubauth.AudienceMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "a.com"},
				},
			},
			before: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Audience{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
		},
		{
			desc: "delete policy empty",
			mut: []*hubauth.AudienceMutation{
				{
					Op:     hubauth.AudienceMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "a.com"},
				},
			},
			before: &hubauth.Audience{},
			after:  &hubauth.Audience{},
		},
		{
			desc: "multiple",
			mut: []*hubauth.AudienceMutation{
				{Op: hubauth.AudienceMutationOpAddClientID, ClientID: "c"},
				{
					Op: hubauth.AudienceMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Audience{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Audience{
				ClientIDs: []string{"a", "b", "c"},
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
	}

	s := newTestService(t)
	ctx := context.Background()
	url := "https://cluster.mutate.example.com"
	for _, tt := range tests {
		tt.before.URL = url
		tt.after.URL = url
		err := s.CreateAudience(ctx, tt.before)
		require.NoError(t, err, tt.desc)
		before, err := s.GetAudience(ctx, url)
		require.NoError(t, err)

		err = s.MutateAudience(ctx, url, tt.mut)
		require.NoError(t, err, tt.desc)

		res, err := s.GetAudience(ctx, url)
		require.NoError(t, err, tt.desc)
		if len(res.Policies) == 0 {
			res.Policies = nil
		}
		require.Equal(t, before.CreateTime, res.CreateTime)

		res.CreateTime = time.Time{}
		res.UpdateTime = time.Time{}
		require.Equal(t, tt.after, res, tt.desc)

		s.DeleteAudience(ctx, url)
	}
}

func TestMutateAudiencePolicy(t *testing.T) {
	domain := "policy.domain"

	type test struct {
		desc   string
		mut    []*hubauth.AudiencePolicyMutation
		before []*hubauth.GoogleUserPolicy
		after  []*hubauth.GoogleUserPolicy
	}
	tests := []test{
		{
			desc: "new api user",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:      hubauth.AudiencePolicyMutationOpSetAPIUser,
					APIUser: "user2",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user2", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
		{
			desc: "same api user",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:      hubauth.AudiencePolicyMutationOpSetAPIUser,
					APIUser: "user1",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
		{
			desc: "add groups",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:    hubauth.AudiencePolicyMutationOpAddGroup,
					Group: "added-1",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpAddGroup,
					Group: "added-2",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpAddGroup,
					Group: "grp2",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2", "added-1", "added-2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
		{
			desc: "delete groups",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
					Group: "grp1",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
					Group: "grp2",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2", "grp3"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp3"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
		{
			desc: "delete all groups",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
					Group: "grp1",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
					Group: "grp2",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: nil},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
		{
			desc: "multiple",
			mut: []*hubauth.AudiencePolicyMutation{
				{
					Op:    hubauth.AudiencePolicyMutationOpAddGroup,
					Group: "added-1",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpAddGroup,
					Group: "added-2",
				},
				{
					Op:    hubauth.AudiencePolicyMutationOpDeleteGroup,
					Group: "grp1",
				},
				{
					Op:      hubauth.AudiencePolicyMutationOpSetAPIUser,
					APIUser: "new-user",
				},
			},
			before: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "user1", Groups: []string{"grp1", "grp2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
			after: []*hubauth.GoogleUserPolicy{
				{Domain: domain, APIUser: "new-user", Groups: []string{"grp2", "added-1", "added-2"}},
				{Domain: "other", APIUser: "user1", Groups: []string{"grp1", "grp2"}},
			},
		},
	}

	s := newTestService(t)
	ctx := context.Background()
	for _, tt := range tests {
		aud := &hubauth.Audience{
			URL:      "https://cluster.mutate.example.com",
			Policies: tt.before,
		}

		err := s.CreateAudience(ctx, aud)
		require.NoError(t, err, tt.desc)
		before, err := s.GetAudience(ctx, aud.URL)
		require.NoError(t, err)

		err = s.MutateAudiencePolicy(ctx, aud.URL, domain, tt.mut)
		require.NoError(t, err, tt.desc)

		res, err := s.GetAudience(ctx, aud.URL)
		require.NoError(t, err, tt.desc)
		if len(res.Policies) == 0 {
			res.Policies = nil
		}
		require.Equal(t, before.CreateTime, res.CreateTime)

		// sort to ensure consistent slice comparison
		for _, p := range res.Policies {
			sort.Strings(p.Groups)
		}
		for _, p := range tt.after {
			sort.Strings(p.Groups)
		}

		require.Equal(t, tt.after, res.Policies, tt.desc)

		s.DeleteAudience(ctx, aud.URL)
	}
}
