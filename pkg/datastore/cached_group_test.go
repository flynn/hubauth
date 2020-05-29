package datastore

import (
	"context"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/require"
)

func TestCachedGroupCRD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	cg := &hubauth.CachedGroup{
		Domain:  "example.com",
		GroupID: "123",
		Email:   "g@example.com",
	}
	members := []*hubauth.CachedGroupMember{
		{
			UserID: "444",
			Email:  "u1@example.com",
		},
		{
			UserID: "443",
			Email:  "u2@example.com",
		},
	}

	res, err := s.SetCachedGroup(ctx, cg, members)
	require.NoError(t, err)
	require.True(t, res.UpdatedGroup)
	require.Len(t, res.AddedMembers, 2)
	require.Len(t, res.UpdatedMembers, 0)
	require.Len(t, res.DeletedMembers, 0)

	gs, err := s.ListCachedGroups(ctx)
	require.NoError(t, err)
	var readGroup *hubauth.CachedGroup
	for _, g := range gs {
		if g.Domain == cg.Domain && g.GroupID == cg.GroupID {
			readGroup = g
			break
		}
	}
	require.NotNil(t, readGroup)
	require.WithinDuration(t, time.Now(), readGroup.CreateTime, time.Second)
	require.Equal(t, readGroup.CreateTime, readGroup.UpdateTime)
	readGroup.CreateTime = time.Time{}
	readGroup.UpdateTime = time.Time{}
	require.Equal(t, cg, readGroup)

	for _, id := range []string{"444", "443"} {
		ids, err := s.GetCachedMemberGroups(ctx, id)
		require.NoError(t, err)
		require.Len(t, ids, 1)
		require.Equal(t, cg.GroupID, ids[0])
	}

	err = s.DeleteCachedGroup(ctx, cg.Domain, cg.GroupID)
	require.NoError(t, err)

	gs, err = s.ListCachedGroups(ctx)
	require.NoError(t, err)
	var found bool
	for _, g := range gs {
		if g.Domain == cg.Domain && g.GroupID == cg.GroupID {
			found = true
			break
		}
	}
	require.False(t, found)

	for _, id := range []string{"444", "443"} {
		ids, err := s.GetCachedMemberGroups(ctx, id)
		require.NoError(t, err)
		require.Len(t, ids, 0)
	}
}

func TestCachedGroupUpdate(t *testing.T) {
	type test struct {
		desc          string
		beforeGroup   *hubauth.CachedGroup
		beforeMembers []*hubauth.CachedGroupMember
		newGroup      *hubauth.CachedGroup
		newMembers    []*hubauth.CachedGroupMember
		result        *hubauth.SetCachedGroupResult
	}

	tests := []test{
		{
			desc: "no updates",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			newMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
		},
		{
			desc: "replace all",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			newMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "c",
					Email:  "c@example.com",
				},
				{
					UserID: "d",
					Email:  "d@example.com",
				},
			},
			result: &hubauth.SetCachedGroupResult{
				AddedMembers:   []string{"c", "d"},
				DeletedMembers: []string{"a", "b"},
			},
		},
		{
			desc: "add one",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			newMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
				{
					UserID: "c",
					Email:  "c@example.com",
				},
			},
			result: &hubauth.SetCachedGroupResult{AddedMembers: []string{"c"}},
		},
		{
			desc: "update one",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			newMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "aasdf@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			result: &hubauth.SetCachedGroupResult{UpdatedMembers: []string{"a"}},
		},
		{
			desc: "delete one",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			newMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
			},
			result: &hubauth.SetCachedGroupResult{DeletedMembers: []string{"b"}},
		},
		{
			desc: "delete all",
			beforeGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			beforeMembers: []*hubauth.CachedGroupMember{
				{
					UserID: "a",
					Email:  "a@example.com",
				},
				{
					UserID: "b",
					Email:  "b@example.com",
				},
			},
			newGroup: &hubauth.CachedGroup{
				Domain:  "example.com",
				GroupID: "testupdate",
				Email:   "testupdate@example.com",
			},
			result: &hubauth.SetCachedGroupResult{DeletedMembers: []string{"a", "b"}},
		},
		// delete/add/update/update group
	}

	s := newTestService(t)
	ctx := context.Background()

	for _, tt := range tests {
		_, err := s.SetCachedGroup(ctx, tt.beforeGroup, tt.beforeMembers)
		require.NoError(t, err, tt.desc)

		res, err := s.SetCachedGroup(ctx, tt.newGroup, tt.newMembers)
		require.NoError(t, err, tt.desc)

		if tt.result == nil {
			tt.result = &hubauth.SetCachedGroupResult{}
		}
		require.Equal(t, tt.result, res, tt.desc)

		gs, err := s.ListCachedGroups(ctx)
		require.NoError(t, err, tt.desc)
		var listGroup *hubauth.CachedGroup
		for _, g := range gs {
			if g.Domain == tt.newGroup.Domain && g.GroupID == tt.newGroup.GroupID {
				listGroup = g
				break
			}
		}
		require.WithinDuration(t, time.Now(), listGroup.CreateTime, time.Second, tt.desc)
		require.WithinDuration(t, time.Now(), listGroup.UpdateTime, time.Second, tt.desc)

		for _, m := range tt.newMembers {
			gs, err := s.GetCachedMemberGroups(ctx, m.UserID)
			require.NoError(t, err, tt.desc)
			require.Len(t, gs, 1, tt.desc)
			require.Equal(t, gs[0], tt.newGroup.GroupID, tt.desc)
		}

		for _, m := range tt.result.DeletedMembers {
			gs, err := s.GetCachedMemberGroups(ctx, m)
			require.NoError(t, err, tt.desc)
			require.Len(t, gs, 0, tt.desc)
		}

		err = s.DeleteCachedGroup(ctx, tt.newGroup.Domain, tt.newGroup.GroupID)
		require.NoError(t, err, tt.desc)
	}
}

func TestCachedGroupMultiGroupMember(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	cg1 := &hubauth.CachedGroup{
		Domain:  "example.com",
		GroupID: "1",
		Email:   "g1@example.com",
	}
	cg2 := &hubauth.CachedGroup{
		Domain:  "example.com",
		GroupID: "2",
		Email:   "g2@example.com",
	}
	members := []*hubauth.CachedGroupMember{
		{
			UserID: "u1",
			Email:  "u1@example.com",
		},
	}

	_, err := s.SetCachedGroup(ctx, cg1, members)
	require.NoError(t, err)

	_, err = s.SetCachedGroup(ctx, cg2, members)
	require.NoError(t, err)

	res, err := s.GetCachedMemberGroups(ctx, members[0].UserID)
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, res, []string{cg1.GroupID, cg2.GroupID})

	err = s.DeleteCachedGroup(ctx, cg1.Domain, cg1.GroupID)
	require.NoError(t, err)
	err = s.DeleteCachedGroup(ctx, cg2.Domain, cg2.GroupID)
	require.NoError(t, err)

	res, err = s.GetCachedMemberGroups(ctx, members[0].UserID)
	require.NoError(t, err)
	require.Len(t, res, 0)
}
