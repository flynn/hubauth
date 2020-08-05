package groupsync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	gdatastore "cloud.google.com/go/datastore"
	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admin "google.golang.org/api/admin/directory/v1"
)

type mockACF struct {
	mock.Mock
}

var _ adminClientFactory = (*mockACF)(nil)

func (m *mockACF) NewAdminClient(ctx context.Context, tp TargetPrincipal, subject, domain string) (adminClient, error) {
	args := m.Called(ctx, tp, subject, domain)
	return args.Get(0).(adminClient), args.Error(1)
}
func (m *mockACF) FetchTargetPrincipal() (TargetPrincipal, error) {
	args := m.Called()
	return args.Get(0).(TargetPrincipal), args.Error(1)
}

type mockAC struct {
	mock.Mock
}

func (m *mockAC) GetGroup(ctx context.Context, key string) (*admin.Group, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*admin.Group), args.Error(1)
}
func (m *mockAC) GetGroupMembers(ctx context.Context, key string, pageToken string) (*admin.Members, error) {
	args := m.Called(ctx, key, pageToken)
	return args.Get(0).(*admin.Members), args.Error(1)
}

func newTestGroupSyncService(t *testing.T) *Service {
	// randomize db project to ensure starting from a fresh empty project
	randomProject := make([]byte, 16)
	_, err := rand.Read(randomProject)
	require.NoError(t, err)

	dsc, err := gdatastore.NewClient(context.Background(), hex.EncodeToString(randomProject))
	require.NoError(t, err)
	db := datastore.New(dsc)

	s := New(db, &clog.ErrInfo{})
	s.acf = &mockACF{}

	return s
}

func TestGroupSync(t *testing.T) {
	srv := newTestGroupSyncService(t)

	tp := TargetPrincipal("targetPrincipal")

	apiUser := "apiUser"

	domain1 := "domain1"
	domain2 := "domain2"
	domain3 := "domain3"

	group1 := "group1"
	group2 := "group2"
	group3 := "group3"

	err := srv.db.CreateAudience(context.Background(), &hubauth.Audience{
		Name: "audience1",
		URL:  "audience1",
		Policies: []*hubauth.GoogleUserPolicy{
			{
				APIUser: apiUser,
				Domain:  domain1,
				Groups:  []string{group1},
			},
			{
				APIUser: apiUser,
				Domain:  domain2,
				Groups:  []string{group2, group3},
			},
			{
				APIUser: apiUser,
				Domain:  domain3,
				Groups:  []string{},
			},
		},
	})
	require.NoError(t, err)

	adminGroup1 := &admin.Group{Id: group1, Email: group1}
	adminGroup2 := &admin.Group{Id: group2, Email: group2}
	adminGroup3 := &admin.Group{Id: group3, Email: group3}

	member1 := &admin.Member{Id: "member1", Email: "member1", Status: "ACTIVE"}
	member2 := &admin.Member{Id: "member2", Email: "member2", Status: "ACTIVE"}
	member3 := &admin.Member{Id: "member3", Email: "member3", Status: "ACTIVE"}
	member4 := &admin.Member{Id: "member4", Email: "member4", Status: "INACTIVE"}

	members1 := &admin.Members{Members: []*admin.Member{member1, member4}}
	members2 := &admin.Members{Members: []*admin.Member{member1}}
	members3 := &admin.Members{Members: []*admin.Member{member2, member3}}

	ac1 := &mockAC{}
	ac1.On("GetGroup", mock.Anything, group1).Return(adminGroup1, nil)
	ac1.On("GetGroupMembers", mock.Anything, group1, "").Return(members1, nil)

	ac2 := &mockAC{}
	ac2.On("GetGroup", mock.Anything, group2).Return(adminGroup2, nil)
	ac2.On("GetGroupMembers", mock.Anything, group2, "").Return(members2, nil)
	ac2.On("GetGroup", mock.Anything, group3).Return(adminGroup3, nil)
	ac2.On("GetGroupMembers", mock.Anything, group3, "").Return(members3, nil)

	srv.acf.(*mockACF).On("FetchTargetPrincipal").Return(tp, nil)
	srv.acf.(*mockACF).On("NewAdminClient", mock.Anything, tp, apiUser, domain1).Return(ac1, nil)
	srv.acf.(*mockACF).On("NewAdminClient", mock.Anything, tp, apiUser, domain2).Return(ac2, nil)

	assertMembersGroups(t, srv.db, map[string][]string{
		member1.Id: {},
		member2.Id: {},
		member3.Id: {},
		member4.Id: {},
	})

	// Sync creates groups with expected members
	require.NoError(t, srv.Sync(context.Background()))

	assertMembersGroups(t, srv.db, map[string][]string{
		member1.Id: {group1, group2},
		member2.Id: {group3},
		member3.Id: {group3},
		member4.Id: {},
	})

	members2.Members = []*admin.Member{member2}
	members3.Members = []*admin.Member{member3}
	member4.Status = "ACTIVE"

	adminGroup1.Email = "newEmail"

	// Sync updates existing groups and their members
	require.NoError(t, srv.Sync(context.Background()))

	expectedCachedGroups := map[string]*hubauth.CachedGroup{
		adminGroup1.Id: {
			Domain:  domain1,
			GroupID: adminGroup1.Id,
			Email:   adminGroup1.Email,
		},
		adminGroup2.Id: {
			Domain:  domain2,
			GroupID: adminGroup2.Id,
			Email:   adminGroup2.Email,
		},
		adminGroup3.Id: {
			Domain:  domain2,
			GroupID: adminGroup3.Id,
			Email:   adminGroup3.Email,
		},
	}
	expectedMembersGroups := map[string][]string{
		member1.Id: {group1},
		member2.Id: {group2},
		member3.Id: {group3},
		member4.Id: {group1},
	}

	assertCachedGroups(t, srv.db, expectedCachedGroups)
	assertMembersGroups(t, srv.db, expectedMembersGroups)

	// Sync does nothing when nothing changed
	require.NoError(t, srv.Sync(context.Background()))

	assertCachedGroups(t, srv.db, expectedCachedGroups)
	assertMembersGroups(t, srv.db, expectedMembersGroups)
}

func assertMembersGroups(t *testing.T, db hubauth.DataStore, membersGroups map[string][]string) {
	for memberID, expectedGroups := range membersGroups {
		g, err := db.GetCachedMemberGroups(context.Background(), memberID)
		require.NoError(t, err)
		require.Equal(t, expectedGroups, g)
	}
}

func assertCachedGroups(t *testing.T, db hubauth.DataStore, expectedGroups map[string]*hubauth.CachedGroup) {
	cachedGroups, err := db.ListCachedGroups(context.Background())
	require.NoError(t, err)

	require.Equal(t, len(expectedGroups), len(cachedGroups))
	for _, cg := range cachedGroups {
		eg, ok := expectedGroups[cg.GroupID]
		require.True(t, ok)

		require.Equal(t, eg.Domain, cg.Domain)
		require.Equal(t, eg.GroupID, cg.GroupID)
		require.Equal(t, eg.Email, cg.Email)
	}
}
