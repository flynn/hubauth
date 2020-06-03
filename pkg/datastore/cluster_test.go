package datastore

import (
	"context"
	"testing"
	"time"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors"
)

func TestClusterCRD(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	c := &hubauth.Cluster{
		URL:       "https://controller.example.com",
		ClientIDs: []string{"a"},
		Policies: []*hubauth.GoogleUserPolicy{
			{
				Domain:  "example.com",
				APIUser: "user@example.com",
				Groups:  []string{"admin@example.com"},
			},
		},
	}
	err := s.CreateCluster(ctx, c)
	require.NoError(t, err)

	res, err := s.GetCluster(ctx, c.URL)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), res.CreateTime, time.Second)
	require.Equal(t, res.CreateTime, res.UpdateTime)
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	require.Equal(t, c, res)

	clusters, err := s.ListClusters(ctx)
	require.NoError(t, err)
	for _, res = range clusters {
		if res.URL == c.URL {
			break
		}
	}
	res.CreateTime = time.Time{}
	res.UpdateTime = time.Time{}
	require.Equal(t, c, res)

	err = s.DeleteCluster(ctx, c.URL)
	require.NoError(t, err)

	_, err = s.GetCluster(ctx, c.URL)
	require.Truef(t, errors.Is(err, hubauth.ErrNotFound), "wrong err %v", err)
}
func TestClusterListForClientID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	c1 := &hubauth.Cluster{
		URL:       "https://controller.1.example.com",
		ClientIDs: []string{"a", "b"},
	}
	err := s.CreateCluster(ctx, c1)
	require.NoError(t, err)

	c2 := &hubauth.Cluster{
		URL:       "https://controller.2.example.com",
		ClientIDs: []string{"b", "c"},
	}
	err = s.CreateCluster(ctx, c2)
	require.NoError(t, err)

	clusters, err := s.ListClustersForClient(ctx, "b")
	require.NoError(t, err)
	found1 := false
	found2 := false
	for _, res := range clusters {
		if res.URL == c1.URL {
			found1 = true
		}
		if res.URL == c2.URL {
			found2 = true
		}
	}
	require.Len(t, clusters, 2)
	require.True(t, found1, "didn't find cluster1")
	require.True(t, found2, "didn't find cluster2")

	err = s.DeleteCluster(ctx, c1.URL)
	require.NoError(t, err)
	err = s.DeleteCluster(ctx, c2.URL)
	require.NoError(t, err)

	clusters, err = s.ListClustersForClient(ctx, "b")
	require.NoError(t, err)
	require.Len(t, clusters, 0)
}

func TestClusterMutate(t *testing.T) {
	type test struct {
		desc   string
		mut    []*hubauth.ClusterMutation
		before *hubauth.Cluster
		after  *hubauth.Cluster
	}
	tests := []test{
		{
			desc: "add cluster existing",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpAddClientID, ClientID: "a"},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"a"},
			},
			after: &hubauth.Cluster{
				ClientIDs: []string{"a"},
			},
		},
		{
			desc: "add cluster new empty",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpAddClientID, ClientID: "a"},
			},
			before: &hubauth.Cluster{},
			after: &hubauth.Cluster{
				ClientIDs: []string{"a"},
			},
		},
		{
			desc: "add cluster new others",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpAddClientID, ClientID: "c"},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Cluster{
				ClientIDs: []string{"a", "b", "c"},
			},
		},
		{
			desc: "delete redirect existing",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"a", "c", "b"},
			},
			after: &hubauth.Cluster{
				ClientIDs: []string{"a", "b"},
			},
		},
		{
			desc: "delete redirect only",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"c"},
			},
			after: &hubauth.Cluster{},
		},
		{
			desc: "delete redirect nonexistent",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Cluster{
				ClientIDs: []string{"a", "b"},
			},
		},
		{
			desc: "delete redirect empty",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpDeleteClientID, ClientID: "c"},
			},
			before: &hubauth.Cluster{},
			after:  &hubauth.Cluster{},
		},
		{
			desc: "set policy existing",
			mut: []*hubauth.ClusterMutation{
				{
					Op: hubauth.ClusterMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "set policy new empty",
			mut: []*hubauth.ClusterMutation{
				{
					Op: hubauth.ClusterMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Cluster{},
			after: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "set policy new existing",
			mut: []*hubauth.ClusterMutation{
				{
					Op: hubauth.ClusterMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
				},
			},
			after: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"a", "b"}, APIUser: "foo"},
				},
			},
		},
		{
			desc: "delete policy existing",
			mut: []*hubauth.ClusterMutation{
				{
					Op:     hubauth.ClusterMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "example.com"},
				},
			},
			before: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "a.com", Groups: []string{"foo"}, APIUser: "example"},
				},
			},
		},
		{
			desc: "delete policy only",
			mut: []*hubauth.ClusterMutation{
				{
					Op:     hubauth.ClusterMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "example.com"},
				},
			},
			before: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Cluster{},
		},
		{
			desc: "delete policy nonexistent",
			mut: []*hubauth.ClusterMutation{
				{
					Op:     hubauth.ClusterMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "a.com"},
				},
			},
			before: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
			after: &hubauth.Cluster{
				Policies: []*hubauth.GoogleUserPolicy{
					{Domain: "example.com", Groups: []string{"old"}, APIUser: "other"},
				},
			},
		},
		{
			desc: "delete policy empty",
			mut: []*hubauth.ClusterMutation{
				{
					Op:     hubauth.ClusterMutationOpDeletePolicy,
					Policy: hubauth.GoogleUserPolicy{Domain: "a.com"},
				},
			},
			before: &hubauth.Cluster{},
			after:  &hubauth.Cluster{},
		},
		{
			desc: "multiple",
			mut: []*hubauth.ClusterMutation{
				{Op: hubauth.ClusterMutationOpAddClientID, ClientID: "c"},
				{
					Op: hubauth.ClusterMutationOpSetPolicy,
					Policy: hubauth.GoogleUserPolicy{
						Domain:  "example.com",
						Groups:  []string{"a", "b"},
						APIUser: "foo",
					},
				},
			},
			before: &hubauth.Cluster{
				ClientIDs: []string{"a", "b"},
			},
			after: &hubauth.Cluster{
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
		err := s.CreateCluster(ctx, tt.before)
		require.NoError(t, err, tt.desc)
		before, err := s.GetCluster(ctx, url)
		require.NoError(t, err)

		err = s.MutateCluster(ctx, url, tt.mut)
		require.NoError(t, err, tt.desc)

		res, err := s.GetCluster(ctx, url)
		require.NoError(t, err, tt.desc)
		if len(res.Policies) == 0 {
			res.Policies = nil
		}
		require.Equal(t, before.CreateTime, res.CreateTime)

		res.CreateTime = time.Time{}
		res.UpdateTime = time.Time{}
		require.Equal(t, tt.after, res, tt.desc)

		s.DeleteCluster(ctx, url)
	}
}
