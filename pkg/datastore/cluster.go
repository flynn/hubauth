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

func buildCluster(c *hubauth.Cluster) *cluster {
	now := time.Now()
	policies := make([]googleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = buildGoogleUserPolicy(p)
	}
	return &cluster{
		Key:        clusterKey(c.URL),
		ClientIDs:  c.ClientIDs,
		Policies:   policies,
		CreateTime: now,
		UpdateTime: now,
	}
}

type cluster struct {
	Key        *datastore.Key `datastore:"__key__"`
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

func (c *cluster) Export() *hubauth.Cluster {
	policies := make([]*hubauth.GoogleUserPolicy, len(c.Policies))
	for i, p := range c.Policies {
		policies[i] = &hubauth.GoogleUserPolicy{
			Domain:  p.Domain,
			APIUser: p.APIUser,
			Groups:  strings.Split(p.Groups, ","),
		}
	}
	return &hubauth.Cluster{
		URL:        c.Key.Name,
		ClientIDs:  c.ClientIDs,
		Policies:   policies,
		CreateTime: c.CreateTime,
		UpdateTime: c.UpdateTime,
	}
}

func clusterKey(url string) *datastore.Key {
	return datastore.NameKey(kindCluster, url, nil)
}

func (s *service) GetCluster(ctx context.Context, url string) (*hubauth.Cluster, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.GetCluster")
	span.AddAttributes(trace.StringAttribute("cluster_url", url))
	defer span.End()

	res := &cluster{}
	if err := s.db.Get(ctx, clusterKey(url), res); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = hubauth.ErrNotFound
		}
		return nil, fmt.Errorf("datastore: error fetching cluster %s: %w", url, err)
	}
	return res.Export(), nil
}

func (s *service) CreateCluster(ctx context.Context, cluster *hubauth.Cluster) error {
	ctx, span := trace.StartSpan(ctx, "datastore.CreateCluster")
	span.AddAttributes(trace.StringAttribute("cluster_url", cluster.URL))
	defer span.End()

	c := buildCluster(cluster)
	if _, err := s.db.Put(ctx, c.Key, c); err != nil {
		return fmt.Errorf("datastore: error creating cluster: %w", err)
	}
	return nil
}

func (s *service) MutateCluster(ctx context.Context, url string, mut []*hubauth.ClusterMutation) error {
	ctx, span := trace.StartSpan(ctx, "datastore.MutateCluster")
	span.AddAttributes(
		trace.StringAttribute("cluster_url", url),
		trace.Int64Attribute("cluster_mutation_count", int64(len(mut))),
	)
	defer span.End()

	k := clusterKey(url)
	_, err := s.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		cluster := &cluster{}
		if err := tx.Get(k, cluster); err != nil {
			if err == datastore.ErrNoSuchEntity {
				err = hubauth.ErrNotFound
			}
			return fmt.Errorf("datastore: error fetching cluster %s: %w", url, err)
		}
		modified := false
	outer:
		for _, m := range mut {
			switch m.Op {
			case hubauth.ClusterMutationOpAddClientID:
				for _, id := range cluster.ClientIDs {
					if id == m.ClientID {
						continue outer
					}
				}
				cluster.ClientIDs = append(cluster.ClientIDs, m.ClientID)
				modified = true
			case hubauth.ClusterMutationOpDeleteClientID:
				for i, u := range cluster.ClientIDs {
					if u != m.ClientID {
						continue
					}
					cluster.ClientIDs[i] = cluster.ClientIDs[len(cluster.ClientIDs)-1]
					cluster.ClientIDs = cluster.ClientIDs[:len(cluster.ClientIDs)-1]
					modified = true
				}
			case hubauth.ClusterMutationOpSetPolicy:
				for i, p := range cluster.Policies {
					if p.Domain == m.Policy.Domain {
						cluster.Policies[i] = buildGoogleUserPolicy(&m.Policy)
						modified = true
						continue outer
					}
				}
				cluster.Policies = append(cluster.Policies, buildGoogleUserPolicy(&m.Policy))
				modified = true
			case hubauth.ClusterMutationOpDeletePolicy:
				for i, p := range cluster.Policies {
					if p.Domain != m.Policy.Domain {
						continue
					}
					cluster.Policies[i] = cluster.Policies[len(cluster.Policies)-1]
					cluster.Policies = cluster.Policies[:len(cluster.Policies)-1]
					modified = true
				}
			default:
				return fmt.Errorf("datastore: unknown cluster mutation op %s", m.Op)
			}
		}
		if !modified {
			return nil
		}
		cluster.UpdateTime = time.Now()
		_, err := tx.Put(k, cluster)
		return err
	})
	if err != nil {
		return fmt.Errorf("datastore: error mutating cluster %s: %w", url, err)
	}
	return nil
}

func (s *service) ListClusters(ctx context.Context) ([]*hubauth.Cluster, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListClusters")
	defer span.End()

	var clusters []*cluster
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindCluster), &clusters); err != nil {
		return nil, fmt.Errorf("datastore: error listing clusters: %w", err)
	}
	res := make([]*hubauth.Cluster, len(clusters))
	for i, c := range clusters {
		res[i] = c.Export()
	}
	return res, nil
}

func (s *service) ListClustersForClient(ctx context.Context, clientID string) ([]*hubauth.Cluster, error) {
	ctx, span := trace.StartSpan(ctx, "datastore.ListClustersForClient")
	span.AddAttributes(trace.StringAttribute("client_id", clientID))
	defer span.End()

	var clusters []*cluster
	if _, err := s.db.GetAll(ctx, datastore.NewQuery(kindCluster).Filter("ClientIDs =", clientID), &clusters); err != nil {
		return nil, fmt.Errorf("datastore: error listing clusters for clientID %s: %w", clientID, err)
	}
	res := make([]*hubauth.Cluster, len(clusters))
	for i, c := range clusters {
		res[i] = c.Export()
	}
	span.AddAttributes(trace.Int64Attribute("cluster_count", int64(len(res))))
	return res, nil
}

func (s *service) DeleteCluster(ctx context.Context, url string) error {
	ctx, span := trace.StartSpan(ctx, "datastore.DeleteCluster")
	span.AddAttributes(trace.StringAttribute("cluster_url", url))
	defer span.End()

	if err := s.db.Delete(ctx, clusterKey(url)); err != nil {
		return fmt.Errorf("datastore: error deleting cluster %s: %w", url, err)
	}
	return nil
}
