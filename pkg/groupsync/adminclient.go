package groupsync

import (
	"context"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/flynn/hubauth/pkg/impersonate"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

type adminClient interface {
	GetGroup(ctx context.Context, key string) (*admin.Group, error)
	GetGroupMembers(ctx context.Context, key string, pageToken string) (*admin.Members, error)
}

type TargetPrincipal string

type adminClientFactory interface {
	NewAdminClient(ctx context.Context, tp TargetPrincipal, subject, domain string) (adminClient, error)
	FetchTargetPrincipal() (TargetPrincipal, error)
}

type googleAdminClientFactory struct {
	tokenSource oauth2.TokenSource

	mtx          sync.Mutex
	adminClients map[string]adminClient
}

var _ adminClientFactory = (*googleAdminClientFactory)(nil)

func newAdminClientFactory() adminClientFactory {
	return &googleAdminClientFactory{
		tokenSource:  google.ComputeTokenSource("", "https://www.googleapis.com/auth/iam"),
		adminClients: make(map[string]adminClient),
	}
}

func (acf *googleAdminClientFactory) NewAdminClient(ctx context.Context, tp TargetPrincipal, subject, domain string) (adminClient, error) {
	acf.mtx.Lock()
	defer acf.mtx.Unlock()

	client, ok := acf.adminClients[domain]
	if !ok {
		ts, err := impersonate.TokenSource(ctx, &impersonate.TokenConfig{
			TokenSource:     acf.tokenSource,
			TargetPrincipal: string(tp),
			Lifetime:        3600 * time.Second,
			TargetScopes:    []string{"https://www.googleapis.com/auth/admin.directory.group.readonly"},
			Subject:         subject,
		})
		if err != nil {
			return nil, err
		}

		ac, err := admin.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return nil, err
		}

		client = &googleAdminClient{ac}
		acf.adminClients[domain] = client
	}

	return client, nil
}

func (acf *googleAdminClientFactory) FetchTargetPrincipal() (TargetPrincipal, error) {
	email, err := metadata.Email("")
	if err != nil {
		return "", err
	}

	return TargetPrincipal(email), nil
}

type googleAdminClient struct {
	*admin.Service
}

var _ adminClient = (*googleAdminClient)(nil)

func (ac *googleAdminClient) GetGroup(ctx context.Context, key string) (*admin.Group, error) {
	return ac.Service.Groups.Get(key).Context(ctx).Do()
}

func (ac *googleAdminClient) GetGroupMembers(ctx context.Context, key string, pageToken string) (*admin.Members, error) {
	req := ac.Service.Members.List(key).Context(ctx)
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}

	return req.Do()
}
