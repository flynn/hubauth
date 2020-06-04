package groupsync

import (
	"context"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/impersonate"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"golang.org/x/exp/errors/fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

func New(db hubauth.DataStore, errInfo *clog.ErrInfo) *Service {
	return &Service{
		db:           db,
		errInfo:      errInfo,
		adminClients: make(map[string]*admin.Service),
	}
}

type Service struct {
	db hubauth.DataStore

	errInfo *clog.ErrInfo

	mtx          sync.Mutex
	adminClients map[string]*admin.Service
}

type domainGroup struct {
	Domain string
	Group  string
}

func (s *Service) reportError(l *zap.Logger, err error) {
	if l == nil {
		l = clog.Logger
	}
	clog.ErrorWithLogger(l, err, s.errInfo)
}

func (s *Service) Sync(ctx context.Context) error {
	ctx, span := trace.StartSpan(ctx, "groupsync.Sync")
	defer span.End()

	clusters, err := s.db.ListClusters(ctx)
	if err != nil {
		return fmt.Errorf("groupsync: error listing clients: %w", err)
	}

	groups := make(map[domainGroup]string)
	for _, c := range clusters {
		for _, p := range c.Policies {
			if p.APIUser == "" || p.Domain == "" || len(p.Groups) == 0 {
				continue
			}
			for _, g := range p.Groups {
				groups[domainGroup{p.Domain, g}] = p.APIUser
			}
		}
	}

	if len(groups) == 0 {
		return nil
	}

	serviceAccountToken := google.ComputeTokenSource("", "https://www.googleapis.com/auth/iam")
	serviceAccountEmail, err := metadata.Email("")
	if err != nil {
		return fmt.Errorf("groupsync: error retrieving service account email: %w", err)
	}

	l := clog.Logger.With(zap.String("service_account", serviceAccountEmail))
	l.Info("starting sync", zap.Int("group_count", len(groups)))
	var failed int
	for g, apiUser := range groups {
		func() {
			l := l.With(
				zap.String("api_user", apiUser),
				zap.String("domain", g.Domain),
				zap.String("group", g.Group),
			)
			ctx, span := trace.StartSpan(ctx, "groupsync.SyncGroup")
			span.AddAttributes(
				trace.StringAttribute("domain", g.Domain),
				trace.StringAttribute("group", g.Group),
			)
			defer span.End()

			s.mtx.Lock()
			ac, ok := s.adminClients[g.Domain]
			if !ok {
				ac, err = newAdminClient(context.Background(), apiUser, serviceAccountEmail, serviceAccountToken)
				if err != nil {
					s.mtx.Unlock()
					s.reportError(l, err)
					failed++
					return
				}
				s.adminClients[g.Domain] = ac
			}
			s.mtx.Unlock()

			group, err := ac.Groups.Get(g.Group).Context(ctx).Do()
			if err != nil {
				s.reportError(l, err)
				failed++
				return
			}

			var members []*admin.Member
			var pageToken string
			for {
				req := ac.Members.List(g.Group).Context(ctx)
				if pageToken != "" {
					req = req.PageToken(pageToken)
				}
				res, err := req.Do()
				if err != nil {
					s.reportError(l, err)
					failed++
					return
				}
				members = append(members, res.Members...)
				pageToken = res.NextPageToken
				if pageToken == "" {
					break
				}
			}

			cachedMembers := make([]*hubauth.CachedGroupMember, 0, len(members))
			memberEmails := make([]string, 0, len(members))
			for _, m := range members {
				if m.Status != "ACTIVE" {
					continue
				}
				cachedMembers = append(cachedMembers, &hubauth.CachedGroupMember{
					UserID: m.Id,
					Email:  m.Email,
				})
				memberEmails = append(memberEmails, m.Email)
			}

			res, err := s.db.SetCachedGroup(ctx, &hubauth.CachedGroup{
				Domain:  g.Domain,
				GroupID: group.Id,
				Email:   group.Email,
			}, cachedMembers)
			if err != nil {
				s.reportError(l, err)
				failed++
				return
			}
			l.Info("synced group",
				zap.Strings("added_members", res.AddedMembers),
				zap.Strings("deleted_members", res.DeletedMembers),
				zap.Strings("updated_members", res.UpdatedMembers),
				zap.Strings("member_list", memberEmails),
				zap.Bool("updated_group", res.UpdatedGroup),
			)
		}()
	}
	l.Info("finished sync", zap.Int("group_count", len(groups)), zap.Int("group_sync_failures", failed))
	return nil
}

func newAdminClient(ctx context.Context, subject, targetPrincipal string, rootToken oauth2.TokenSource) (*admin.Service, error) {
	ts, err := impersonate.TokenSource(ctx, &impersonate.TokenConfig{
		TokenSource:     rootToken,
		TargetPrincipal: targetPrincipal,
		Lifetime:        3600 * time.Second,
		TargetScopes:    []string{"https://www.googleapis.com/auth/admin.directory.group.readonly"},
		Subject:         subject,
	})
	if err != nil {
		return nil, err
	}
	return admin.NewService(ctx, option.WithTokenSource(ts))
}
