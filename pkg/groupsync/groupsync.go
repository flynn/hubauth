package groupsync

import (
	"context"

	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/hubauth"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"golang.org/x/exp/errors/fmt"
	admin "google.golang.org/api/admin/directory/v1"
)

func New(db hubauth.DataStore, errInfo *clog.ErrInfo) *Service {
	return &Service{
		db:      db,
		acf:     newAdminClientFactory(),
		errInfo: errInfo,
		logger:  clog.Logger,
	}
}

type Service struct {
	db  hubauth.DataStore
	acf adminClientFactory

	logger  *zap.Logger
	errInfo *clog.ErrInfo
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

	audiences, err := s.db.ListAudiences(ctx)
	if err != nil {
		return fmt.Errorf("groupsync: error listing audiences: %w", err)
	}

	groups := make(map[domainGroup]string)
	for _, a := range audiences {
		for _, ug := range a.UserGroups {
			if ug.APIUser == "" || ug.Domain == "" || len(ug.Groups) == 0 {
				continue
			}
			for _, g := range ug.Groups {
				groups[domainGroup{ug.Domain, g}] = ug.APIUser
			}
		}
	}

	if len(groups) == 0 {
		return nil
	}

	serviceAccountEmail, err := s.acf.FetchTargetPrincipal()
	if err != nil {
		return fmt.Errorf("groupsync: error retrieving service account email: %w", err)
	}

	l := s.logger.With(zap.String("service_account", string(serviceAccountEmail)))
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

			ac, err := s.acf.NewAdminClient(context.Background(), serviceAccountEmail, apiUser, g.Domain)
			if err != nil {
				s.reportError(l, fmt.Errorf("failed to create admin client: %v", err))
				failed++
				return
			}

			group, err := ac.GetGroup(ctx, g.Group)
			if err != nil {
				s.reportError(l, fmt.Errorf("failed to get group: %v", err))
				failed++
				return
			}

			var members []*admin.Member
			var pageToken string
			for {
				res, err := ac.GetGroupMembers(ctx, g.Group, pageToken)
				if err != nil {
					s.reportError(l, fmt.Errorf("failed to get group members: %v", err))
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
				s.reportError(l, fmt.Errorf("failed to set cached group: %v", err))
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
