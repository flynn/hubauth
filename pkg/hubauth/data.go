package hubauth

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("hubauth: resource not found")
	ErrExpired  = errors.New("hubauth: resource has expired")

	ErrIncorrectCodeSecret         = errors.New("hubauth: incorrect secret for code")
	ErrRefreshTokenVersionMismatch = errors.New("hubauth: provided refresh token has the wrong version")
	ErrClientIDMismatch            = errors.New("hubauth: client ID does match")
)

type DataStore interface {
	ClientStore
	AudienceStore
	CodeStore
	RefreshTokenStore
	CachedGroupStore
}

type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) (string, error)
	MutateClient(ctx context.Context, id string, mut []*ClientMutation) error
	ListClients(ctx context.Context) ([]*Client, error)
	DeleteClient(ctx context.Context, id string) error
}

type Client struct {
	ID                 string
	RedirectURIs       []string
	RefreshTokenExpiry time.Duration
	CreateTime         time.Time
	UpdateTime         time.Time
}

type ClientMutationOp byte

const (
	ClientMutationOpAddRedirectURI ClientMutationOp = iota
	ClientMutationOpDeleteRedirectURI
	ClientMutationOpSetRefreshTokenExpiry
)

type ClientMutation struct {
	Op ClientMutationOp

	RedirectURI        string
	RefreshTokenExpiry time.Duration
}

type AudienceStore interface {
	GetAudience(ctx context.Context, url string) (*Audience, error)
	CreateAudience(ctx context.Context, audience *Audience) error
	MutateAudience(ctx context.Context, url string, mut []*AudienceMutation) error
	MutateAudienceUserGroups(ctx context.Context, url string, domain string, mut []*AudienceUserGroupsMutation) error
	ListAudiencesForClient(ctx context.Context, clientID string) ([]*Audience, error)
	ListAudiences(ctx context.Context) ([]*Audience, error)
	DeleteAudience(ctx context.Context, url string) error
}

type Audience struct {
	URL        string              `json:"url"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	ClientIDs  []string            `json:"-"`
	UserGroups []*GoogleUserGroups `json:"-"`
	CreateTime time.Time           `json:"-"`
	UpdateTime time.Time           `json:"-"`
}

type GoogleUserGroups struct {
	Domain  string
	APIUser string
	Groups  []string
}

type AudienceMutationOp byte

const (
	AudienceMutationOpAddClientID AudienceMutationOp = iota
	AudienceMutationOpDeleteClientID
	AudienceMutationOpSetUserGroups
	AudienceMutationOpDeleteUserGroups
	AudienceMutationSetType
	AudienceMutationMigratePolicy
)

type AudienceMutation struct {
	Op AudienceMutationOp

	ClientID   string
	Type       string
	UserGroups GoogleUserGroups
}

type AudienceUserGroupsMutationOp byte

const (
	AudienceUserGroupsMutationOpAddGroup AudienceUserGroupsMutationOp = iota
	AudienceUserGroupsMutationOpDeleteGroup
	AudienceUserGroupsMutationOpSetAPIUser
)

type AudienceUserGroupsMutation struct {
	Op AudienceUserGroupsMutationOp

	APIUser string
	Group   string
}

type CodeStore interface {
	GetCode(ctx context.Context, id string) (*Code, error)
	VerifyAndDeleteCode(ctx context.Context, id, secret string) (*Code, error)
	CreateCode(ctx context.Context, code *Code) (string, string, error)
	DeleteCode(ctx context.Context, id string) error
	DeleteExpiredCodes(ctx context.Context) ([]string, error)
}

type Code struct {
	ID            string
	Secret        string
	ClientID      string
	UserID        string
	UserEmail     string
	RedirectURI   string
	Nonce         string
	PKCEChallenge string
	CreateTime    time.Time
	ExpiryTime    time.Time
}

type RefreshTokenStore interface {
	GetRefreshToken(ctx context.Context, id string) (*RefreshToken, error)
	AllocateRefreshTokenID(ctx context.Context, clientID string) (string, error)
	CreateRefreshToken(ctx context.Context, token *RefreshToken) (string, error)
	RenewRefreshToken(ctx context.Context, clientID, id string, prevIssueTime, now time.Time) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error
	DeleteRefreshTokensWithCode(ctx context.Context, codeID string) ([]string, error)
	DeleteExpiredRefreshTokens(ctx context.Context) ([]string, error)
}

type RefreshToken struct {
	ID          string
	ClientID    string
	UserID      string
	UserEmail   string
	RedirectURI string
	CodeID      string
	CreateTime  time.Time
	IssueTime   time.Time
	ExpiryTime  time.Time
}

type SetCachedGroupResult struct {
	UpdatedGroup   bool
	AddedMembers   []string
	UpdatedMembers []string
	DeletedMembers []string
}

type CachedGroupStore interface {
	ListCachedGroups(ctx context.Context) ([]*CachedGroup, error)
	SetCachedGroup(ctx context.Context, group *CachedGroup, members []*CachedGroupMember) (*SetCachedGroupResult, error)
	GetCachedMemberGroups(ctx context.Context, userID string) ([]string, error)
	DeleteCachedGroup(ctx context.Context, domain, groupID string) error
}

type CachedGroup struct {
	Domain     string
	GroupID    string
	Email      string
	UpdateTime time.Time
	CreateTime time.Time
}

type CachedGroupMember struct {
	UserID string
	Email  string
}

type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e OAuthError) Error() string {
	if e.Description == "" {
		return "oauth error: " + e.Code
	}
	return e.Description
}

func (e OAuthError) RedirectURI(baseURL, state string, fragment bool) string {
	res, _ := RedirectURI(baseURL, fragment, map[string]string{
		"state":             state,
		"error":             e.Code,
		"error_description": e.Description,
	})
	return res
}

func RedirectURI(base string, fragment bool, data map[string]string) (string, bool) {
	u, err := url.Parse(base)
	if err != nil {
		return "", false
	}

	var params url.Values
	if fragment {
		params = make(url.Values, 3)
	} else {
		params = u.Query()
	}

	for k, v := range data {
		params.Set(k, v)
	}

	if fragment {
		if u.Fragment != "" && !strings.HasSuffix(u.Fragment, "&") {
			u.Fragment += "&"
		}
		u.Fragment += params.Encode()
	} else {
		u.RawQuery = params.Encode()
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if host == "" {
		host = u.Host
	}
	isLocalhost := host == "127.0.0.1" || host == "localhost"

	return u.String(), isLocalhost
}

type ClientInfo struct {
	// Only set after the RedirectURI has been validated
	RedirectURI string
	State       string
	Fragment    bool
}

type ctxKeyClientInfo struct{}

func InitClientInfo(parent context.Context) context.Context {
	return context.WithValue(parent, ctxKeyClientInfo{}, &ClientInfo{})
}

func GetClientInfo(ctx context.Context) *ClientInfo {
	res, ok := ctx.Value(ctxKeyClientInfo{}).(*ClientInfo)
	if !ok {
		return nil
	}
	return res
}
