package hubauth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("hubauth: resource not found")
	ErrExpired  = errors.New("hubauth: resource has expired")

	ErrIncorrectCodeSecret         = errors.New("hubauth: incorrect secret for code")
	ErrRefreshTokenVersionMismatch = errors.New("hubauth: provided refresh token has the wrong version")
)

type DataStore interface {
	ClientStore
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
	ID           string
	RedirectURIs []string
	Policies     []*GoogleUserPolicy
	CreateTime   time.Time
	UpdateTime   time.Time
}

type GoogleUserPolicy struct {
	Domain  string
	APIUser string
	Groups  []string
}

type ClientMutationOp byte

const (
	ClientMutationOpAddRedirectURI ClientMutationOp = iota
	ClientMutationOpDeleteRedirectURI
	ClientMutationOpSetPolicy
	ClientMutationOpDeletePolicy
)

type ClientMutation struct {
	Op          ClientMutationOp
	RedirectURI string
	Policy      GoogleUserPolicy
}

type CodeStore interface {
	GetCode(ctx context.Context, id string) (*Code, error)
	VerifyAndDeleteCode(ctx context.Context, id, secret string) (*Code, error)
	CreateCode(ctx context.Context, code *Code) (string, string, error)
	DeleteCode(ctx context.Context, id string) error
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type Code struct {
	ID            string
	Secret        string
	ClientID      string
	UserID        string
	RedirectURI   string
	Nonce         string
	PKCEChallenge string
	CreateTime    time.Time
	ExpiryTime    time.Time
}

type RefreshTokenStore interface {
	GetRefreshToken(ctx context.Context, id string) (*RefreshToken, error)
	CreateRefreshToken(ctx context.Context, token *RefreshToken) (string, error)
	RenewRefreshToken(ctx context.Context, id string, version int) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error
	DeleteRefreshTokensWithCode(ctx context.Context, codeID string) ([]string, error)
	DeleteExpiredRefreshTokens(ctx context.Context) ([]string, error)
}

type RefreshToken struct {
	ID         string
	ClientID   string
	UserID     string
	CodeID     string
	Version    int
	CreateTime time.Time
	RenewTime  time.Time
	ExpiryTime time.Time
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
	Etag       string
	UpdateTime time.Time
	CreateTime time.Time
}

type CachedGroupMember struct {
	UserID string
	Email  string
	Etag   string
}
