package token

import (
	"context"
	"time"
)

type AccessTokenData struct {
	ClientID      string
	UserID        string
	UserEmail     string
	UserPublicKey []byte
	IssueTime     time.Time
	ExpireTime    time.Time
}

type AccessTokenBuilder interface {
	Build(ctx context.Context, audience string, t *AccessTokenData) ([]byte, error)
	TokenType() string
}
