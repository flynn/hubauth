package token

import (
	"context"
	"time"
)

type AccessTokenData struct {
	ClientID  string
	UserID    string
	UserEmail string
}

type AccessTokenBuilder interface {
	Build(ctx context.Context, audience string, t *AccessTokenData, now time.Time, duration time.Duration) ([]byte, error)
}
