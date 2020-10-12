package token

import (
	"context"
	"crypto"
	"errors"

	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/biscuit"
	"github.com/flynn/hubauth/pkg/kmssign"
)

var (
	ErrPublicKeyRequired = errors.New("token: a public key is required")
)

type biscuitBuilder struct {
	kms         kmssign.KMSClient
	audienceKey kmssign.AudienceKeyNamer
	rootKeyPair sig.Keypair
}

func NewBiscuitBuilder() AccessTokenBuilder {
	return &biscuitBuilder{}
}

func (b *biscuitBuilder) Build(ctx context.Context, audience string, t *AccessTokenData) ([]byte, error) {
	if len(t.UserPublicKey) == 0 {
		return nil, ErrPublicKeyRequired
	}
	audienceKey := kmssign.NewPrivateKey(b.kms, b.audienceKey(audience), crypto.SHA256)

	meta := &biscuit.Metadata{
		ClientID:  t.ClientID,
		UserID:    t.UserID,
		UserEmail: t.UserEmail,
		IssueTime: t.IssueTime,
	}

	return biscuit.GenerateSignable(b.rootKeyPair, audience, audienceKey, t.UserPublicKey, t.ExpireTime, meta)
}
