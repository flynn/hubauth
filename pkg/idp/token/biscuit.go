package token

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
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

func NewBiscuitBuilder(kms kmssign.KMSClient, audienceKey kmssign.AudienceKeyNamer, rootKeyPair sig.Keypair) AccessTokenBuilder {
	return &biscuitBuilder{
		kms:         kms,
		audienceKey: audienceKey,
		rootKeyPair: rootKeyPair,
	}
}

func (b *biscuitBuilder) Build(ctx context.Context, audience string, t *AccessTokenData) ([]byte, error) {
	if len(t.UserPublicKey) == 0 {
		return nil, ErrPublicKeyRequired
	}
	audienceKey := kmssign.NewPrivateKey(b.kms, b.audienceKey(audience), crypto.SHA256)

	meta := &signedbiscuit.Metadata{
		ClientID:  t.ClientID,
		UserID:    t.UserID,
		UserEmail: t.UserEmail,
		IssueTime: t.IssueTime,
	}

	builder := biscuit.NewBuilder(b.rootKeyPair)
	builder, err := signedbiscuit.WithSignableFacts(builder, audience, audienceKey, t.UserPublicKey, t.ExpireTime, meta)
	if err != nil {
		return nil, err
	}

	bisc, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return bisc.Serialize()
}

func (b *biscuitBuilder) TokenType() string {
	return "Biscuit"
}

func DecodeB64PrivateKey(b64key string) (sig.Keypair, error) {
	var kp sig.Keypair
	privKey, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return kp, fmt.Errorf("failed to decode b64 key: %w", err)
	}
	rootPrivateKey, err := sig.NewPrivateKey(privKey)
	if err != nil {
		return kp, fmt.Errorf("failed to create biscuit private key: %w", err)
	}
	kp = sig.NewKeypair(rootPrivateKey)
	return kp, nil
}
