package token

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/policy"
)

var (
	ErrPublicKeyRequired = errors.New("token: a public key is required")
)

type biscuitBuilder struct {
	kms         kmssign.KMSClient
	db          hubauth.AudienceGetterStore
	audienceKey kmssign.AudienceKeyNamer
	rootKeyPair sig.Keypair
}

func NewBiscuitBuilder(kms kmssign.KMSClient, db hubauth.AudienceGetterStore, audienceKey kmssign.AudienceKeyNamer, rootKeyPair sig.Keypair) AccessTokenBuilder {
	return &biscuitBuilder{
		kms:         kms,
		db:          db,
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
		ClientID:   t.ClientID,
		UserID:     t.UserID,
		UserEmail:  t.UserEmail,
		UserGroups: t.UserGroups,
		IssueTime:  t.IssueTime,
	}

	builder := biscuit.NewBuilder(b.rootKeyPair)
	builder, err := signedbiscuit.WithSignableFacts(builder, audience, audienceKey, t.UserPublicKey, t.ExpireTime, meta)
	if err != nil {
		return nil, err
	}

	// retrieve policies from user groups and add each policy rules and caveats to the biscuit
	userPolicies, err := b.getUserPolicies(ctx, audience, t.UserGroups)
	if err != nil {
		return nil, err
	}

	for _, p := range userPolicies {
		builder, err = withPolicy(builder, p)
		if err != nil {
			return nil, err
		}
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

func (b *biscuitBuilder) getUserPolicies(ctx context.Context, audience string, userGroups []string) ([]*hubauth.BiscuitPolicy, error) {
	aud, err := b.db.GetAudience(ctx, audience)
	if err != nil {
		return nil, err
	}

	var userPolicies []*hubauth.BiscuitPolicy
	for _, p := range aud.Policies {
	outer:
		for _, g := range p.Groups {
			for _, ug := range userGroups {
				if g == ug {
					userPolicies = append(userPolicies, p)
					continue outer
				}
			}
		}
	}
	return userPolicies, nil
}

func withPolicy(builder biscuit.Builder, p *hubauth.BiscuitPolicy) (biscuit.Builder, error) {
	parsed, err := policy.ParseDocumentPolicy(strings.NewReader(p.Content))
	if err != nil {
		return nil, err
	}
	for _, rule := range parsed.Rules {
		biscuitRule, err := rule.ToBiscuit()
		if err != nil {
			return nil, err
		}
		if err := builder.AddAuthorityRule(*biscuitRule); err != nil {
			return nil, err
		}
	}
	for _, caveat := range parsed.Caveats {
		biscuitCaveat, err := caveat.ToBiscuit()
		if err != nil {
			return nil, err
		}
		if err := builder.AddAuthorityCaveat(*biscuitCaveat); err != nil {
			return nil, err
		}
	}
	return builder, nil
}
