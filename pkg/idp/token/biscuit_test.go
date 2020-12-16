package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/stretchr/testify/require"
)

func TestBiscuitBuilder(t *testing.T) {
	audience := "https://audience.url"
	audienceKeyName := audienceKeyNamer(audience)
	kmsClient := kmssim.NewClient([]string{audienceKeyName})
	rootKeyPair := sig.GenerateKeypair(rand.Reader)

	builder := NewBiscuitBuilder(kmsClient, audienceKeyNamer, rootKeyPair)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	userPublicKey, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	now := time.Now()
	accessTokenData := &AccessTokenData{
		ClientID:   "clientID",
		ExpireTime: now.Add(1 * time.Minute),
		IssueTime:  now,
		UserEmail:  "user@email",
		UserID:     "userID",
	}
	_, err = builder.Build(context.Background(), audience, accessTokenData)
	require.Equal(t, ErrPublicKeyRequired, err)

	accessTokenData.UserPublicKey = userPublicKey
	token, err := builder.Build(context.Background(), audience, accessTokenData)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	_, err = b.Verify(rootKeyPair.Public())
	require.NoError(t, err)
}

func TestDecodeB64PrivateKey(t *testing.T) {
	expectedKP := sig.GenerateKeypair(rand.Reader)
	b64key := base64.StdEncoding.EncodeToString(expectedKP.Private().Bytes())

	kp, err := DecodeB64PrivateKey(b64key)
	require.NoError(t, err)
	require.Equal(t, expectedKP.Private().Bytes(), kp.Private().Bytes())
	require.Equal(t, expectedKP.Public().Bytes(), kp.Public().Bytes())
}
