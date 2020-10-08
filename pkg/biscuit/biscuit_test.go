package biscuit

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/stretchr/testify/require"
)

func TestBiscuit(t *testing.T) {
	rootKey := sig.GenerateKeypair(rand.Reader)
	audience := "http://random.audience.url"

	kms := kmssim.NewClient([]string{audience})
	audienceKey, err := kmssign.NewKey(context.Background(), kms, audience)
	require.NoError(t, err)

	userKey := generateUserKeyPair(t)

	signableBiscuit, err := GenerateSignable(rootKey, audience, audienceKey, userKey.Public)
	require.NoError(t, err)
	t.Logf("signable biscuit size: %d", len(signableBiscuit))

	t.Run("happy path", func(t *testing.T) {
		signedBiscuit, err := Sign(signableBiscuit, rootKey.Public(), userKey)
		require.NoError(t, err)
		t.Logf("signed biscuit size: %d", len(signedBiscuit))

		err = Verify(signedBiscuit, rootKey.Public(), audience, audienceKey)
		require.NoError(t, err)
	})

	t.Run("user sign with wrong key", func(t *testing.T) {
		_, err := Sign(signableBiscuit, rootKey.Public(), generateUserKeyPair(t))
		require.Error(t, err)
	})

	t.Run("verify wrong audience", func(t *testing.T) {
		signedBiscuit, err := Sign(signableBiscuit, rootKey.Public(), userKey)
		require.NoError(t, err)

		err = Verify(signedBiscuit, rootKey.Public(), "http://another.audience.url", audienceKey)
		require.Error(t, err)

		wrongAudience := "http://another.audience.url"
		kms := kmssim.NewClient([]string{wrongAudience})
		wrongAudienceKey, err := kmssign.NewKey(context.Background(), kms, wrongAudience)
		require.NoError(t, err)

		err = Verify(signedBiscuit, rootKey.Public(), audience, wrongAudienceKey)
		require.Error(t, err)
	})
}
