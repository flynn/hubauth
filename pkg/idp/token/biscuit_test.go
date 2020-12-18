package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/flynn/hubauth/pkg/kmssign/kmssim"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type mockAudienceGetterStore struct {
	mock.Mock
}

func (m *mockAudienceGetterStore) GetAudience(ctx context.Context, url string) (*hubauth.Audience, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*hubauth.Audience), args.Error(1)
}

var _ hubauth.AudienceGetterStore = (*mockAudienceGetterStore)(nil)

func TestBiscuitBuilder(t *testing.T) {
	audience := "https://audience.url"
	audienceKeyName := audienceKeyNamer(audience)
	kmsClient := kmssim.NewClient([]string{audienceKeyName})
	rootKeyPair := sig.GenerateKeypair(rand.Reader)

	audienceGetterStore := new(mockAudienceGetterStore)

	builder := NewBiscuitBuilder(kmsClient, audienceGetterStore, audienceKeyNamer, rootKeyPair)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	userPublicKey, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	now := time.Now()
	userGroups := []string{"grp1", "grp2"}

	accessTokenData := &AccessTokenData{
		ClientID:   "clientID",
		ExpireTime: now.Add(1 * time.Minute),
		IssueTime:  now,
		UserEmail:  "user@email",
		UserGroups: userGroups,
		UserID:     "userID",
	}
	_, err = builder.Build(context.Background(), audience, accessTokenData)
	require.Equal(t, ErrPublicKeyRequired, err)

	accessTokenData.UserPublicKey = userPublicKey

	p1Content := `
		policy "p1" {
			caveats {[
				*valid() <- test(#ambient, "policy1exists")
			]}
		}
	`

	p2Content := `
		policy "p2" {
			rules {
				*test(#authority, $inputStr)
					<- testRule(#ambient, $inputStr)
			}
			caveats {[
				*valid() <- test(#authority, "policy2exists")
			]}
		}
	`

	p3Content := `
		policy "p3" {
			caveats {[
				*valid() <- test(#ambient, "policy3exists")
			]}
		}
	`

	aud := &hubauth.Audience{
		URL: audience,
		Policies: []*hubauth.BiscuitPolicy{
			{
				Name:    "p1",
				Content: p1Content,
				Groups:  []string{"grp1"},
			},
			{
				Name:    "p2",
				Content: p2Content,
				Groups:  []string{"grp2", "grp3"},
			},
			{
				Name:    "p3",
				Content: p3Content,
				Groups:  []string{"grp3"},
			},
		},
	}
	audienceGetterStore.On("GetAudience", mock.Anything, audience).Return(aud, nil)

	token, err := builder.Build(context.Background(), audience, accessTokenData)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	userKeyPair, err := signedbiscuit.NewECDSAKeyPair(priv)
	require.NoError(t, err)
	token, err = signedbiscuit.Sign(token, rootKeyPair.Public(), userKeyPair)
	require.NoError(t, err)

	b, err := biscuit.Unmarshal(token)
	require.NoError(t, err)

	verifier, err := b.Verify(rootKeyPair.Public())
	require.NoError(t, err)

	kmsPubkey, err := kmsClient.GetPublicKey(context.Background(), &kms.GetPublicKeyRequest{Name: audienceKeyName})
	require.NoError(t, err)
	pemBlock, _ := pem.Decode([]byte(kmsPubkey.Pem))
	audiencePubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	require.NoError(t, err)

	verifier, metas, err := signedbiscuit.WithSignatureVerification(verifier, audience, audiencePubKey.(*ecdsa.PublicKey))
	require.NoError(t, err)

	require.Equal(t, accessTokenData.ClientID, metas.ClientID)
	require.Equal(t, accessTokenData.UserEmail, metas.UserEmail)
	require.Equal(t, accessTokenData.UserGroups, metas.UserGroups)
	require.Equal(t, accessTokenData.UserID, metas.UserID)
	require.Equal(t, accessTokenData.IssueTime.Unix(), metas.IssueTime.Unix())

	require.Error(t, verifier.Verify())

	verifier.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "test",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("policy1exists")},
	}})
	require.Error(t, verifier.Verify())

	verifier.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "testRule",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("policy2exists")},
	}})
	require.NoError(t, verifier.Verify())
}

func TestDecodeB64PrivateKey(t *testing.T) {
	expectedKP := sig.GenerateKeypair(rand.Reader)
	b64key := base64.StdEncoding.EncodeToString(expectedKP.Private().Bytes())

	kp, err := DecodeB64PrivateKey(b64key)
	require.NoError(t, err)
	require.Equal(t, expectedKP.Private().Bytes(), kp.Private().Bytes())
	require.Equal(t, expectedKP.Public().Bytes(), kp.Public().Bytes())
}
