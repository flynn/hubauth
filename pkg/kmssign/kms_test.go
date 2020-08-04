package kmssign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type mockKMSClient struct {
	mock.Mock
}

var _ KMSClient = (*mockKMSClient)(nil)

func (m *mockKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*kmspb.AsymmetricSignResponse), args.Error(1)
}
func (m *mockKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*kmspb.PublicKey), args.Error(1)
}

func TestNewKey(t *testing.T) {
	ctx := context.Background()
	name := "keyName"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(privKey.Public())
	require.NoError(t, err)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER}))

	testCases := []struct {
		Desc         string
		PrivKey      crypto.Signer
		PublicKey    *kmspb.PublicKey
		ExpectedHash crypto.Hash
	}{
		{
			Desc:    "SHA256 ECDSA key",
			PrivKey: privKey,
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				Pem:       pubKeyPEM,
			},
			ExpectedHash: crypto.SHA256,
		},
		{
			Desc:    "SHA384 ECDSA key",
			PrivKey: privKey,
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
				Pem:       pubKeyPEM,
			},
			ExpectedHash: crypto.SHA384,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			mockKMS := &mockKMSClient{}
			mockKMS.On("GetPublicKey", ctx, &kmspb.GetPublicKeyRequest{Name: name}, []gax.CallOption(nil)).Return(testCase.PublicKey, nil)
			want, err := NewKey(ctx, mockKMS, name)
			require.NoError(t, err)

			got := &Key{
				name: name,
				c:    mockKMS,
				hash: testCase.ExpectedHash,
				pub:  testCase.PrivKey.Public().(*ecdsa.PublicKey),
			}
			require.Equal(t, got, want)
		})
	}
}

func TestNewKeyErrors(t *testing.T) {
	kmsErr := errors.New("kms error")
	keyName := "keyName"

	invalidPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}))

	rsaPK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(rsaPK.Public())
	require.NoError(t, err)
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}))

	testCases := []struct {
		Desc         string
		KeyName      string
		PublicKey    *kmspb.PublicKey
		PublicKeyErr error
		ExpectedErr  error
	}{
		{
			Desc:         "KMS client returns an error",
			PublicKey:    &kmspb.PublicKey{},
			PublicKeyErr: kmsErr,
			ExpectedErr:  kmsErr,
		},
		{
			Desc: "Unsupported algorithm",
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			},
		},
		{
			Desc: "PublicKey is not PEM encoded",
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				Pem:       "invalid",
			},
		},
		{
			Desc: "PublicKey PEM is not a valid DER",
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				Pem:       invalidPEM,
			},
		},
		{
			Desc: "PublicKey DER is not an ECDSA key",
			PublicKey: &kmspb.PublicKey{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				Pem:       rsaPEM,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			mockKMS := &mockKMSClient{}
			mockKMS.On("GetPublicKey", mock.Anything, &kmspb.GetPublicKeyRequest{
				Name: keyName,
			}, []gax.CallOption(nil)).Return(testCase.PublicKey, testCase.PublicKeyErr).Once()

			_, err := NewKey(context.Background(), mockKMS, keyName)
			require.Error(t, err)
			if testCase.ExpectedErr != nil {
				require.Equal(t, testCase.ExpectedErr, errors.Unwrap(err))
			}
		})
	}
}

type opts struct {
	crypto.SignerOpts
	ctx context.Context
}

func (o opts) Context() context.Context {
	return o.ctx
}

func TestKeySign(t *testing.T) {
	sha256Digest := make([]byte, crypto.SHA256.Size())
	sha384Digest := make([]byte, crypto.SHA384.Size())

	testCases := []struct {
		Desc                 string
		KeyHash              crypto.Hash
		ExpectedDigest       *kmspb.Digest
		ExpectedSignedDigest []byte
	}{
		{
			Desc:                 "SHA256 hash",
			KeyHash:              crypto.SHA256,
			ExpectedDigest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: sha256Digest}},
			ExpectedSignedDigest: sha256Digest,
		},
		{
			Desc:                 "SHA384 hash",
			KeyHash:              crypto.SHA384,
			ExpectedDigest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: sha384Digest}},
			ExpectedSignedDigest: sha384Digest,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			keyName := "keyName"
			mockKMS := &mockKMSClient{}
			k := NewPrivateKey(mockKMS, keyName, testCase.KeyHash)

			expectedSignature := []byte("signature")
			ctx := context.Background()

			mockKMS.On("AsymmetricSign", ctx, &kmspb.AsymmetricSignRequest{
				Name:   keyName,
				Digest: testCase.ExpectedDigest,
			}, []gax.CallOption(nil)).Return(&kmspb.AsymmetricSignResponse{
				Signature: expectedSignature,
			}, nil)

			signature, err := k.Sign(rand.Reader, testCase.ExpectedSignedDigest, opts{k, ctx})
			require.NoError(t, err)
			require.Equal(t, expectedSignature, signature)
		})
	}
}

func TestKeySignErrors(t *testing.T) {

	testCases := []struct {
		Desc     string
		KMSErr   error
		KeyHash  crypto.Hash
		SignHash crypto.Hash
		Digest   []byte
	}{
		{
			Desc:     "hash func mismatch",
			KeyHash:  crypto.SHA256,
			SignHash: crypto.SHA384,
		},
		{
			Desc:     "incorrect sha256 digest length",
			KeyHash:  crypto.SHA256,
			SignHash: crypto.SHA256,
			Digest:   make([]byte, crypto.SHA256.Size()+1),
		},
		{
			Desc:     "incorrect sha384 digest length",
			KeyHash:  crypto.SHA384,
			SignHash: crypto.SHA384,
			Digest:   make([]byte, crypto.SHA384.Size()+1),
		},
		{
			Desc:     "unsupported digest",
			KeyHash:  crypto.SHA512,
			SignHash: crypto.SHA512,
			Digest:   make([]byte, crypto.SHA512.Size()),
		},
		{
			Desc:     "KMS client error",
			KeyHash:  crypto.SHA256,
			SignHash: crypto.SHA256,
			Digest:   make([]byte, crypto.SHA256.Size()),
			KMSErr:   errors.New("kms error"),
		},
	}

	for _, testCase := range testCases {
		mockKMS := &mockKMSClient{}
		k := NewPrivateKey(mockKMS, "keyName", testCase.KeyHash)

		mockKMS.On("AsymmetricSign", mock.Anything, mock.Anything, mock.Anything).Return(&kmspb.AsymmetricSignResponse{}, testCase.KMSErr).Once()

		_, err := k.Sign(rand.Reader, testCase.Digest, testCase.SignHash)
		require.Error(t, err)

		if testCase.KMSErr != nil {
			require.Equal(t, testCase.KMSErr, errors.Unwrap(err))
		}
	}
}

func TestVerify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockKMS := &mockKMSClient{}
	k := &Key{
		name: "keyName",
		c:    mockKMS,
		hash: crypto.SHA256,
		pub:  privKey.Public().(*ecdsa.PublicKey),
	}

	digest := sha256.Sum256([]byte("digest"))
	signature, err := privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	require.True(t, k.Verify(digest[:], signature))
}

func TestVerifyPanicWithEmptyPubkey(t *testing.T) {
	defer func() { recover() }()

	mockKMS := &mockKMSClient{}
	k := &Key{
		name: "keyName",
		c:    mockKMS,
		hash: crypto.SHA256,
		pub:  nil,
	}

	k.Verify([]byte("digest"), []byte("signature"))

	t.Errorf("did not panic")
}
