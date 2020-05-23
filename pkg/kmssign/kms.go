package kmssign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"

	gax "github.com/googleapis/gax-go/v2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/exp/errors/fmt"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

type SignerOpts interface {
	crypto.SignerOpts

	Context() context.Context
}

func NewKey(ctx context.Context, client KMSClient, name string) (*Key, error) {
	res, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("kmssign: error looking up key: %w", err)
	}

	k := &Key{
		name: name,
		c:    client,
	}

	switch res.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		k.hash = crypto.SHA256
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		k.hash = crypto.SHA384
	default:
		return nil, fmt.Errorf("kmssign: algorithm %v is not supported", res.Algorithm)
	}

	keyDER, _ := pem.Decode([]byte(res.Pem))
	if keyDER == nil {
		return nil, fmt.Errorf("kmssign: error decode public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(keyDER.Bytes)
	if err != nil {
		return nil, fmt.Errorf("kmssign: error decoding public key DER: %w", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kmssign: unexpected key type %T", ecdsaKey)
	}
	k.pub = ecdsaKey

	return k, nil
}

type Key struct {
	name string
	pub  *ecdsa.PublicKey
	hash crypto.Hash
	c    KMSClient
}

func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *Key) HashFunc() crypto.Hash {
	return k.hash
}

func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx context.Context
	if o, ok := opts.(SignerOpts); ok {
		ctx = o.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.HashFunc() != k.hash {
		return nil, fmt.Errorf("kmssign: incorrect hash function %v, required to be %v", opts.HashFunc(), k.hash)
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: k.name,
	}
	switch k.hash {
	case crypto.SHA256:
		req.Digest = &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}
	case crypto.SHA384:
		req.Digest = &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}
	}

	res, err := k.c.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("kmssign: error signing: %w", err)
	}

	return res.Signature, nil
}

func (k *Key) Verify(digest, sig []byte) bool {
	return verifyASN1(k.pub, digest, sig)
}

// This should be replaced with ecdsa.VerifyASN1 when Go 1.15 is available
// https://go.googlesource.com/go/+/8c09e8af3633b0c08d2c309e56a58124dfee3d7c
func verifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return ecdsa.Verify(pub, hash, r, s)
}
