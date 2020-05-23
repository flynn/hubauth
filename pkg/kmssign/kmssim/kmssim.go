package kmssim

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/flynn/hubauth/pkg/kmssign"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func NewClient(keyNames []string) kmssign.KMSClient {
	c := &client{
		pub:  make(map[string]string, len(keyNames)),
		priv: make(map[string]*ecdsa.PrivateKey, len(keyNames)),
	}
	for _, n := range keyNames {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		c.priv[n] = k
		der, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			panic(err)
		}
		c.pub[n] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return c
}

type client struct {
	pub  map[string]string
	priv map[string]*ecdsa.PrivateKey
}

func (c *client) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	priv, ok := c.priv[req.Name]
	if !ok {
		// TODO: make this error realistic
		return nil, errors.New("key not found")
	}
	sig, err := priv.Sign(rand.Reader, req.Digest.GetSha256(), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &kms.AsymmetricSignResponse{
		Signature: sig,
	}, nil
}
func (c *client) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	pem, ok := c.pub[req.Name]
	if !ok {
		// TODO: make this error realistic
		return nil, errors.New("key not found")
	}
	return &kmspb.PublicKey{
		Pem:       pem,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	}, nil
}
