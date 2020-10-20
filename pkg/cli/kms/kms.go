package kms

import (
	"context"
	"fmt"

	gkms "cloud.google.com/go/kms/apiv1"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Client interface {
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	// ListCryptoKeyVersions differ from google KMS client interface to get ride of their *kms.CryptoKeyVersionIterator
	ListCryptoKeyVersions(context.Context, *kmspb.ListCryptoKeyVersionsRequest, ...gax.CallOption) ([]*kmspb.CryptoKeyVersion, error)
	DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

type kms struct {
	c *gkms.KeyManagementClient
}

func NewKMSClient(ctx context.Context) (Client, error) {
	c, err := gkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return &kms{c: c}, nil
}

func (k *kms) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return k.c.CreateCryptoKey(ctx, req, opts...)
}

func (k *kms) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	return k.c.GetPublicKey(ctx, req, opts...)
}

func (k *kms) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...gax.CallOption) ([]*kmspb.CryptoKeyVersion, error) {
	it := k.c.ListCryptoKeyVersions(ctx, req, opts...)
	var versions []*kmspb.CryptoKeyVersion
	for {
		version, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get crypto key version: %v", err)
		}
		versions = append(versions, version)
	}
	return versions, nil
}

func (k *kms) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return k.c.DestroyCryptoKeyVersion(ctx, req, opts...)
}
