package cli

import (
	"context"

	"github.com/flynn/hubauth/pkg/hubauth"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KMS interface {
	CreateCryptoKey(context.Context, *kms.CreateCryptoKeyRequest, ...gax.CallOption) (*kms.CryptoKey, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyRequest, ...gax.CallOption) (*kms.PublicKey, error)
}

type Config struct {
	DB  hubauth.DataStore
	KMS KMS

	ProjectID string
}

type CLI struct {
	ProjectID string `kong:"name='project-id',default='flynn-hubauth-production',help='GCP project ID'"`

	Clients   clientsCmd   `kong:"cmd,help='manage oauth clients'"`
	Audiences audiencesCmd `kong:"cmd,help='manage audiences'"`
}
