package cli

import (
	"github.com/flynn/hubauth/pkg/cli/kms"
	"github.com/flynn/hubauth/pkg/hubauth"
)

type Config struct {
	DB  hubauth.DataStore
	KMS kms.Client

	ProjectID string
}

type CLI struct {
	ProjectID string `kong:"name='project-id',default='flynn-hubauth-production',help='GCP project ID'"`

	Clients   clientsCmd   `kong:"cmd,help='manage oauth clients'"`
	Audiences audiencesCmd `kong:"cmd,help='manage audiences'"`
	Policies  policiesCmd  `kong:"cmd,help='manage policies'"`
}
