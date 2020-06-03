package main

import (
	"context"
	"log"

	google_datastore "cloud.google.com/go/datastore"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/alecthomas/kong"
	"github.com/flynn/hubauth/pkg/cli"
	"github.com/flynn/hubauth/pkg/datastore"
)

func main() {
	cmd := &cli.CLI{}
	kc := kong.Parse(cmd)

	ctx := context.Background()
	dsClient, err := google_datastore.NewClient(ctx, cmd.ProjectID)
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("error initializing kms client: %s", err)
	}

	kc.FatalIfErrorf(kc.Run(&cli.Config{
		DB:        datastore.New(dsClient),
		KMS:       kmsClient,
		ProjectID: cmd.ProjectID,
	}))
}
