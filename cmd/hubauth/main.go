package main

import (
	"context"
	"log"
	"os"

	google_datastore "cloud.google.com/go/datastore"
	"github.com/alecthomas/kong"
	"github.com/flynn/hubauth/pkg/cli"
	"github.com/flynn/hubauth/pkg/datastore"
)

func main() {
	ctx := context.Background()
	dsClient, err := google_datastore.NewClient(ctx, os.Getenv("PROJECT_ID"))
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}

	kc := kong.Parse(&cli.CLI)
	kc.FatalIfErrorf(kc.Run(&cli.Config{DB: datastore.New(dsClient)}))
}
