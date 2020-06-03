package main

import (
	"context"
	"log"
	"net/http"
	"os"

	google_datastore "cloud.google.com/go/datastore"
	"cloud.google.com/go/errorreporting"
	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"contrib.go.opencensus.io/exporter/stackdriver/propagation"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/httpapi"
	"github.com/flynn/hubauth/pkg/idp"
	"github.com/flynn/hubauth/pkg/kmssign"
	"github.com/flynn/hubauth/pkg/rp/google"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/trace"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

func main() {
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8000"
	}

	exporter, err := stackdriver.NewExporter(stackdriver.Options{
		DefaultTraceAttributes: map[string]interface{}{"build_rev": os.Getenv("BUILD_REV")},
	})
	if err != nil {
		log.Fatal(err)
	}
	trace.RegisterExporter(exporter)
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	ctx := context.Background()
	errClient, err := errorreporting.NewClient(ctx, os.Getenv("PROJECT_ID"), errorreporting.Config{
		ServiceName:    "hubauth-ext",
		ServiceVersion: os.Getenv("BUILD_REV"),
	})
	if err != nil {
		log.Fatalf("error initializing error reporting client: %s", err)
	}

	dsClient, err := google_datastore.NewClient(ctx, os.Getenv("PROJECT_ID"))
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("error initializing kms client: %s", err)
	}
	refreshKey, err := kmssign.NewKey(ctx, kmsClient, os.Getenv("REFRESH_KEY"))
	if err != nil {
		log.Fatalf("error initializing refresh key: %s", err)
	}

	secretsClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("error initializing secrets manager client: %s", err)
	}
	secret := func(name string) string {
		req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: os.Getenv(name),
		}
		result, err := secretsClient.AccessSecretVersion(ctx, req)
		if err != nil {
			log.Fatalf("failed to access secret version: %s", err)
		}
		return result.Payload.String()
	}

	log.Fatal(http.ListenAndServe(":"+httpPort, &ochttp.Handler{
		Propagation: &propagation.HTTPFormat{},
		Handler: httpapi.New(
			idp.New(datastore.New(dsClient),
				google.New(
					os.Getenv("RP_GOOGLE_CLIENT_ID"),
					os.Getenv("RP_GOOGLE_CLIENT_SECRET"),
					os.Getenv("BASE_URL")+"/rp/google",
				),
				kmsClient,
				[]byte(secret("CODE_KEY_SECRET")),
				refreshKey,
				idp.ClusterKeyNameFunc(os.Getenv("PROJECT_ID"), os.Getenv("KMS_LOCATION"), os.Getenv("KMS_KEYRING")),
			),
			errClient,
			[]byte(secret("COOKIE_KEY_SECRET")),
		)},
	))
}
