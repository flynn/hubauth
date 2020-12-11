package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	google_datastore "cloud.google.com/go/datastore"
	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"contrib.go.opencensus.io/exporter/stackdriver/propagation"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/httpapi"
	"github.com/flynn/hubauth/pkg/idp"
	"github.com/flynn/hubauth/pkg/idp/token"
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
			log.Fatalf("failed to access secret version for %s: %s", name, err)
		}

		// Payload.String() would return a json encoded version of the secret: {"data": "..."}
		// the actual secret is in Data.
		return string(result.Payload.Data)
	}

	forcedAudienceKeyVersions := new(kmssign.ForcedAudiencesKeyVersion)
	// AUDIENCE_KEYS is a env variable containing a serialized json object, holding tuples of audienceURL: keyVersion
	// it allows to specify a different key to use for some audience.
	// example:
	// {
	//   "https://audience.url": "projects/PROJECT/locations/KMS_LOCATION/keyRings/KMS_KEYRING/cryptoKeys/AUDIENCE_NAME/cryptoKeyVersions/VERSION",
	//   "https://another.audience.url": "projects/PROJECT/locations/KMS_LOCATION/keyRings/KMS_KEYRING/cryptoKeys/AUDIENCE_NAME/cryptoKeyVersions/VERSION"
	// }
	if keys := os.Getenv("AUDIENCE_KEYS"); keys != "" {
		if err := json.Unmarshal([]byte(keys), forcedAudienceKeyVersions); err != nil {
			log.Fatalf("invalid audience keys: %v", err)
		}
	}

	audienceKeyNamer := kmssign.AudienceKeyNameFunc(*forcedAudienceKeyVersions, os.Getenv("PROJECT_ID"), os.Getenv("KMS_LOCATION"), os.Getenv("KMS_KEYRING"))

	var accessTokenBuilder token.AccessTokenBuilder
	var rootPubKey []byte
	tokenType, exists := os.LookupEnv("TOKEN_TYPE")
	if !exists {
		tokenType = "Bearer"
	}
	switch tokenType {
	case "Bearer":
		accessTokenBuilder = token.NewBearerBuilder(kmsClient, audienceKeyNamer)
	case "Biscuit":
		biscuitKey, err := token.DecodeB64PrivateKey(secret("BISCUIT_ROOT_PRIVKEY"))
		if err != nil {
			log.Fatalf("failed to initialize biscuit keypair: %v", err)
		}

		rootPubKey = biscuitKey.Public().Bytes()
		accessTokenBuilder = token.NewBiscuitBuilder(kmsClient, audienceKeyNamer, biscuitKey)
	default:
		log.Fatalf("invalid TOKEN_TYPE, must be one of: Bearer, Biscuit")
	}

	log.Fatal(http.ListenAndServe(":"+httpPort, &ochttp.Handler{
		Propagation: &propagation.HTTPFormat{},
		Handler: httpapi.New(httpapi.Config{
			IdP: idp.New(
				datastore.New(dsClient),
				google.New(
					os.Getenv("RP_GOOGLE_CLIENT_ID"),
					os.Getenv("RP_GOOGLE_CLIENT_SECRET"),
					os.Getenv("BASE_URL")+"/rp/google",
				),
				[]byte(secret("CODE_KEY_SECRET")),
				refreshKey,
				accessTokenBuilder,
			),
			CookieKey:  []byte(secret("COOKIE_KEY_SECRET")),
			ProjectID:  os.Getenv("PROJECT_ID"),
			Repository: fmt.Sprintf("https://source.developers.google.com/p/%s/r/%s", os.Getenv("PROJECT_ID"), os.Getenv("BUILD_REPO")),
			Revision:   os.Getenv("BUILD_REV"),
			PublicKey:  rootPubKey,
		}),
	},
	))
}
