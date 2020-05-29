package main

import (
	"context"
	"log"
	"net/http"
	"os"

	google_datastore "cloud.google.com/go/datastore"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"contrib.go.opencensus.io/exporter/stackdriver/propagation"
	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/groupsync"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
)

func main() {
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8000"
	}

	exporter, err := stackdriver.NewExporter(stackdriver.Options{})
	if err != nil {
		log.Fatal(err)
	}
	trace.RegisterExporter(exporter)
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	dsClient, err := google_datastore.NewClient(context.Background(), os.Getenv("PROJECT_ID"))
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}
	ss := groupsync.New(datastore.New(dsClient))

	http.Handle("/cron", ochttp.WithRouteTag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := ss.Sync(r.Context()); err != nil {
			clog.Logger.Error("sync error", zap.Error(err))
		}
		w.WriteHeader(http.StatusOK)
	}), "/cron"))

	log.Fatal(http.ListenAndServe(":"+httpPort, &ochttp.Handler{Propagation: &propagation.HTTPFormat{}}))
}
