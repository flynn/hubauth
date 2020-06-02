package main

import (
	"context"
	"log"
	"net/http"
	"os"

	google_datastore "cloud.google.com/go/datastore"
	"cloud.google.com/go/errorreporting"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"contrib.go.opencensus.io/exporter/stackdriver/propagation"
	"github.com/flynn/hubauth/pkg/clog"
	"github.com/flynn/hubauth/pkg/datastore"
	"github.com/flynn/hubauth/pkg/errstack"
	"github.com/flynn/hubauth/pkg/groupsync"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
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
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(0.1)})

	ctx := context.Background()
	errClient, err := errorreporting.NewClient(ctx, os.Getenv("PROJECT_ID"), errorreporting.Config{
		ServiceName:    "hubauth-int",
		ServiceVersion: os.Getenv("BUILD_REV"),
	})
	if err != nil {
		log.Fatalf("error initializing error reporting client: %s", err)
	}

	dsClient, err := google_datastore.NewClient(ctx, os.Getenv("PROJECT_ID"))
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}
	ds := datastore.New(dsClient)
	ss := groupsync.New(ds, errClient)

	http.HandleFunc("/cron", func(w http.ResponseWriter, r *http.Request) {
		g := &errgroup.Group{}
		g.Go(func() error {
			if err := ss.Sync(r.Context()); err != nil {
				clog.Logger.Error("group sync error", zap.Error(err))
			}
			return nil
		})
		g.Go(func() error {
			ctx, span := trace.StartSpan(r.Context(), "cron.DeleteExpiredCodes")
			defer span.End()
			deleted, err := ds.DeleteExpiredCodes(ctx)
			if err != nil {
				clog.Logger.Error("delete expired codes error", zap.Error(err))
				errClient.Report(errorreporting.Entry{
					Error: err,
					Stack: errstack.Format(err),
				})
			} else if len(deleted) > 0 {
				clog.Logger.Info("deleted expired codes", zap.Strings("code_ids", deleted))
			}
			return nil
		})
		g.Go(func() error {
			ctx, span := trace.StartSpan(r.Context(), "cron.DeleteExpiredRefreshTokens")
			defer span.End()
			deleted, err := ds.DeleteExpiredRefreshTokens(ctx)
			if err != nil {
				clog.Logger.Error("delete expired refresh tokens error", zap.Error(err))
				errClient.Report(errorreporting.Entry{
					Error: err,
					Stack: errstack.Format(err),
				})
			} else if len(deleted) > 0 {
				clog.Logger.Info("deleted expired refresh tokens", zap.Strings("refresh_token_ids", deleted))
			}
			return nil
		})
		g.Wait()
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":"+httpPort, &ochttp.Handler{Propagation: &propagation.HTTPFormat{}}))
}
