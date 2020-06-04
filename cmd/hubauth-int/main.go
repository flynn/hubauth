package main

import (
	"context"
	"fmt"
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

	dsClient, err := google_datastore.NewClient(context.Background(), os.Getenv("PROJECT_ID"))
	if err != nil {
		log.Fatalf("error initializing datastore client: %s", err)
	}
	ds := datastore.New(dsClient)

	errInfo := &clog.ErrInfo{
		Repository: fmt.Sprintf("https://source.developers.google.com/p/%s/r/%s", os.Getenv("PROJECT_ID"), os.Getenv("BUILD_REPO")),
		Revision:   os.Getenv("BUILD_REV"),
	}
	ss := groupsync.New(ds, errInfo)

	http.HandleFunc("/cron", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		g := &errgroup.Group{}
		g.Go(func() error {
			if err := ss.Sync(ctx); err != nil {
				clog.ErrorWithLogger(clog.Logger, err, errInfo)
			}
			return nil
		})
		g.Go(func() error {
			deleted, err := ds.DeleteExpiredCodes(ctx)
			if err != nil {
				clog.ErrorWithLogger(clog.Logger, err, errInfo)
			} else if len(deleted) > 0 {
				clog.Logger.Info("deleted expired codes", zap.Strings("code_ids", deleted))
			}
			return nil
		})
		g.Go(func() error {
			deleted, err := ds.DeleteExpiredRefreshTokens(ctx)
			if err != nil {
				clog.ErrorWithLogger(clog.Logger, err, errInfo)
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
