package clog

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

var Logger, _ = zap.NewProduction()

type ctxKey struct{}

type ctxValue struct {
	fields []zap.Field
	sync.Mutex
}

func Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxValue{})
}

func Set(ctx context.Context, f zap.Field) {
	ctxVal := ctx.Value(ctxKey{}).(*ctxValue)
	ctxVal.Lock()
	ctxVal.fields = append(ctxVal.fields, f)
	ctxVal.Unlock()
}

func Log(ctx context.Context, msg string) {
	ctxVal := ctx.Value(ctxKey{}).(*ctxValue)
	ctxVal.Lock()
	Logger.Info(msg, ctxVal.fields...)
	ctxVal.fields = ctxVal.fields[:0]
	ctxVal.Unlock()
}
