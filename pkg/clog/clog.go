package clog

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger, _ = zap.Config{
	Level:    zap.NewAtomicLevelAt(zap.InfoLevel),
	Encoding: "json",
	EncoderConfig: zapcore.EncoderConfig{
		LevelKey:       "level",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
	},
	OutputPaths:      []string{"stdout"},
	ErrorOutputPaths: []string{"stdout"},
}.Build()

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
