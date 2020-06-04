package clog

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/flynn/hubauth/pkg/errsource"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger, _ = zap.Config{
	Level:    zap.NewAtomicLevelAt(zap.InfoLevel),
	Encoding: "json",
	EncoderConfig: zapcore.EncoderConfig{
		LevelKey:       "severity",
		MessageKey:     "message",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    googleLevelEncoder,
		EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
		EncodeDuration: millisDurationEncoder,
	},
	OutputPaths:      []string{"stdout"},
	ErrorOutputPaths: []string{"stdout"},
}.Build()

func millisDurationEncoder(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendFloat64(float64(d) / float64(time.Millisecond))
}

func googleLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var s string
	switch l {
	case zapcore.DebugLevel:
		s = "DEBUG"
	case zapcore.InfoLevel:
		s = "INFO"
	case zapcore.WarnLevel:
		s = "WARNING"
	case zapcore.ErrorLevel:
		s = "ERROR"
	case zapcore.DPanicLevel:
		s = "CRITICAL"
	case zapcore.PanicLevel:
		s = "ALERT"
	case zapcore.FatalLevel:
		s = "EMERGENCY"
	default:
		s = "DEFAULT"
	}
	enc.AppendString(s)
}

type ctxKey struct{}

type ctxValue struct {
	fields []zap.Field
	sync.Mutex
}

func Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxValue{})
}

func Set(ctx context.Context, f ...zap.Field) {
	ctxVal := ctx.Value(ctxKey{}).(*ctxValue)
	ctxVal.Lock()
	ctxVal.fields = append(ctxVal.fields, f...)
	ctxVal.Unlock()
}

func Log(ctx context.Context, msg string) {
	ctxVal := ctx.Value(ctxKey{}).(*ctxValue)
	ctxVal.Lock()
	Logger.Info(msg, ctxVal.fields...)
	ctxVal.fields = ctxVal.fields[:0]
	ctxVal.Unlock()
}

type ErrInfo struct {
	Request      *http.Request
	ResponseCode int
	Repository   string
	Revision     string
}

func Error(ctx context.Context, err error, info *ErrInfo) {
	ctxVal := ctx.Value(ctxKey{}).(*ctxValue)
	ctxVal.Lock()
	defer ctxVal.Unlock()
	ErrorWithLogger(Logger, err, info, ctxVal.fields...)
	ctxVal.fields = ctxVal.fields[:0]
}

func ErrorWithLogger(l *zap.Logger, err error, info *ErrInfo, fields ...zap.Field) {
	context := make(map[string]interface{})
	if info != nil && info.Request != nil {
		req := make(map[string]interface{})
		context["httpRequest"] = req
		req["method"] = info.Request.Method
		req["url"] = info.Request.URL.String()
		if ua := info.Request.Header.Get("User-Agent"); ua != "" {
			req["userAgent"] = ua
		}
		if r := info.Request.Header.Get("Referer"); r != "" {
			req["referrer"] = r
		}
		if info.ResponseCode > 0 {
			req["responseStatusCode"] = info.ResponseCode
		}
		if xff := info.Request.Header.Get("X-Forwarded-For"); xff != "" {
			req["remoteIp"] = xff
		}
	}

	frame := errsource.Source(err)
	if frame == nil {
		var f [3]uintptr
		runtime.Callers(1, f[:])
		frames := runtime.CallersFrames(f[:])
		if _, ok := frames.Next(); ok {
			f, _ := frames.Next()
			frame = &f
		}
	}
	context["reportLocation"] = map[string]interface{}{
		"filePath":     strings.TrimPrefix(frame.File, "/app/"),
		"lineNumber":   frame.Line,
		"functionName": frame.Function,
	}

	if info != nil && info.Revision != "" && info.Repository != "" {
		context["sourceReferences"] = []map[string]interface{}{{
			"repository": info.Repository,
			"revisionId": info.Revision,
		}}
	}

	fields = append(fields,
		zap.String("@type", "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent"),
		zap.Reflect("context", context),
	)

	l.Error(err.Error(), fields...)
}
