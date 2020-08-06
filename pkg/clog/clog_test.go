package clog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type MemorySink struct {
	*bytes.Buffer
}

func (s *MemorySink) Close() error { return nil }
func (s *MemorySink) Sync() error  { return nil }

var globalSink = &MemorySink{new(bytes.Buffer)}

func init() {
	zap.RegisterSink("globalSink", func(*url.URL) (zap.Sink, error) {
		return globalSink, nil
	})

	cfg.OutputPaths = []string{"globalSink://"}
	var err error
	Logger, err = cfg.Build()
	if err != nil {
		panic(err)
	}
}

func newTestLogger(t *testing.T) (*zap.Logger, *MemorySink) {
	sink := &MemorySink{new(bytes.Buffer)}
	zap.RegisterSink("localSink", func(*url.URL) (zap.Sink, error) {
		return sink, nil
	})

	c := cfg
	c.OutputPaths = []string{"localSink://"}
	c.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

	logger, err := c.Build()
	require.NoError(t, err)

	return logger, sink
}

func TestErrorWithLogger(t *testing.T) {
	logger, sink := newTestLogger(t)

	loggedErr := errors.New("expected error")
	info := &ErrInfo{
		Request: &http.Request{
			URL:    &url.URL{Host: "host", Path: "/path"},
			Method: http.MethodPatch,
			Header: http.Header{
				"User-Agent":      {"userAgent"},
				"Referer":         {"referer"},
				"X-Forwarded-For": {"remoteIP"},
			},
		},
		ResponseCode: http.StatusBadRequest,
		Repository:   "repository",
		Revision:     "revision",
	}

	fields := []zapcore.Field{
		zap.Int64("field1", 42),
		zap.String("field2", "str"),
	}

	ErrorWithLogger(logger, loggedErr, info, fields...)
	_, filename, line, _ := runtime.Caller(0)

	assertEqualOutput(t, fmt.Sprintf(`{
		"severity":"ERROR",
		"message":"expected error",
		"field1":42,
		"field2":"str",
		"@type":"type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent",
		"context":{
			"httpRequest":{
				"method":"PATCH",
				"referrer":"referer",
				"remoteIp":"remoteIP",
				"responseStatusCode":400,
				"url":"//host/path",
				"userAgent":"userAgent"
			},
			"reportLocation":{
				"filePath":"%s",
				"functionName":"github.com/flynn/hubauth/pkg/clog.TestErrorWithLogger",
				"lineNumber":%d
			},
			"sourceReferences":[
				{"repository":"repository","revisionId":"revision"}
			]
		}
	}`, strings.TrimPrefix(filename, "/app/"), line-1), sink)

}

func assertEqualOutput(t *testing.T, s string, sink *MemorySink) {
	expectedOut := new(bytes.Buffer)
	require.NoError(t, json.Compact(expectedOut, []byte(s)))
	expectedOut.WriteByte('\n')

	require.Equal(t, expectedOut.String(), sink.String())
	sink.Truncate(0)
}

func TestError(t *testing.T) {
	ctx := Context(context.Background())

	fields := []zapcore.Field{
		zap.Int64("field1", 42),
		zap.String("field2", "str"),
	}
	Set(ctx, fields...)

	loggedErr := errors.New("logged error")
	info := &ErrInfo{
		ResponseCode: http.StatusInternalServerError,
		Repository:   "repository",
		Revision:     "revision",
	}

	Error(ctx, loggedErr, info)
	_, filename, line, _ := runtime.Caller(0)

	assertEqualOutput(t, fmt.Sprintf(`{
		"severity":"ERROR",
		"message":"logged error",
		"field1":42,
		"field2":"str",
		"@type":"type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent",
		"context":{
			"reportLocation":{
				"filePath":"%s",
				"functionName":"github.com/flynn/hubauth/pkg/clog.TestError",
				"lineNumber":%d
			},
			"sourceReferences":[
				{"repository":"repository","revisionId":"revision"}
			]
		}
	}`, strings.TrimPrefix(filename, "/app/"), line-1), globalSink)
}

func TestLog(t *testing.T) {
	ctx := Context(context.Background())

	fields := []zapcore.Field{
		zap.Int64("field1", 42),
		zap.String("field2", "str"),
	}
	Set(ctx, fields...)

	msg := "logged msg"
	Log(ctx, msg)

	assertEqualOutput(t, `{
		"severity":"INFO",
		"message":"logged msg",
		"field1":42,
		"field2":"str"
	}`, globalSink)
}

type mockEncoder struct {
	mock.Mock
	zapcore.PrimitiveArrayEncoder
}

func (m *mockEncoder) AppendString(s string) {
	m.Called(s)
}
func TestGoogleLevelEncoder(t *testing.T) {
	testCases := []struct {
		ExpectedLevel string
		Level         zapcore.Level
	}{
		{
			Level:         zapcore.DebugLevel,
			ExpectedLevel: "DEBUG",
		},
		{
			Level:         zapcore.InfoLevel,
			ExpectedLevel: "INFO",
		},
		{
			Level:         zapcore.WarnLevel,
			ExpectedLevel: "WARNING",
		},
		{
			Level:         zapcore.ErrorLevel,
			ExpectedLevel: "ERROR",
		},
		{
			Level:         zapcore.DPanicLevel,
			ExpectedLevel: "CRITICAL",
		},
		{
			Level:         zapcore.PanicLevel,
			ExpectedLevel: "ALERT",
		},
		{
			Level:         zapcore.FatalLevel,
			ExpectedLevel: "EMERGENCY",
		},
		{
			Level:         zapcore.FatalLevel + 1,
			ExpectedLevel: "DEFAULT",
		},
	}

	for _, testCase := range testCases {
		mockEnc := &mockEncoder{}
		mockEnc.On("AppendString", testCase.ExpectedLevel)
		googleLevelEncoder(testCase.Level, mockEnc)
		require.True(t, mock.AssertExpectationsForObjects(t, mockEnc))
	}
}
