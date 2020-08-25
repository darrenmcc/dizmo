package dizmo

import (
	"context"
	"fmt"
	stdlog "log"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-kit/kit/transport/http"
	"google.golang.org/grpc/metadata"
)

func NewLogger(ctx context.Context, projectID, serviceID, svcVersion string) (log.Logger, func() error) {
	if projectID == "" {
		// this isn't a GCP environment, just use a stdlib logger
		return sdtlibLogger{}, func() error { return nil }
	}

	lg, cl, err := newStackdriverLogger(ctx, projectID, serviceID, svcVersion)
	if err != nil {
		return sdtlibLogger{}, func() error { return nil }
	}
	return lg, cl
}

type sdtlibLogger struct{}

func (sdtlibLogger) Log(keyvals ...interface{}) error {
	for i := 0; i < len(keyvals); i++ {
		s, ok := keyvals[i].(string)
		if !ok {
			continue
		}
		switch s {
		case "message", "error", "stacktrace":
			if i < len(keyvals)-1 {
				stdlog.Println(keyvals[i+1])
			}
		}
	}
	return nil
}

// SetLogger sets log.Logger to the context and returns new context with logger.
func SetLogger(ctx context.Context, l log.Logger) context.Context {
	return context.WithValue(ctx, logKey, addLogKeyVals(ctx, l))
}

// Logger will return a kit/log.Logger that has been injected into the context by the kit
// server. This logger has had request headers and metadata added as key values.
// This function will only work within the scope of a request initiated by the server.
func Logger(ctx context.Context) log.Logger {
	return ctx.Value(logKey).(log.Logger)
}

// addLogKeyVals will add any common HTTP headers or gRPC metadata
// from the given context to the given logger as fields.
// This is used by the server to initialize the request scoped logger.
func addLogKeyVals(ctx context.Context, l log.Logger) log.Logger {
	// for HTTP requests
	keys := map[interface{}]string{
		http.ContextKeyRequestMethod:        "http-method",
		http.ContextKeyRequestURI:           "http-uri",
		http.ContextKeyRequestPath:          "http-path",
		http.ContextKeyRequestHost:          "http-host",
		http.ContextKeyRequestXRequestID:    "http-x-request-id",
		http.ContextKeyRequestRemoteAddr:    "http-remote-addr",
		http.ContextKeyRequestXForwardedFor: "http-x-forwarded-for",
		http.ContextKeyRequestUserAgent:     "http-user-agent",
		CloudTraceContextKey:                cloudTraceLogKey,
	}
	for k, v := range keys {
		if val, ok := ctx.Value(k).(string); ok && val != "" {
			l = log.With(l, v, val)
		}
	}
	// for gRPC requests
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for k, v := range md {
			l = log.With(l, k, v)
		}
	}

	return l
}

func Debugf(ctx context.Context, format string, v ...interface{}) error {
	return level.Debug(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}
func Infof(ctx context.Context, format string, v ...interface{}) error {
	return level.Info(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}
func Warningf(ctx context.Context, format string, v ...interface{}) error {
	return level.Warn(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}
func Errorf(ctx context.Context, format string, v ...interface{}) error {
	return level.Error(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}
