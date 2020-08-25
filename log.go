package gizmo

import (
	"context"
	"fmt"
	stdlog "log"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-kit/kit/transport/http"
	"google.golang.org/grpc/metadata"
)

// NewLogger will inspect the environment and, if running in the Google App Engine,
// Google Kubernetes Engine, Google Compute Engine or AWS EC2 environment,
// it will return a new Stackdriver logger annotated with the current
// server's project ID, service ID and version and other environment specific values.
// If not in App Engine, GKE, GCE or AWS EC2 - a normal JSON logger pointing to stdout
// will be returned.
// This function can be used for services that need to log information outside the
// context of an inbound request.
// When using the Stackdriver logger, any go-kit/log/levels will be translated to
// Stackdriver severity levels.
// The logID field is used when the server is deployed in a Stackdriver enabled environment.
// If an empty string is provided, "gae_log" will be used in App Engine and "stdout" elsewhere.
// For more information about to use of logID see the documentation here: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#FIELDS.log_name
// To speed up start up time in non-GCP enabled environments, this function also checks
// the if projectID is empty and will use a basic JSON logger writing to stdout if not set.
func NewLogger(ctx context.Context, projectID, serviceID, svcVersion string) (log.Logger, func() error) {
	if projectID == "" {
		// this isn't a GCP environment, just use a stdlib logger
		return sdtlibLogger{}, func() error { return nil }
	}

	lg, cl, err := newStackdriverLogger(ctx, projectID, serviceID, svcVersion)
	if err != nil {
		lg = newJSONLogger()
		cl = func() error { return nil }
		lg.Log("error", err,
			"message", "unable to initialize Stackdriver logger, falling back to stdout JSON logging.")
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

func newJSONLogger() log.Logger {
	return log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
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

// LogDebugf will format the given string with the arguments then log to the server
// logger with the key "message" along with all the common request headers or gRPC
// metadata.
// Arguments are handled in the manner of fmt.Printf.
// This message will have a "debug" log level associated with it.
func LogDebugf(ctx context.Context, format string, v ...interface{}) error {
	return level.Debug(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}

// LogInfof will format the given string with the arguments then log to the server
// logger with the key "message" along with all the common request headers or gRPC
// metadata.
// Arguments are handled in the manner of fmt.Printf.
// This message will have an "info" log level associated with it.
func LogInfof(ctx context.Context, format string, v ...interface{}) error {
	return level.Info(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}

// LogWarningf will the format given string with the arguments then log to the server
// logger with the key "message" along with all the common request headers or gRPC
// metadata.
// Arguments are handled in the manner of fmt.Printf.
// This message will have a "warn" log level associated with it.
func LogWarningf(ctx context.Context, format string, v ...interface{}) error {
	return level.Warn(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}

// LogErrorf will format the given string with the arguments then log to the server
// logger with the key "message" along with all the common request headers or gRPC
// metadata.
// Arguments are handled in the manner of fmt.Printf.
// This message will have an "error" log level associated with it.
func LogErrorf(ctx context.Context, format string, v ...interface{}) error {
	return level.Error(Logger(ctx)).Log("message", fmt.Sprintf(format, v...))
}
