package dizmo

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"cloud.google.com/go/logging"
	trace "cloud.google.com/go/trace/apiv2"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"contrib.go.opencensus.io/exporter/stackdriver/monitoredresource"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/api/monitoredres"
)

type sdLogger struct {
	project string
	monRes  *monitoredres.MonitoredResource
	lc      *logging.Client
	lgr     *logging.Logger
}

// getSDOpts returns Stack Driver Options that you can pass directly
// to the OpenCensus exporter or other libraries.
func getSDOpts(projectID, service, version string) *stackdriver.Options {
	var mr monitoredresource.Interface
	if !IsGAE() && !IsCloudRun() {
		mr = monitoredresource.Autodetect()
		if mr == nil {
			// no valid monitored resource available
			// likely because we're running locally
			return nil
		}
	}

	// this is so that you can export views from your local server up to SD if you wish
	creds, err := google.FindDefaultCredentials(context.Background(), trace.DefaultAuthScopes()...)
	if err != nil {
		return nil
	}

	return &stackdriver.Options{
		ProjectID:         projectID,
		MonitoredResource: mr,
		MonitoringClientOptions: []option.ClientOption{
			option.WithCredentials(creds),
		},
		TraceClientOptions: []option.ClientOption{
			option.WithCredentials(creds),
		},
		DefaultTraceAttributes: map[string]interface{}{
			"service": service,
			"version": version,
		},
	}
}

func newStackdriverLogger(ctx context.Context, projectID, service, version string) (log.Logger, func() error, error) {
	resource := monitoredres.MonitoredResource{}
	logID := "stdout"

	if IsGAE() {
		resource.Type = "gae_app"
		logID = "app_logs"
		resource.Labels = map[string]string{
			"module_id":  service,
			"project_id": projectID,
			"version_id": version,
		}
	} else if IsCloudRun() {
		resource.Type = "cloud_run_revision"
		resource.Labels = map[string]string{
			"service_name":       service,
			"configuration_name": service, // configuration is seemingly always the same as service
			"revision_name":      version,
		}
	} else if mr := monitoredresource.Autodetect(); mr != nil {
		resource.Type, resource.Labels = mr.MonitoredResource()
	} else {
		return nil, nil, errors.New("unable to find monitored resource")
	}

	client, err := logging.NewClient(ctx, fmt.Sprintf("projects/%s", projectID))
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to initiate stackdriver log client")
	}

	return sdLogger{
		lc:      client,
		lgr:     client.Logger(logID),
		project: projectID,
		monRes:  &resource,
	}, client.Close, nil
}

func (l sdLogger) Log(keyvals ...interface{}) error {
	kvs, lvl, traceContext := logKeyValsToMap(keyvals...)
	var traceID string
	if traceContext != "" {
		traceID = l.getTraceID(traceContext)
	}

	svrty := logging.Default
	switch lvl {
	case level.DebugValue():
		svrty = logging.Debug
	case level.ErrorValue():
		svrty = logging.Error
	case level.InfoValue():
		svrty = logging.Info
	case level.WarnValue():
		svrty = logging.Warning
	}

	payload, err := json.Marshal(kvs)
	if err != nil {
		return err
	}

	l.lgr.Log(logging.Entry{
		Severity: svrty,
		Payload:  json.RawMessage(payload),
		Trace:    traceID,
		Resource: l.monRes,
	})
	return nil
}

func (l sdLogger) getTraceID(traceCtx string) string {
	return "projects/" + l.project + "/traces/" + strings.Split(traceCtx, "/")[0]
}

const cloudTraceLogKey = "cloud-trace"

///////////////////////////////////////////////////
// below funcs are straight up copied out of go-kit/kit/log:
// https://github.com/go-kit/kit/blob/master/log/json_logger.go
// we needed the magic for keyvals => map[string]interface{} but we're doing the
// writing the JSON ourselves
///////////////////////////////////////////////////

func logKeyValsToMap(keyvals ...interface{}) (map[string]interface{}, level.Value, string) {
	var (
		lvl          level.Value
		traceContext string
	)
	n := (len(keyvals) + 1) / 2 // +1 to handle case when len is odd
	m := make(map[string]interface{}, n)
	for i := 0; i < len(keyvals); i += 2 {
		k := keyvals[i]
		var v interface{} = log.ErrMissingValue
		if i+1 < len(keyvals) {
			v = keyvals[i+1]
		}
		merge(m, k, v)
		if k == cloudTraceLogKey {
			traceContext = v.(string)
		}
		if k == level.Key() {
			lvl = v.(level.Value)
		}
	}
	message := m["message"]

	if message != "" {
		if host, ok := m["http-host"].(string); ok && host != "" {
			m["message"] = fmt.Sprintf("[%s] %s", host, message)
		} else if hosts, ok := m[":authority"].([]string); ok && len(hosts) > 0 {
			m["message"] = fmt.Sprintf("[%s] %s", hosts[0], message)
		}
	}
	return m, lvl, traceContext
}

func merge(dst map[string]interface{}, k, v interface{}) {
	var key string
	switch x := k.(type) {
	case string:
		key = x
	case fmt.Stringer:
		key = safeString(x)
	default:
		key = fmt.Sprint(x)
	}

	// We want json.Marshaler and encoding.TextMarshaller to take priority over
	// err.Error() and v.String(). But json.Marshal (called later) does that by
	// default so we force a no-op if it's one of those 2 case.
	switch x := v.(type) {
	case json.Marshaler:
	case encoding.TextMarshaler:
	case error:
		v = safeError(x)
	case fmt.Stringer:
		v = safeString(x)
	}

	dst[key] = v
}

func safeString(str fmt.Stringer) (s string) {
	defer func() {
		if panicVal := recover(); panicVal != nil {
			if v := reflect.ValueOf(str); v.Kind() == reflect.Ptr && v.IsNil() {
				s = "NULL"
			} else {
				panic(panicVal)
			}
		}
	}()
	s = str.String()
	return
}

func safeError(err error) (s interface{}) {
	defer func() {
		if panicVal := recover(); panicVal != nil {
			if v := reflect.ValueOf(err); v.Kind() == reflect.Ptr && v.IsNil() {
				s = nil
			} else {
				panic(panicVal)
			}
		}
	}()
	s = err.Error()
	return
}
