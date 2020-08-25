// Package observe provides functions
// that help with setting tracing/metrics
// in cloud providers, mainly GCP.
package dizmo

import (
	"io/ioutil"
	"net/http"
	"os"

	"contrib.go.opencensus.io/exporter/stackdriver"
)

// NewStackdriverExporter will return the tracing and metrics through
// the stack driver exporter, if exists in the underlying platform.
// If exporter is registered, it returns the exporter so you can register
// it and ensure to call Flush on termination.
func NewStackdriverExporter(projectID, svcName, svcVersion string) (*stackdriver.Exporter, error) {
	opts := getSDOpts(projectID, svcName, svcVersion)
	if opts == nil {
		return nil, nil
	}
	return stackdriver.NewExporter(*opts)
}

// GoogleProjectID returns the GCP Project ID that can be used to instantiate various
// GCP clients such as Stack Driver. It will attempt to fetch it from Google's
// metadata server if it's not injected into the environment by default.
func GoogleProjectID() string {
	id := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if id == "" {
		const url = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return ""
		}
		req.Header.Add("Metadata-Flavor", "Google")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return ""
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		id = string(b)
		os.Setenv("GOOGLE_CLOUD_PROJECT", id)
	}
	return id
}

// IsGAE tells you whether your program is running
// within the App Engine platform.
func IsGAE() bool {
	return os.Getenv("GAE_DEPLOYMENT_ID") != ""
}

// GetGAEInfo returns the service and the version of the
// GAE application.
func GetGAEInfo() (service, version string) {
	return os.Getenv("GAE_SERVICE"), os.Getenv("GAE_VERSION")
}

// IsCloudRun tells you whether your program is running
// within the Cloud Run platform.
func IsCloudRun() bool {
	return os.Getenv("K_CONFIGURATION") != ""
}

// GetCloudRunInfo returns the service and the version of the
// Cloud Run application.
func GetCloudRunInfo() (service, version string) {
	return os.Getenv("K_SERVICE"), os.Getenv("K_REVISION")
}

// GetServiceInfo returns the GCP Project ID,
// the service name and version (GAE or through
// SERVICE_NAME/SERVICE_VERSION env vars). Note
// that SERVICE_NAME/SERVICE_VERSION are not standard but
// your application can pass them in as variables
// to be included in your trace attributes
func GetServiceInfo() (service, version string) {
	switch {
	case IsGAE():
		return GetGAEInfo()
	case IsCloudRun():
		return GetCloudRunInfo()
	default:
		return os.Getenv("SERVICE_NAME"), os.Getenv("SERVICE_VERSION")
	}
}
