// Package kit implements an opinionated server based on go-kit primitives.
package gizmo

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime/debug"
	"strings"

	"cloud.google.com/go/errorreporting"
	"cloud.google.com/go/profiler"
	"contrib.go.opencensus.io/exporter/stackdriver/propagation"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/pkg/errors"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// Server encapsulates all logic for registering and running a gizmo kit server.
type Server struct {
	logger   log.Logger
	logClose func() error
	ocFlush  func()
	errs     *errorreporting.Client
	mux      Router
	cfg      Config
	svc      Service
	svr      *http.Server
	gsvr     *grpc.Server
	handler  http.Handler

	// exit chan for graceful shutdown
	exit chan chan error
}

type contextKey int

const (
	// key to set/retrieve URL params from a request context.
	varsKey contextKey = iota
	// key for logger
	logKey

	// CloudTraceContextKey is a context key for storing and retrieving the
	// inbound 'x-cloud-trace-context' header. This server will automatically look for
	// and inject the value into the request context. If in the App Engine environment
	// this will be used to enable combined access and application logs.
	CloudTraceContextKey
)

// NewServer will create a new kit server for the given Service.
//
// Generally, users should only use the 'Run' function to start a server and use this
// function within tests so they may call ServeHTTP.
func NewServer(svc Service) *Server {
	var (
		ctx                 = context.Background()
		projectID           = GoogleProjectID()
		svcName, svcVersion = GetServiceInfo()
		lg, logClose        = NewLogger(ctx, projectID, svcName, svcVersion)

		ocFlush     func()
		errReporter *errorreporting.Client
	)
	if projectID != "" {
		exp, err := NewStackdriverExporter(projectID, svcName, svcVersion)
		if err == nil {
			trace.RegisterExporter(exp)
			view.RegisterExporter(exp)
			ocFlush = exp.Flush
		}

		err = profiler.Start(profiler.Config{
			ProjectID:      projectID,
			Service:        svcName,
			ServiceVersion: svcVersion,
		})
		if err != nil {
			lg.Log("message", "unable to initiate profiling client: "+err.Error())
		}

		errReporter, err = errorreporting.NewClient(ctx, projectID, errorreporting.Config{
			ServiceName:    svcName,
			ServiceVersion: svcVersion,
			OnError: func(err error) {
				lg.Log("message", "error reporting client encountered an error: "+err.Error())
			},
		})
		if err != nil {
			lg.Log("message", "unable to initiate error reporting client: "+err.Error())
		}
	}

	// initialize router
	ropts := svc.HTTPRouterOptions()
	if len(ropts) == 0 {
		// default the router if none set
		ropts = []RouterOption{RouterSelect("")}
	}
	var router Router
	for _, opt := range ropts {
		router = opt(router)
	}

	// initialize server
	s := &Server{
		cfg:      loadConfig(),
		mux:      router,
		exit:     make(chan chan error),
		logger:   lg,
		logClose: logClose,
		ocFlush:  ocFlush,
		errs:     errReporter,
	}
	s.svr = &http.Server{
		Handler: &ochttp.Handler{
			Handler:     s,
			Propagation: &propagation.HTTPFormat{},
		},
		Addr:           fmt.Sprintf("%s:%d", s.cfg.HTTPAddr, s.cfg.HTTPPort),
		MaxHeaderBytes: s.cfg.MaxHeaderBytes,
		ReadTimeout:    s.cfg.ReadTimeout,
		WriteTimeout:   s.cfg.WriteTimeout,
		IdleTimeout:    s.cfg.IdleTimeout,
	}
	s.register(svc)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// populate context with helpful keys
	ctx := httptransport.PopulateRequestContext(r.Context(), r)

	// add google trace header to use in tracing and logging
	const traceKey = "X-Cloud-Trace-Context"
	trace := r.Header.Get(traceKey)
	ctx = context.WithValue(ctx, CloudTraceContextKey, trace)

	// apply trace context to any downstream grpc services we call
	ctx = grpcmetadata.AppendToOutgoingContext(ctx, traceKey, trace)

	// add a request scoped logger to the context
	ctx = SetLogger(ctx, s.logger)

	defer func() {
		if reason := recover(); reason != nil {
			LogErrorf(ctx, "the server encountered a panic: %v: stracktrace: %s", reason, debug.Stack())

			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, http.StatusText(http.StatusInternalServerError))

			// if we have an error client, send out a report
			if s.errs != nil {
				s.errs.ReportSync(ctx, errorreporting.Entry{
					Req:   r,
					Error: fmt.Errorf("%v", reason),
					Stack: debug.Stack(),
				})
			}
		}
	}()

	s.handler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) register(svc Service) {
	s.svc = svc
	s.handler = s.svc.HTTPMiddleware(s.mux)

	const warmupPath = "/_ah/warmup"
	var (
		healthzFound bool
		warmupFound  bool
	)

	opts := svc.HTTPOptions()

	// register all endpoints with our wrappers & default decoders/encoders
	for path, epMethods := range svc.HTTPEndpoints() {
		for method, ep := range epMethods {

			// check if folks are supplying their own healthcheck
			if method == http.MethodGet && path == s.cfg.HealthCheckPath {
				healthzFound = true
			}

			// check for a GAE "warm up" request endpoint
			if method == http.MethodGet && path == warmupPath {
				warmupFound = true
			}

			// just pass the http.Request in if no decoder provided
			if ep.Decoder == nil {
				ep.Decoder = basicDecoder
			}
			// default to the httptransport helper
			if ep.Encoder == nil {
				ep.Encoder = httptransport.EncodeJSONResponse
			}
			s.mux.Handle(method, path,
				ochttp.WithRouteTag(
					httptransport.NewServer(
						svc.Middleware(ep.Endpoint),
						ep.Decoder,
						ep.Encoder,
						append(opts, ep.Options...)...), path))
		}
	}

	// register a simple health check if none provided
	if !healthzFound {
		s.mux.Handle(http.MethodGet, s.cfg.HealthCheckPath,
			ochttp.WithRouteTag(
				httptransport.NewServer(
					svc.Middleware(okEndpoint),
					basicDecoder,
					httptransport.EncodeJSONResponse,
					opts...), s.cfg.HealthCheckPath))
	}

	// register a warmup request for App Engine apps that dont have one already.
	if !warmupFound {
		s.mux.Handle(http.MethodGet, warmupPath,
			ochttp.WithRouteTag(
				httptransport.NewServer(
					svc.Middleware(okEndpoint),
					basicDecoder,
					httptransport.EncodeJSONResponse,
					opts...), warmupPath))
	}

	// add all pprof endpoints by default to HTTP
	if s.cfg.EnablePProf {
		registerPprof(s.mux)
	}

	gdesc := svc.RPCServiceDesc()
	if gdesc != nil {
		inters := []grpc.UnaryServerInterceptor{
			grpc.UnaryServerInterceptor(
				// inject logger into gRPC server and hook in go-kit middleware
				func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
					ctx = SetLogger(ctx, s.logger)
					return svc.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
						return handler(ctx, req)
					})(ctx, req)
				},
			),
		}
		if mw := svc.RPCMiddleware(); mw != nil {
			inters = append(inters, mw)
		}
		opts := append(
			svc.RPCOptions(),
			grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(inters...)),
			grpc.StatsHandler(&ocgrpc.ServerHandler{}))
		s.gsvr = grpc.NewServer(opts...)

		s.gsvr.RegisterService(gdesc, svc)
	}
}

func okEndpoint(ctx context.Context, _ interface{}) (interface{}, error) {
	return "OK", nil
}

func basicDecoder(_ context.Context, r *http.Request) (interface{}, error) {
	return r, nil
}

func (s *Server) start() error {
	go func() {
		err := s.svr.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.logger.Log(
				"error", err,
				"message", "HTTP server error - initiating shutting down")
			s.stop()
		}
	}()

	s.logger.Log("message", fmt.Sprintf("listening on HTTP %s:%d", s.cfg.HTTPAddr, s.cfg.HTTPPort))

	if s.gsvr != nil {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.RPCPort))
		if err != nil {
			return errors.Wrap(err, "failed to listen to RPC port")
		}

		go func() {
			err := s.gsvr.Serve(lis)
			if err != nil {
				// the gRPC server _always_ returns non-nil
				// this filters out the known err we don't care about logging
				if !strings.Contains(err.Error(), "use of closed network connection") {
					s.logger.Log(
						"error", err,
						"message", "gRPC server error - initiating shutting down")
					s.stop()
				}
			}
		}()
		s.logger.Log("message", fmt.Sprintf("listening on RPC port: %d", s.cfg.RPCPort))
	}

	go func() {
		exit := <-s.exit

		// stop the listener with timeout
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		defer func() {
			// flush the logger after server shuts down
			if s.logClose != nil {
				s.logClose()
			}

			// flush the stack driver exporter
			if s.ocFlush != nil {
				s.ocFlush()
			}

			if s.errs != nil {
				s.errs.Close()
			}
		}()

		if shutdown, ok := s.svc.(Shutdowner); ok {
			shutdown.Shutdown()
		}
		if s.gsvr != nil {
			s.gsvr.GracefulStop()
		}
		exit <- s.svr.Shutdown(ctx)
	}()

	return nil
}

func (s *Server) stop() error {
	ch := make(chan error)
	s.exit <- ch
	return <-ch
}

func registerPprof(mx Router) {
	mx.HandleFunc(http.MethodGet, "/debug/pprof/", pprof.Index)
	mx.HandleFunc(http.MethodGet, "/debug/pprof/cmdline", pprof.Cmdline)
	mx.HandleFunc(http.MethodGet, "/debug/pprof/profile", pprof.Profile)
	mx.HandleFunc(http.MethodGet, "/debug/pprof/symbol", pprof.Symbol)
	mx.HandleFunc(http.MethodGet, "/debug/pprof/trace", pprof.Trace)
	// Manually add support for paths linked to by index page at /debug/pprof/
	mx.Handle(http.MethodGet, "/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mx.Handle(http.MethodGet, "/debug/pprof/heap", pprof.Handler("heap"))
	mx.Handle(http.MethodGet, "/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	mx.Handle(http.MethodGet, "/debug/pprof/block", pprof.Handler("block"))
}
