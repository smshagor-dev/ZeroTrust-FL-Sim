package observability

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// Config controls coordinator telemetry endpoints.
type Config struct {
	ServiceName   string
	InstanceID    string
	MetricsAddr   string
	OTLPEndpoint  string
	OTLPInsecure  bool
}

// Runtime owns the coordinator trace provider, Prometheus registry, and metrics server.
type Runtime struct {
	provider *sdktrace.TracerProvider
	registry *prometheus.Registry
	server   *http.Server

	rpcLatency *prometheus.HistogramVec
	rpcTotal   *prometheus.CounterVec
}

// New configures tracing and starts the Prometheus endpoint when MetricsAddr is non-empty.
func New(ctx context.Context, cfg Config) (*Runtime, error) {
	if strings.TrimSpace(cfg.ServiceName) == "" {
		cfg.ServiceName = "zerotrust-fl-coordinator"
	}
	if strings.TrimSpace(cfg.InstanceID) == "" {
		cfg.InstanceID = "coordinator"
	}

	res := resource.NewWithAttributes(
		"",
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.instance.id", cfg.InstanceID),
		attribute.String("service.namespace", "zerotrust-fl-sim"),
	)

	providerOptions := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}
	if strings.TrimSpace(cfg.OTLPEndpoint) != "" {
		exporterOptions := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
		}
		if cfg.OTLPInsecure {
			exporterOptions = append(exporterOptions, otlptracegrpc.WithInsecure())
		}
		exporter, err := otlptracegrpc.New(ctx, exporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
		}
		providerOptions = append(providerOptions, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(providerOptions...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	registry := prometheus.NewRegistry()
	commonLabels := prometheus.Labels{
		"service":  cfg.ServiceName,
		"instance": cfg.InstanceID,
	}
	rpcLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:        "ztfl_grpc_server_latency_seconds",
			Help:        "Coordinator gRPC server latency in seconds.",
			ConstLabels: commonLabels,
			Buckets:     prometheus.DefBuckets,
		},
		[]string{"method", "code"},
	)
	rpcTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "ztfl_grpc_server_requests_total",
			Help:        "Coordinator gRPC requests by method and status code.",
			ConstLabels: commonLabels,
		},
		[]string{"method", "code"},
	)
	registry.MustRegister(rpcLatency, rpcTotal)

	runtime := &Runtime{
		provider:   provider,
		registry:   registry,
		rpcLatency: rpcLatency,
		rpcTotal:   rpcTotal,
	}
	if strings.TrimSpace(cfg.MetricsAddr) != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		runtime.server = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			_ = runtime.server.ListenAndServe()
		}()
	}
	return runtime, nil
}

// GRPCStatsHandler instruments server spans and distributed trace context propagation.
func (r *Runtime) GRPCStatsHandler() stats.Handler {
	return otelgrpc.NewServerHandler()
}

// UnaryServerInterceptor records Prometheus request counts and latency.
func (r *Runtime) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		started := time.Now()
		response, err := handler(ctx, req)
		code := status.Code(err)
		if err == nil {
			code = codes.OK
		}
		codeLabel := code.String()
		r.rpcTotal.WithLabelValues(info.FullMethod, codeLabel).Inc()
		r.rpcLatency.WithLabelValues(info.FullMethod, codeLabel).Observe(time.Since(started).Seconds())
		return response, err
	}
}

// Shutdown flushes traces and stops the metrics HTTP server.
func (r *Runtime) Shutdown(ctx context.Context) error {
	var shutdownErrors []error
	if r.server != nil {
		if err := r.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if r.provider != nil {
		if err := r.provider.Shutdown(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	return errors.Join(shutdownErrors...)
}
