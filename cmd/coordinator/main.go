package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/observability"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	var (
		listenAddress       = flag.String("listen", envString("ZTFL_LISTEN_ADDRESS", "127.0.0.1:50051"), "TCP address for the coordinator gRPC server")
		serverCert          = flag.String("server-cert", envString("ZTFL_SERVER_CERT", "certs/dev/server.crt"), "server certificate file")
		serverKey           = flag.String("server-key", envString("ZTFL_SERVER_KEY", "certs/dev/server.key"), "server private key file")
		clientCA            = flag.String("client-ca", envString("ZTFL_CLIENT_CA", "certs/dev/ca.crt"), "CA certificate used to verify client certificates")
		jwtPublicKey        = flag.String("jwt-public-key", envString("ZTFL_JWT_PUBLIC_KEY", "certs/dev/jwt_signing_public.pem"), "Ed25519 JWT verification key")
		trustDomain         = flag.String("trust-domain", envString("ZTFL_TRUST_DOMAIN", ztsecurity.DefaultTrustDomain), "certificate URI SAN trust domain")
		tokenIssuer         = flag.String("token-issuer", envString("ZTFL_TOKEN_ISSUER", "zerotrust-fl-sim"), "required JWT issuer")
		tokenAudience       = flag.String("token-audience", envString("ZTFL_TOKEN_AUDIENCE", "zerotrust-fl-services"), "required JWT audience")
		leaseTTL            = flag.Duration("registration-lease", envDuration("ZTFL_REGISTRATION_LEASE", 5*time.Minute), "node registration lease")
		maxMessage          = flag.Int("max-message-bytes", envInt("ZTFL_MAX_MESSAGE_BYTES", 8<<20), "maximum gRPC request and response size")
		minUpdates          = flag.Int("min-updates", envInt("ZTFL_MIN_UPDATES", 1), "minimum unique worker updates required before advancing a round")
		maxUpdatesPerMinute = flag.Int("max-updates-per-minute", envInt("ZTFL_MAX_UPDATES_PER_MINUTE", 60), "per-worker SubmitLocalUpdate rate limit")
		aggregationMethod   = flag.String("aggregation-method", envString("ZTFL_AGGREGATION_METHOD", "median"), "network aggregation method: median or weighted_mean")
		stateFile           = flag.String("state-file", envString("ZTFL_STATE_FILE", ""), "atomic coordinator state snapshot file; empty keeps volatile state")
		pqcModeValue        = flag.String("pqc-mode", envString("ZTFL_PQC_MODE", "prefer"), "post-quantum TLS key-exchange policy: off, prefer, or require")
		requirePQCIdentity  = flag.Bool("pqc-require-identity", envBool("ZTFL_PQC_REQUIRE_IDENTITY", false), "require ML-DSA peer and local X.509 identities")
		metricsAddress      = flag.String("metrics-address", envString("ZTFL_METRICS_ADDRESS", "127.0.0.1:9464"), "Prometheus metrics listen address; empty disables the endpoint")
		otelEndpoint        = flag.String("otel-endpoint", envString("ZTFL_OTEL_ENDPOINT", ""), "OTLP/gRPC trace collector endpoint; empty disables trace export")
		otelInsecure        = flag.Bool("otel-insecure", envBool("ZTFL_OTEL_INSECURE", false), "use plaintext OTLP/gRPC only for an explicitly trusted local collector")
		telemetryInstance   = flag.String("telemetry-instance", envString("ZTFL_TELEMETRY_INSTANCE", "coordinator"), "OpenTelemetry/Prometheus instance identifier")
	)
	flag.Parse()

	if *minUpdates <= 0 {
		fmt.Fprintln(os.Stderr, "min-updates must be positive")
		os.Exit(2)
	}
	if *maxUpdatesPerMinute <= 0 {
		fmt.Fprintln(os.Stderr, "max-updates-per-minute must be positive")
		os.Exit(2)
	}

	pqcMode, err := ztsecurity.ParsePQCMode(*pqcModeValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid PQC mode: %v\n", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	telemetry, err := observability.New(context.Background(), observability.Config{
		ServiceName:  "zerotrust-fl-coordinator",
		InstanceID:   *telemetryInstance,
		MetricsAddr:  *metricsAddress,
		OTLPEndpoint: *otelEndpoint,
		OTLPInsecure: *otelInsecure,
	})
	if err != nil {
		logger.Error("configure observability", "error", err)
		os.Exit(1)
	}

	transportCreds, err := ztsecurity.ServerTransportCredentials(ztsecurity.ServerTLSOptions{
		CertificateFile:    *serverCert,
		PrivateKeyFile:     *serverKey,
		ClientCAFile:       *clientCA,
		TrustDomain:        *trustDomain,
		AllowedClientRoles: []string{"edge-worker", "observer", "admin"},
		PQCMode:            pqcMode,
		RequirePQCIdentity: *requirePQCIdentity,
	})
	if err != nil {
		logger.Error("configure mutual TLS", "error", err)
		os.Exit(1)
	}

	verifier, err := ztsecurity.NewTokenVerifierFromPEMFile(*jwtPublicKey, *tokenIssuer, *tokenAudience, 15*time.Second)
	if err != nil {
		logger.Error("configure JWT verifier", "error", err)
		os.Exit(1)
	}

	registry := ztsecurity.NewRegistrationStore()
	authorizer, err := ztsecurity.NewAuthorizer(*trustDomain, verifier, registry)
	if err != nil {
		logger.Error("configure authorization middleware", "error", err)
		os.Exit(1)
	}

	serviceConfig := coordinator.Config{
		LeaseTTL:            *leaseTTL,
		MaxUpdateBytes:      *maxMessage,
		MinUpdates:          *minUpdates,
		MaxUpdatesPerMinute: *maxUpdatesPerMinute,
		AggregationMethod:   *aggregationMethod,
	}
	var service flv1.CoordinatorServiceServer
	durableStateEnabled := *stateFile != ""
	if durableStateEnabled {
		stateStore, err := coordinator.NewFileStateStore(*stateFile)
		if err != nil {
			logger.Error("configure coordinator state store", "error", err)
			os.Exit(1)
		}
		service, err = coordinator.NewDurableService(registry, serviceConfig, stateStore)
		if err != nil {
			logger.Error("recover durable coordinator state", "error", err)
			os.Exit(1)
		}
	} else {
		service, err = coordinator.NewService(registry, serviceConfig)
		if err != nil {
			logger.Error("configure coordinator service", "error", err)
			os.Exit(1)
		}
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(transportCreds),
		grpc.StatsHandler(telemetry.GRPCStatsHandler()),
		grpc.ChainUnaryInterceptor(
			telemetry.UnaryServerInterceptor(),
			authorizer.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(authorizer.StreamServerInterceptor()),
		grpc.MaxRecvMsgSize(*maxMessage),
		grpc.MaxSendMsgSize(*maxMessage),
		grpc.MaxConcurrentStreams(256),
		grpc.ConnectionTimeout(10*time.Second),
	)
	flv1.RegisterCoordinatorServiceServer(grpcServer, service)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("zerotrust.fl.v1.CoordinatorService", healthpb.HealthCheckResponse_SERVING)

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		logger.Error("listen for coordinator connections", "address", *listenAddress, "error", err)
		os.Exit(1)
	}

	serveErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"coordinator listening",
			"address", listener.Addr().String(),
			"tls", "1.3",
			"mtls", true,
			"pqc_key_exchange", string(pqcMode),
			"pqc_identity_required", *requirePQCIdentity,
			"metrics_address", *metricsAddress,
			"otel_endpoint", *otelEndpoint,
			"min_updates", *minUpdates,
			"max_updates_per_minute", *maxUpdatesPerMinute,
			"aggregation_method", *aggregationMethod,
			"durable_state", durableStateEnabled,
		)
		serveErrors <- grpcServer.Serve(listener)
	}()

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErrors:
		if err != nil {
			logger.Error("gRPC server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-signalContext.Done():
		logger.Info("shutting down coordinator")
	}

	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthServer.SetServingStatus("zerotrust.fl.v1.CoordinatorService", healthpb.HealthCheckResponse_NOT_SERVING)

	gracefulDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(gracefulDone)
	}()

	select {
	case <-gracefulDone:
		logger.Info("coordinator stopped")
	case <-time.After(10 * time.Second):
		logger.Warn("graceful shutdown timed out; forcing stop")
		grpcServer.Stop()
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := telemetry.Shutdown(shutdownContext); err != nil {
		logger.Warn("telemetry shutdown returned an error", "error", err)
	}
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		panic(fmt.Sprintf("invalid %s duration %q: %v", name, value, err))
	}
	return parsed
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("invalid %s integer %q: %v", name, value, err))
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		panic(fmt.Sprintf("invalid %s boolean %q: %v", name, value, err))
	}
	return parsed
}
