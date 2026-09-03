module github.com/smshagor-dev/ZeroTrust-FL-Sim

go 1.27.1

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/prometheus/client_golang v1.24.1
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.71.0
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0
	go.opentelemetry.io/otel/sdk v1.46.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)
