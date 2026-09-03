package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const defaultMaxMessageBytes = 64 << 20

type TokenSource func(context.Context) (string, error)

type Config struct {
	Address         string
	TLS             ztsecurity.ClientTLSOptions
	Token           string
	TokenSource     TokenSource
	MaxMessageBytes int
}

type Client struct {
	Connection  *grpc.ClientConn
	Coordinator flv1.CoordinatorServiceClient
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, errors.New("coordinator address is required")
	}
	if cfg.TokenSource == nil && strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("bearer token or token source is required")
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = defaultMaxMessageBytes
	}

	creds, err := ztsecurity.ClientTransportCredentials(cfg.TLS)
	if err != nil {
		return nil, err
	}

	tokenSource := cfg.TokenSource
	if tokenSource == nil {
		staticToken := strings.TrimSpace(cfg.Token)
		tokenSource = func(context.Context) (string, error) { return staticToken, nil }
	}

	conn, err := grpc.NewClient(
		cfg.Address,
		grpc.WithTransportCredentials(creds),
		grpc.WithChainUnaryInterceptor(bearerUnaryClientInterceptor(tokenSource)),
		grpc.WithChainStreamInterceptor(bearerStreamClientInterceptor(tokenSource)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(cfg.MaxMessageBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create coordinator gRPC client: %w", err)
	}

	return &Client{
		Connection:  conn,
		Coordinator: flv1.NewCoordinatorServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.Connection == nil {
		return nil
	}
	return c.Connection.Close()
}

func bearerUnaryClientInterceptor(source TokenSource) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		authorizedContext, err := contextWithBearerToken(ctx, source)
		if err != nil {
			return err
		}
		return invoker(authorizedContext, method, req, reply, cc, opts...)
	}
}

func bearerStreamClientInterceptor(source TokenSource) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		authorizedContext, err := contextWithBearerToken(ctx, source)
		if err != nil {
			return nil, err
		}
		return streamer(authorizedContext, desc, cc, method, opts...)
	}
}

func contextWithBearerToken(ctx context.Context, source TokenSource) (context.Context, error) {
	token, err := source(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain bearer token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("bearer token is empty")
	}

	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(ctx, md), nil
}
