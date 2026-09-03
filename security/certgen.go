package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func main() {
	var (
		outputDir   = flag.String("out", "certs/dev", "output directory for local PKI material")
		trustDomain = flag.String("trust-domain", ztsecurity.DefaultTrustDomain, "SPIFFE-style trust domain")
		serverName  = flag.String("server-name", "coordinator.local", "coordinator certificate DNS name and common name")
		edgeNodeID  = flag.String("edge-node-id", "edge-worker-01", "development edge worker node ID")
		observerID  = flag.String("observer-node-id", "observer-01", "development observer node ID")
		issuer      = flag.String("token-issuer", "zerotrust-fl-sim", "JWT issuer")
		audience    = flag.String("token-audience", "zerotrust-fl-services", "JWT audience")
		tokenTTL    = flag.Duration("token-ttl", 24*time.Hour, "development JWT lifetime")
	)
	flag.Parse()

	artifacts, err := ztsecurity.GenerateDevelopmentPKI(ztsecurity.DevelopmentPKIConfig{
		OutputDir:   *outputDir,
		TrustDomain: *trustDomain,
		ServerName:  *serverName,
		Issuer:      *issuer,
		Audience:    *audience,
		TokenTTL:    *tokenTTL,
		Clients: []ztsecurity.DevelopmentClient{
			{NodeID: *edgeNodeID, Role: "edge-worker"},
			{NodeID: *observerID, Role: "observer"},
		},
	})
	if err != nil {
		log.Fatalf("generate development PKI: %v", err)
	}

	fmt.Printf("CA certificate: %s\n", artifacts.CACertificateFile)
	fmt.Printf("Server certificate: %s\n", artifacts.ServerCertificateFile)
	fmt.Printf("JWT verification key: %s\n", artifacts.JWTSigningPublicKeyFile)
	for nodeID, client := range artifacts.Clients {
		fmt.Printf("Client %s certificate: %s\n", nodeID, client.CertificateFile)
		fmt.Printf("Client %s token: %s\n", nodeID, client.TokenFile)
	}
}
