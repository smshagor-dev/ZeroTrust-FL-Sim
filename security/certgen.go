package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
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
		clients     = flag.String("clients", "", "comma-separated node=role identities; overrides edge-node-id and observer-node-id")
		issuer      = flag.String("token-issuer", "zerotrust-fl-sim", "JWT issuer")
		audience    = flag.String("token-audience", "zerotrust-fl-services", "JWT audience")
		tokenTTL    = flag.Duration("token-ttl", 24*time.Hour, "development JWT lifetime")
	)
	flag.Parse()

	developmentClients, err := parseDevelopmentClients(*clients)
	if err != nil {
		log.Fatalf("parse development clients: %v", err)
	}
	if len(developmentClients) == 0 {
		developmentClients = []ztsecurity.DevelopmentClient{
			{NodeID: *edgeNodeID, Role: "edge-worker"},
			{NodeID: *observerID, Role: "observer"},
		}
	}

	artifacts, err := ztsecurity.GenerateDevelopmentPKI(ztsecurity.DevelopmentPKIConfig{
		OutputDir:   *outputDir,
		TrustDomain: *trustDomain,
		ServerName:  *serverName,
		Issuer:      *issuer,
		Audience:    *audience,
		TokenTTL:    *tokenTTL,
		Clients:     developmentClients,
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

func parseDevelopmentClients(value string) ([]ztsecurity.DevelopmentClient, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	clients := make([]ztsecurity.DevelopmentClient, 0)
	for _, rawEntry := range strings.Split(value, ",") {
		entry := strings.TrimSpace(rawEntry)
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("client %q must use node=role syntax", entry)
		}
		nodeID := strings.TrimSpace(parts[0])
		role := strings.TrimSpace(parts[1])
		if nodeID == "" || role == "" {
			return nil, fmt.Errorf("client %q must contain a non-empty node and role", entry)
		}
		if _, exists := seen[nodeID]; exists {
			return nil, fmt.Errorf("duplicate client node ID %q", nodeID)
		}
		seen[nodeID] = struct{}{}
		clients = append(clients, ztsecurity.DevelopmentClient{NodeID: nodeID, Role: role})
	}
	return clients, nil
}
