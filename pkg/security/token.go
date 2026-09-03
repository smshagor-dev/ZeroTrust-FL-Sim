package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const tokenAlgorithm = "EdDSA"

type TokenClaims struct {
	NodeID string `json:"node_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type TokenVerifier struct {
	publicKey ed25519.PublicKey
	issuer    string
	audience  string
	leeway    time.Duration
}

func NewTokenVerifier(publicKey ed25519.PublicKey, issuer, audience string, leeway time.Duration) (*TokenVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("token issuer is required")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("token audience is required")
	}
	if leeway < 0 {
		return nil, errors.New("token leeway cannot be negative")
	}

	keyCopy := make(ed25519.PublicKey, len(publicKey))
	copy(keyCopy, publicKey)

	return &TokenVerifier{
		publicKey: keyCopy,
		issuer:    issuer,
		audience:  audience,
		leeway:    leeway,
	}, nil
}

func NewTokenVerifierFromPEMFile(path, issuer, audience string, leeway time.Duration) (*TokenVerifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token verification key: %w", err)
	}

	publicKey, err := ParseEd25519PublicKeyPEM(data)
	if err != nil {
		return nil, err
	}
	return NewTokenVerifier(publicKey, issuer, audience, leeway)
}

func (v *TokenVerifier) Verify(rawToken string) (*TokenClaims, error) {
	if v == nil {
		return nil, errors.New("token verifier is not configured")
	}
	if strings.TrimSpace(rawToken) == "" {
		return nil, errors.New("token is empty")
	}

	claims := new(TokenClaims)
	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != tokenAlgorithm {
				return nil, fmt.Errorf("unexpected token signing algorithm %q", token.Method.Alg())
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{tokenAlgorithm}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	if claims.Subject == "" || claims.NodeID == "" || claims.Role == "" {
		return nil, errors.New("token identity claims are incomplete")
	}
	if claims.Subject != claims.NodeID {
		return nil, errors.New("token subject does not match node_id")
	}
	return claims, nil
}

func IssueToken(privateKey ed25519.PrivateKey, issuer, audience, nodeID, role string, ttl time.Duration) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key")
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return "", errors.New("issuer and audience are required")
	}
	if strings.TrimSpace(nodeID) == "" || strings.TrimSpace(role) == "" {
		return "", errors.New("node ID and role are required")
	}
	if ttl <= 0 {
		return "", errors.New("token TTL must be positive")
	}

	now := time.Now().UTC()
	tokenID, err := randomIdentifier(16)
	if err != nil {
		return "", err
	}

	claims := TokenClaims{
		NodeID: nodeID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   nodeID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}

func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("token verification key is not PEM encoded")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse token verification key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("token verification key must be Ed25519")
	}
	return publicKey, nil
}

func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("token signing key is not PEM encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse token signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("token signing key must be Ed25519")
	}
	return privateKey, nil
}

func randomIdentifier(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
