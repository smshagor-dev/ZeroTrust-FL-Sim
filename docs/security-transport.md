# Secure Coordinator Transport

The coordinator accepts gRPC traffic only over TLS 1.3 with mutual certificate authentication. Client certificates must chain to the configured CA, contain a `role:<role>` organizational unit, and include a URI SAN bound to the certificate common name.

The transport also supports explicit post-quantum key-exchange policy through Go 1.27 hybrid ML-KEM groups and optional ML-DSA identities. See [`pqc-transport.md`](pqc-transport.md) for the full threat model, policy modes, wire-size calculations, and strict configuration.

Example edge worker identity:

```text
Subject CN: edge-worker-01
Subject OU: role:edge-worker
URI SAN:    spiffe://zerotrust-fl.local/node/edge-worker-01
```

The server certificate uses the coordinator identity:

```text
Subject CN: coordinator.local
Subject OU: role:coordinator
DNS SAN:    coordinator.local
URI SAN:    spiffe://zerotrust-fl.local/coordinator/coordinator.local
```

## Authorization flow

Each RPC passes the following checks in order:

1. TLS 1.3 handshake succeeds.
2. The configured PQC key-exchange policy is enforced.
3. The client certificate chains to the configured CA.
4. If strict PQC identity mode is enabled, the peer leaf certificate must use ML-DSA.
5. Certificate CN, role OU, and URI SAN are internally consistent.
6. A single `Authorization: Bearer <JWT>` metadata value is present.
7. The JWT uses EdDSA and passes issuer, audience, expiry, and signature validation.
8. JWT `sub`, `node_id`, and `role` are bound to the certificate identity.
9. The role is allowed to invoke the requested RPC.
10. RPCs other than registration require a live server-side node registration.

A token cannot claim that a node is registered. Registration state is kept by the coordinator and is bound to the certificate fingerprint.

## Post-quantum transport modes

| Mode | Behavior |
| --- | --- |
| `off` | classical X25519/P-256/P-384 only |
| `prefer` | hybrid ML-KEM groups plus classical fallback |
| `require` | hybrid ML-KEM groups only; classical-only negotiation is rejected |

The coordinator defaults to `prefer` for interoperability. Use `require` when the peer stack is known to support the Go 1.27 hybrid groups.

Strict identity mode is separate from key exchange. `-pqc-require-identity` requires ML-DSA leaf certificates in both directions.

## RPC policy

| RPC | Allowed roles | Registration required |
| --- | --- | --- |
| `RegisterNode` | `edge-worker`, `observer`, `admin` | No |
| `Heartbeat` | `edge-worker`, `observer`, `admin` | Yes |
| `GetGlobalModel` | `edge-worker`, `observer`, `admin` | Yes |
| `SubmitLocalUpdate` | `edge-worker`, `admin` | Yes |

Unknown RPC methods are denied by default.

## Generate local credentials

Interoperable Ed25519 development PKI:

```bash
go run ./security -out certs/dev
```

Strict ML-DSA-65 development PKI:

```bash
go run ./security \
  -out certs/pqc \
  -certificate-algorithm mldsa65
```

The command creates a development CA, coordinator certificate, client certificates, an Ed25519 JWT signing key pair, and short-lived development tokens. All generated private material is excluded from Git.

## Generate protobuf code

Install the protocol compiler separately, then install the Go plugins:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
```

Generate Go code:

```bash
make proto
```

Equivalent command:

```bash
protoc \
  --go_out=. --go_opt=module=github.com/smshagor-dev/ZeroTrust-FL-Sim \
  --go-grpc_out=. --go-grpc_opt=module=github.com/smshagor-dev/ZeroTrust-FL-Sim \
  proto/fl_service.proto
```

## Run the coordinator

Hybrid-preferred default:

```bash
go run ./security -out certs/dev
go run ./cmd/coordinator -pqc-mode prefer
```

Strict Go-to-Go post-quantum transport:

```bash
go run ./security \
  -out certs/pqc \
  -certificate-algorithm mldsa65

go run ./cmd/coordinator \
  -server-cert certs/pqc/server.crt \
  -server-key certs/pqc/server.key \
  -client-ca certs/pqc/ca.crt \
  -jwt-public-key certs/pqc/jwt_signing_public.pem \
  -pqc-mode require \
  -pqc-require-identity
```

The default listener is `127.0.0.1:50051`.

## Test

```bash
make test
```

Strict PQC transport tests can also be selected directly:

```bash
go test -v ./pkg/security -run 'PQC|MLDSA'
```

The security suite verifies valid mTLS access, missing-client-certificate rejection, untrusted-client-CA rejection, registration enforcement, certificate/JWT role binding, invalid JWT rejection, strict hybrid ML-KEM negotiation, ML-DSA identity authentication, and rejection of classical-only peers when PQC is required.
