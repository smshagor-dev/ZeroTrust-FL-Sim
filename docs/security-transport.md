# Secure Coordinator Transport

The coordinator accepts gRPC traffic only over TLS 1.3 with mutual certificate authentication. Client certificates must chain to the configured CA, contain a `role:<role>` organizational unit, and include a URI SAN bound to the certificate common name.

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
2. The client certificate chains to the configured CA.
3. Certificate CN, role OU, and URI SAN are internally consistent.
4. A single `Authorization: Bearer <JWT>` metadata value is present.
5. The JWT uses EdDSA and passes issuer, audience, expiry, and signature validation.
6. JWT `sub`, `node_id`, and `role` are bound to the certificate identity.
7. The role is allowed to invoke the requested RPC.
8. RPCs other than registration require a live server-side node registration.

A token cannot claim that a node is registered. Registration state is kept by the coordinator and is bound to the certificate fingerprint.

## RPC policy

| RPC | Allowed roles | Registration required |
| --- | --- | --- |
| `RegisterNode` | `edge-worker`, `observer`, `admin` | No |
| `Heartbeat` | `edge-worker`, `observer`, `admin` | Yes |
| `GetGlobalModel` | `edge-worker`, `observer`, `admin` | Yes |
| `SubmitLocalUpdate` | `edge-worker`, `admin` | Yes |

Unknown RPC methods are denied by default.

## Generate local credentials

```bash
go run ./security -out certs/dev
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

```bash
go run ./security -out certs/dev
go run ./cmd/coordinator
```

The default listener is `127.0.0.1:50051`.

## Test

```bash
make test
```

The security integration suite verifies valid mTLS access, missing-client-certificate rejection, untrusted-client-CA rejection, registration enforcement, certificate/JWT role binding, and invalid JWT rejection.
