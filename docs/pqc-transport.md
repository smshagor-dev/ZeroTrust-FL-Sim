# Post-Quantum Transport Security

ZeroTrust-FL-Sim supports explicit post-quantum TLS 1.3 key-exchange policy on Go 1.27 and optional ML-DSA-65 X.509 identities for strict Go-to-Go experiments.

The live transport path uses the Go standard library rather than replacing `crypto/tls` with a CGo-based Open Quantum Safe TLS fork. Go 1.27 provides standardized ML-KEM groups directly in TLS 1.3 and ML-DSA support in `crypto/x509` and `crypto/tls`.

`liboqs-go` remains useful for independent algorithm experiments and interoperability checks, but it is not required in the production coordinator handshake. This avoids a second TLS implementation, a mandatory CGo/liboqs runtime dependency, and divergence from Go's maintained TLS state machine.

## Threat model

The main cryptographic motivation is the harvest-now-decrypt-later threat. An adversary may record encrypted FL traffic today and attempt to recover a classical ECDHE secret after obtaining a future cryptographically relevant quantum computer.

The hybrid key exchange combines a traditional ephemeral secret with an ML-KEM secret. Conceptually, for X25519MLKEM768:

```math
Z_{\mathrm{hybrid}}
=
Z_{\mathrm{MLKEM768}}
\parallel
Z_{\mathrm{X25519}}.
```

For X25519MLKEM768, each component contributes 32 bytes, so the pre-KDF combined shared secret is 64 bytes:

```math
|Z_{\mathrm{hybrid}}|
=
32 + 32
=
64\ \mathrm{bytes}.
```

TLS 1.3 feeds the negotiated key-exchange secret into its normal HKDF-based key schedule. Under the hybrid construction, confidentiality is designed not to depend exclusively on the continued security of the classical ECDHE component.

## Transport policy

The coordinator accepts three policies through `ZTFL_PQC_MODE` or `--pqc-mode`:

| Mode | Offered/accepted key exchanges | Classical fallback | Intended use |
| --- | --- | --- | --- |
| `off` | X25519, P-256, P-384 | yes | compatibility/control baseline |
| `prefer` | X25519MLKEM768, P-256+ML-KEM-768, P-384+ML-KEM-1024 plus classical groups | yes | default heterogeneous deployment |
| `require` | hybrid ML-KEM groups only | no | strict PQC Go-to-Go validation |

`require` performs two checks:

1. classical-only groups are removed from `tls.Config.CurvePreferences`;
2. `VerifyConnection` rejects the connection unless the final `tls.ConnectionState.CurveID` is a supported ML-KEM or hybrid group.

This prevents a deployment from being labeled PQC-required while silently negotiating a classical-only group.

## Post-quantum identity authentication

Hybrid ML-KEM protects key establishment, but classical certificate signatures remain a separate quantum-migration concern.

Strict experiments can generate ML-DSA-65 CA, server, and client certificates:

```bash
go run ./security \
  -out certs/pqc \
  -certificate-algorithm mldsa65
```

Then require both hybrid key exchange and ML-DSA X.509 identities:

```bash
go run ./cmd/coordinator \
  -server-cert certs/pqc/server.crt \
  -server-key certs/pqc/server.key \
  -client-ca certs/pqc/ca.crt \
  -jwt-public-key certs/pqc/jwt_signing_public.pem \
  -pqc-mode require \
  -pqc-require-identity
```

The Go client must likewise set:

```go
TLS: security.ClientTLSOptions{
    // certificate, CA, server-name and trust-domain fields omitted
    PQCMode:            security.PQCRequired,
    RequirePQCIdentity: true,
}
```

When `RequirePQCIdentity` is enabled, local configuration is rejected if its own leaf certificate is not ML-DSA and the completed handshake is rejected if the peer leaf certificate is not ML-DSA.

The JWT layer currently remains Ed25519. It is a secondary application authorization factor and cannot independently bypass the required ML-DSA mTLS identity. Migrating JWT signatures to ML-DSA can be evaluated separately when the token ecosystem has interoperable JOSE algorithm identifiers and library support.

## Wire-size calculation

For X25519, the raw ephemeral key share is 32 bytes in each direction.

For X25519MLKEM768:

- client key share = 1216 bytes = 1184-byte ML-KEM-768 encapsulation key + 32-byte X25519 share;
- server key share = 1120 bytes = 1088-byte ML-KEM-768 ciphertext + 32-byte X25519 share.

The client-side raw key-share expansion is:

```math
\Delta B_{\mathrm{client}}
=
1216 - 32
=
1184\ \mathrm{bytes}.
```

The raw ratio is:

```math
R_{\mathrm{client}}
=
\frac{1216}{32}
=
38.
```

The server-side expansion is:

```math
\Delta B_{\mathrm{server}}
=
1120 - 32
=
1088\ \mathrm{bytes},
```

with ratio:

```math
R_{\mathrm{server}}
=
\frac{1120}{32}
=
35.
```

Across both key shares:

```math
B_{\mathrm{classical}}
=
32 + 32
=
64\ \mathrm{bytes},
```

```math
B_{\mathrm{hybrid}}
=
1216 + 1120
=
2336\ \mathrm{bytes},
```

and therefore:

```math
\Delta B_{\mathrm{hybrid}}
=
2336 - 64
=
2272\ \mathrm{bytes}.
```

The combined raw key-share multiplier is:

```math
R_{\mathrm{combined}}
=
\frac{2336}{64}
=
36.5.
```

These values cover only the TLS key-exchange payloads. They do not include TLS framing, X.509 chains, ML-DSA certificate/signature size, TCP/IP headers, gRPC/HTTP2 framing, or application payloads.

## Latency calculation

For measured classical handshake latency `T_classical` and hybrid latency `T_pqc`, define absolute overhead:

```math
\Delta T_{\mathrm{PQC}}
=
T_{\mathrm{PQC}}
-
T_{\mathrm{classical}}.
```

Percentage overhead is:

```math
O_{\mathrm{PQC}}
=
100
\left(
\frac{T_{\mathrm{PQC}}}{T_{\mathrm{classical}}}
-1
\right)\%.
```

The result depends on CPU, Go version, TLS session reuse, network RTT, selected group, certificate algorithm, and whether ML-DSA identity authentication is enabled. Publication results should therefore report the exact environment rather than assuming a universal constant.

## Docker compatibility

The Compose testbed defaults to:

```text
ZTFL_PQC_MODE=prefer
ZTFL_PQC_REQUIRE_IDENTITY=false
ZTFL_CERTIFICATE_ALGORITHM=ed25519
```

This keeps Python gRPC workers interoperable while allowing the Go coordinator to negotiate a hybrid group with peers that support it.

Do not switch the existing Python-worker Compose profile to ML-DSA certificates without first verifying the Python gRPC/BoringSSL certificate stack used by the selected `grpcio` build.

Strict hybrid + ML-DSA verification is currently covered by Go transport tests.

## Open Quantum Safe relationship

Open Quantum Safe's `liboqs-go` is an optional research/prototyping dependency, not the live TLS engine in this repository.

Reasons:

- Go 1.27 already implements the standardized ML-KEM TLS groups needed by the coordinator;
- Go 1.27 supports ML-DSA X.509 certificates and TLS signatures;
- liboqs-go requires liboqs and CGo/pkg-config integration;
- introducing a second TLS state machine or custom pre-handshake KEM would create a non-standard protocol and increase attack surface;
- OQS itself recommends hybrid deployments and reliance on standardized NIST outcomes for deployed applications.

OQS remains appropriate for independent KEM/signature benchmarking, cross-implementation known-answer testing, and experimental algorithms that are intentionally outside the production TLS policy.

## Verification

Run the strict transport tests:

```bash
go test -v ./pkg/security -run 'PQC|MLDSA'
```

Run all security and coordinator tests:

```bash
go test -v ./...
```

Relevant implementation files:

```text
pkg/security/pqc.go
pkg/security/tls.go
pkg/security/pki.go
security/certgen.go
cmd/coordinator/main.go
pkg/security/pqc_test.go
```

## References

- NIST FIPS 203: ML-KEM
- NIST FIPS 204: ML-DSA
- RFC 10024: Post-Quantum Traditional Hybrid Key Agreement Mechanisms for TLS 1.3
- Go 1.27 `crypto/tls`, `crypto/mlkem`, `crypto/mldsa`, and `crypto/x509`
- Open Quantum Safe `liboqs` / `liboqs-go`
