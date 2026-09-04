# ADR 0001: Zero-Trust Workload and Credential Boundaries

- Status: Accepted
- Date: 2026-09-04

## Context

Federated-learning workers are intentionally treated as potentially Byzantine. A deployment that gives every worker access to a shared credential directory containing CA private keys, JWT signing keys, or peer credentials invalidates that threat model even if the gRPC transport uses mutual TLS.

Similarly, authenticating a worker proves possession of an enrolled identity; it does not prove that the worker trained honestly or reported truthful metrics.

## Decision

1. Development and production deployment patterns isolate credential material per workload.
2. Workers receive only their own private key/certificate/token and public CA material.
3. The coordinator receives its server identity and public JWT verification material but not ordinary worker private keys, except a narrowly scoped health-probe client identity in the local Compose reference profile.
4. CA/JWT signing private keys remain inside the ephemeral development PKI generation boundary and must move to an external offline/KMS/Vault boundary for production-oriented deployment.
5. Certificate identity, token subject/node/role, registration lease, and request node identity are bound and validated independently.
6. State-changing model-update requests additionally carry freshness and random nonce metadata to provide application-level replay resistance.
7. Model-update content remains untrusted after successful authentication and must pass schema, digest, finite-value, version/round, duplicate, rate-limit, and aggregation-policy validation.

## Consequences

- A compromised worker no longer automatically exposes credentials for other workers or signing authorities in the reference Compose deployment.
- Enrollment and authentication are explicitly separate from Byzantine-model trust.
- Local development PKI uses an interoperable certificate algorithm by default because the Python gRPC runtime and Go TLS server must agree on a certificate type supported by both stacks. Ed25519/ML-DSA may still be used only in environments where interoperability has been validated.
- Credential rotation/revocation and external secret management remain required before the v1 production gate.
- Tests and deployment reviews must fail if privileged signing material is mounted into worker containers.

## Alternatives rejected

### Shared PKI volume

Rejected because any worker compromise would expose peer credentials and signing material, defeating workload isolation.

### Authentication implies trusted update

Rejected because Byzantine FL explicitly assumes authenticated participants may submit adversarial updates.

### Transport TLS alone for replay protection

Rejected as the only layer. TLS protects a connection, while round/version checks plus request nonces provide defense in depth against captured/replayed application requests and implementation mistakes outside a single transport session.
