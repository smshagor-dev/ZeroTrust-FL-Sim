# ZeroTrust-FL-Sim Threat Model

This document defines the security boundary for the current reference implementation. It is a threat model for engineering and research use; it is not a certification claim.

## Assets

The primary assets are the CA and JWT signing keys, node private keys and tokens, global model versions, worker updates, experiment state, audit/telemetry data, benchmark artifacts, and release/build provenance.

## Trust assumptions

The root signing authority, release/build pipeline, and coordinator host are trusted in the current architecture. The network is untrusted. Federated workers are authenticated but are not trusted to behave correctly: a valid worker may be Byzantine, compromised, malicious, stale, resource-abusive, or may submit adversarial model updates.

A successful mTLS/JWT authentication therefore grants identity, not trust in model content.

## Security controls

| Threat | Current control |
| --- | --- |
| Network interception / MITM | TLS 1.3 mutual TLS with CA validation |
| Worker impersonation | Per-node X.509 identity, SPIFFE-style URI SAN, role OU, JWT authorization |
| Lateral credential theft | Per-node isolated credential volumes; CA/JWT signing private keys are not mounted into workers |
| Replay of state-changing updates | Fresh timestamp + cryptographic nonce, replay cache, per-round node deduplication |
| Stale model update | Exact round and base-model-version checks |
| Malformed or oversized update | Message-size cap, SHA-256 validation, strict float32 NPY decoding, dimension checks, finite-value validation |
| Byzantine / poisoned update | Coordinate-wise median is the distributed default; additional robust aggregators exist in the native simulation path |
| Sample-count weight inflation | Distributed zero-trust default does not trust client-reported sample count for weighting; weighted mean is explicit opt-in trusted mode |
| Resource abuse | Per-worker update-rate limiting, gRPC message limits and concurrent-stream limits |
| Secret leakage from development PKI | PKI is generated in an ephemeral directory and only least-privilege artifacts are copied to each service volume |
| Dashboard control abuse | Control endpoint is disabled unless a control token is configured and requires a bearer token |

## Byzantine worker model

Workers are assumed capable of arbitrary behavior after authentication, including label flipping, sign flipping, noise injection, collusion, false metrics, stale submissions, duplicate submissions, and deliberate malformed payloads. Robust aggregation reduces the influence of malicious updates but does not prove that every adversarial strategy is detectable or harmless.

Local differential privacy is not relied upon as a defense against Byzantine clients. A malicious client may bypass local DP unless the execution environment itself is trusted and enforces it.

## Cryptography

The default development/test X.509 identity algorithm is ECDSA P-256 because it interoperates across Go crypto/tls and the BoringSSL stack bundled with Python grpcio wheels. Ed25519 and ML-DSA identity modes remain explicit options where the runtime supports them. PQC transport policy is experimental and must not be interpreted as end-to-end post-quantum security for every component.

CKKS primitives are available for experimentation, but encrypted aggregation is not yet the default distributed gRPC protocol. Do not claim end-to-end encrypted federated aggregation until that path is integrated and independently reviewed.

## Current trust boundary limitations

The coordinator is trusted in this reference architecture. Compromise of the coordinator host can expose model state and control-plane decisions. Registration and global-model state are not yet backed by a durable multi-node consensus/persistence layer, so the current deployment should not be described as highly available or crash-durable.

Full PyTorch state-dict synchronization is also not yet implemented. The simulator therefore rejects models with registered buffers instead of silently allowing divergent BatchNorm-style state.

## Production deployment requirements

A production operator should use externally managed short-lived identities, KMS/HSM or Vault-backed signing keys, durable database/object storage, restricted network policies, authenticated observability, immutable images, signed artifacts, centralized audit retention, and a tested backup/recovery process. Development-generated credentials must not be reused as production credentials.

## Non-goals and non-claims

This project does not claim formal verification, FIPS validation, ISO certification, SOC 2 compliance, immunity to poisoning, or protection against a fully compromised trusted coordinator. Those require separate engineering, operating controls, and where applicable independent assessment.
