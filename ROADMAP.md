# ZeroTrust-FL-Sim Production Roadmap

ZeroTrust-FL-Sim is currently a pre-1.0 engineering and research platform. The goal of the v1 line is a secure, reproducible federated-learning reference platform that can be deployed by researchers, security teams, and infrastructure engineers without relying on undocumented assumptions.

This roadmap is a release contract, not a claim that unfinished capabilities already exist.

## v0.5 — Distributed correctness and trust boundaries

Release gates:

- real global-model advancement on the network coordinator path
- strict model-update schema, dimension, digest, and finite-value validation
- per-round duplicate submission protection and bounded request sizes
- application-level timestamp and nonce replay protection for model updates
- isolated per-workload credentials; workers never receive CA or JWT signing private keys
- TLS 1.3 mutual authentication with explicit workload identity policy
- sample-weighted FedAvg semantics in the local simulator
- quorum-safe worker failure behavior
- explicit raw and balanced Dirichlet partition modes
- secure CUDA finite-value validation enabled by default
- Docker end-to-end mTLS integration green in CI

## v0.6 — Durable coordinator state

Implementation status: issue #38 introduced the schema-versioned atomic filesystem `StateStore` and restart-recovery gate. Issue #42 added the PostgreSQL `StateStore`, explicit database migrations, transactional whole-snapshot commits, PostgreSQL CI coverage, and backup/restore documentation. Issue #44 added content-addressed S3-compatible global-model artifacts with PostgreSQL metadata references, legacy inline-row migration, and object-integrity recovery checks. Issue #46 added the PostgreSQL append-only-by-application-contract, hash-chained audit trail for successful recovery-critical transitions plus a verified bounded NDJSON exporter. Issue #48 added explicit runtime registration-credential generations, self-service rotation, admin-only lease-scoped revocation, durable revocation tombstones, replay protection, and lifecycle audit events. Issue #50 added exported PostgreSQL MVCC snapshots, versioned recovery manifests, verified PostgreSQL/S3/audit backup bundles, a pinned PostgreSQL 18.6 recovery image, source-schema immutability checks, clean-target enforcement, and a destructive clean-room backup/destroy/restore CI gate. Issue #59 adds explicit immutable experiment identity, experiment creation metadata, configuration fingerprints, schema-v1-to-v2 state normalization, restart drift rejection, and experiment-bound disaster recovery.

With issue #59, the documented v0.6 durable-state gates are implemented for the supported single-coordinator reference profile. Experiment identity is persisted directly and is never inferred from model version or round state. A caller-supplied configuration SHA-256 may bind the durable experiment to a wider canonical orchestration manifest covering dataset/partition, seeds, privacy, attack, and other experiment settings; when omitted, the coordinator records a narrower deterministic fingerprint of its own recovery-critical policy.

The project does **not** claim multi-coordinator HA/consensus, CRL/OCSP-based PKI revocation, JWT signing-key rotation, KMS/HSM integration, encrypted backup media, authenticated backup signatures, or guaranteed RPO/RTO.

Release gates:

- persistent experiment, round, model-version, registration, and update metadata
- crash-safe global-model commits
- idempotent recovery after coordinator restart
- database migrations and verified PostgreSQL/S3 backup/restore workflow
- durable tamper-evident audit event export
- explicit lease and runtime registration credential-rotation/revocation lifecycle

Target reference stack: PostgreSQL for durable metadata and durable transition audit records, an S3-compatible object store for model artifacts, and optional Redis for future distributed leases/rate limits. Implementations must keep storage interfaces replaceable.

## v0.7 — Stable protocol and deployment surface

Release gates:

- versioned model envelope with model ID, schema hash, tensor manifest, dtype, dimensions, digest, and protocol version
- backward-compatibility policy for protobuf evolution
- stable Python SDK surface
- operator CLI for validation, coordinator startup, worker enrollment, experiment status, and diagnostics
- OCI images published by immutable digest
- Kubernetes manifests and Helm chart with NetworkPolicy, security contexts, probes, resource limits, and PodDisruptionBudgets
- documented multi-host deployment

## v0.8 — Security and supply-chain hardening

Release gates:

- dependency, secret, SAST, container, and license scanning in CI
- fuzzing for protobuf/model decoding and native aggregation boundaries
- SBOMs for release artifacts and images
- signed release artifacts and OCI images
- build provenance/attestations
- documented NIST SSDF practice mapping without claiming certification
- OpenSSF Best Practices application and Scorecard improvement plan
- external security review or independently reproduced security assessment

## v0.9 — Release candidate quality

Release gates:

- public API freeze
- upgrade/migration testing
- CPU/native/CUDA numerical parity suite
- failure-injection and chaos suite covering worker loss, stale updates, malformed payloads, expired credentials, and coordinator restart
- reproducible benchmark manifests with commit SHA, toolchain, hardware, data partition parameters, seeds, privacy parameters, and threat model
- documented SLO targets and operational runbooks
- no unresolved critical/high security findings for the supported deployment profile

## v1.0 — Stable reference platform

v1.0 is permitted only when all of the following are true:

1. distributed FL state transitions and model publication are durable and recoverable
2. supported model state is synchronized without silent parameter/buffer divergence
3. authentication, authorization, replay protection, credential isolation, rotation, and revocation behavior are documented and tested
4. robust aggregation assumptions and Byzantine tolerance bounds are enforced at configuration time
5. privacy modes distinguish reproducible simulation from security/privacy-preserving operation
6. encrypted aggregation claims are limited to paths that are actually end-to-end integrated
7. Docker and Kubernetes reference deployments pass end-to-end tests
8. supported installation artifacts are reproducible, versioned, signed, and accompanied by SBOM/provenance metadata
9. compatibility, deprecation, support, vulnerability disclosure, and release policies are published
10. the complete required CI, integration, security, packaging, and chaos gates are green

## Post-v1 directions

Potential post-v1 work includes coordinator high availability, threshold decryption for encrypted aggregation, SPIFFE/SPIRE integration, external KMS/HSM support, OIDC operator authentication, policy-as-code authorization, multi-tenancy, and additional robust aggregation research.

No roadmap item is a security guarantee until its implementation and tests ship in a supported release.
