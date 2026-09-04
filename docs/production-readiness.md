# Production Readiness

ZeroTrust-FL-Sim is moving from an advanced research/engineering prototype toward a production-oriented secure federated-learning reference platform. This document records what is implemented and the hard gates that remain before a stable v1.0 claim.

## Current production-readiness foundation

The current hardening baseline includes:

- TLS 1.3 mutual authentication for the gRPC control plane.
- Per-node isolated X.509/JWT credentials with no worker access to CA or JWT signing private keys.
- SPIFFE-style certificate identity and role validation.
- Real distributed round state with update acceptance, quorum, aggregation, global model advancement and stale-version rejection.
- Strict one-dimensional float32 NPY network model format with size, digest, dimensionality and finite-value validation.
- Fresh timestamp/nonce protection for state-changing update submissions, per-round deduplication and per-worker rate limiting.
- Byzantine-resilient coordinate-wise median as the distributed zero-trust default. Sample-weighted mean remains an explicit trusted-mode option.
- Sample-weighted FedAvg semantics for the local benign `mean` simulation path.
- Local quorum behavior that tolerates worker loss while the configured quorum remains achievable.
- Explicit balanced and raw Dirichlet partition modes.
- Fail-closed CUDA finite validation by default.
- Fail-fast handling for models with registered buffers until complete state-dict synchronization is implemented.
- Differential-privacy accounting with nondeterministic noise seeds by default and explicit reproducibility mode.
- Native C++20 robust aggregation, optional CKKS primitives, and portable native builds without `-march=native` by default.
- Localhost/internal-network observability defaults and authenticated dashboard control.
- Docker end-to-end integration and benchmark smoke tests in CI.
- Pinned GitHub Actions revisions and automated dependency update configuration.

## v1.0 hard gates still required

The following work must be completed before describing the project as a generally production-ready, highly available v1.0 platform.

### Durable control-plane state

Move registrations, experiments, rounds, model-version metadata and commit state from process memory into a transactional durable store. Add object storage for model artifacts, restart recovery, idempotent commit semantics, backup/restore testing and leader fencing for multi-replica coordinators.

### Full model-state protocol

Replace parameter-only vectors with a versioned model manifest that synchronizes all required PyTorch state, including registered buffers. Bind architecture/schema identifiers, tensor names/shapes/dtypes, compression metadata and payload digests to the model version.

### Distributed encrypted aggregation

Integrate CKKS into the actual worker-to-coordinator protocol rather than treating it as a standalone primitive. Define key ownership, rotation, ciphertext bounds, authenticated aggregation metadata and preferably threshold decryption so the coordinator does not possess a universal decryption key.

### Deployment platform

Ship supported Kubernetes/Helm manifests with restricted service accounts, NetworkPolicies, PodDisruptionBudgets, resource limits, probes, secret injection and external PostgreSQL/object-storage integrations. Add documented Docker/Podman and Kubernetes compatibility tiers.

### Stable SDK, CLI and compatibility policy

Freeze a supported public Python API and versioned protocol compatibility window. Provide operator/user commands for initialization, validation, coordinator startup, worker enrollment, experiment lifecycle, diagnostics and benchmark execution. Document deprecation rules and upgrade paths.

### Reproducible dependency and build closure

Commit Go module checksums and frontend/package lockfiles, use immutable container digests throughout supported builds, pin native third-party dependencies to immutable revisions, and establish a documented toolchain compatibility matrix.

### Signed releases and provenance

Generate release checksums, SPDX and/or CycloneDX SBOMs, build provenance/attestations, and signed OCI/container and binary artifacts. Target reproducible or independently verifiable builds and an explicit supply-chain security level rather than relying on mutable tags.

### Expanded security verification

Add fuzzing for protobuf/model parsers and native aggregation inputs, chaos testing for coordinator/worker/storage failures, credential-expiry/rotation tests, malicious-resource-exhaustion tests, upgrade/rollback tests and an external security/code review before stable v1.0.

### Repository governance

Require protected-main PR workflows, required CI checks, CODEOWNER review for security-sensitive paths, no force pushes, release-manager policy, supported-version policy, vulnerability disclosure/response targets and signed release tags where practical.

## Release terminology

Until the v1.0 gates above are closed, releases should be described as **production-oriented research/reference releases** rather than certified enterprise production software. Security controls may be mapped to external frameworks, but compliance or certification claims must only be made when the applicable independent assessment has actually been completed.

## Suggested release progression

- v0.5: hardened distributed FL and threat-model baseline.
- v0.6: durable state, restart recovery and transactional round commits.
- v0.7: Kubernetes packaging, stable operator configuration and multi-host deployment.
- v0.8: distributed encrypted aggregation and expanded security/chaos testing.
- v0.9: public API/protocol freeze, release provenance and external review.
- v1.0: all mandatory production gates closed and documented.
