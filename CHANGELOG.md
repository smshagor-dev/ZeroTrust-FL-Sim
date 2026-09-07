# Changelog

All notable user-visible changes to ZeroTrust-FL-Sim should be recorded in this file.

The format is based on Keep a Changelog, and the project uses semantic versioning for tagged software releases.

## [Unreleased]

## [1.0.0] - 2026-09-08

### Added

- Apache License 2.0 licensing and project NOTICE.
- Contribution, security, support, and community governance documentation.
- GitHub issue and pull-request templates.
- Citation metadata for research reuse.
- Explicit durable experiment identity with immutable experiment ID, creation time, and configuration SHA-256 metadata.
- Coordinator flags and environment variables for experiment identity and full-configuration fingerprints.
- Experiment-bound PostgreSQL/S3 disaster-recovery verification.
- Stable Python SDK API v1 with typed enrollment, heartbeat, model snapshot, and update submission results.
- `ztfl` operator CLI for configuration validation, coordinator startup, worker enrollment, experiment status, and diagnostics.
- Production Helm chart with immutable image digests, isolated worker credentials, restrictive security contexts, probes, resources, NetworkPolicy, and PodDisruptionBudgets.
- Multi-host deployment guidance and CI validation of rendered Kubernetes security invariants.
- Release workflow that publishes coordinator, worker, and recovery OCI images and records immutable digests.
- Fail-closed dependency, SAST, secret, license, container, fuzzing, SBOM, signing, and provenance gates for the supported release profile.
- Correctness regression coverage for fail-closed buffer-bearing models and Krum/Multi-Krum Byzantine population bounds.
- CPU/PyTorch/native aggregation parity tests and a separate real-device CUDA evidence collector that refuses CPU-only validation.
- Commit-bound reproducibility manifests for release benchmark runs, including research configuration digests and runtime facts.
- Real ephemeral Kind/Kubernetes supported-profile evidence with immutable image digests, CI-only PKI, authenticated worker model advancement, worker loss/recovery, and coordinator restart verification.
- Operator objectives, recovery runbooks, and a release-readiness evidence map linking claims to executable tests and workflows.
- A tracked v1.0 assurance manifest covering repository protection, independent security review, OpenSSF application evidence, the supported CPU/native profile, and the explicit CUDA validation boundary.
- An executable v1 production release validator with regression tests for version drift, release-note placeholders, unsupported stable tags, unsupported CUDA validation claims, and explicit assurance dispositions.
- Deterministic independent-security-review evidence bundle generation with exact Git HEAD provenance, dirty-tree rejection, SHA-256 manifests, normalized archives, safe overwrite protection, and a reviewer report template.
- A read-only workflow-dispatched security-review artifact handoff for external reviewers.
- Explicit repository-owner risk-acceptance records for external/administrative assurance items that are waived rather than falsely marked satisfied.

### Changed

- Package, Python runtime, CMake/native runtime, Helm, and citation metadata are aligned at `1.0.0`.
- Python package maturity is now `Development Status :: 5 - Production/Stable` for the supported CPU/PyTorch/native C++ profile.
- Coordinator durable state snapshots use schema v3 and independently persist `model_id`; schema-v1/v2 state can adopt the explicitly configured runtime model identity once and is then normalized to v3.
- Schema-v3 durable restart fails closed on missing or changed model identity before state is advanced or normalized.
- Recovery bundle manifests use schema v2 and bind restored state to the persisted experiment identity/configuration fingerprint.
- The supported release contract explicitly separates CPU/native CI evidence from CUDA hardware validation and limits privacy/encryption claims to implemented paths.
- Benchmark smoke evidence emits and verifies an exact-commit reproducibility manifest instead of relying on benchmark outputs alone.
- Tag-triggered release publication validates the tracked production contract and exact-release-commit workflow state before GHCR authentication, then creates a GitHub Release only after immutable image publication, SBOM generation, signing, attestations, and checksum evidence succeed.
- The v1 assurance contract now distinguishes evidence-backed satisfaction from an explicit repository-owner waiver. A waiver must include owner identity, date, issue reference, reason, and limitation disclosure, and release notes must expose the missing assurance publicly.

### Security and assurance exceptions

- Issue #37 branch protection is waived for v1.0.0; GitHub does not technically enforce required checks, force-push prevention, or branch deletion protection on `main` at release time.
- Issue #70 independent security assessment is waived for v1.0.0; the release must not be described as independently audited, assessed, or certified.
- Issue #73 OpenSSF Best Practices application is waived for v1.0.0; the release does not claim a Best Practices project record or badge.
- CUDA remains experimental and unvalidated unless reviewed real-device evidence is produced separately.

## Version History

- `1.0.0` — first stable release of the supported CPU/PyTorch/native C++ federated-learning simulation profile, with reproducible release evidence and explicitly disclosed assurance exceptions.
