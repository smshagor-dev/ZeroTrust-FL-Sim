# Changelog

All notable user-visible changes to ZeroTrust-FL-Sim should be recorded in this file.

The format is based on Keep a Changelog, and the project intends to use semantic versioning for tagged software releases.

## [Unreleased]

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
- v0.9 release-contract tests that freeze the documented public Python SDK surface and fail CI when Python, CMake, Helm, or citation version metadata drifts.
- v0.9 correctness regression coverage for fail-closed buffer-bearing models and Krum/Multi-Krum Byzantine population bounds.
- CPU/PyTorch/native aggregation parity tests and a separate real-device CUDA evidence collector that refuses CPU-only validation.
- Commit-bound reproducibility manifests for release benchmark runs, including research configuration digests and runtime facts.
- Real ephemeral Kind/Kubernetes supported-profile evidence with immutable image digests, CI-only PKI, authenticated worker model advancement, worker loss/recovery, and coordinator restart verification.
- Operator objectives, recovery runbooks, and a release-readiness evidence map linking claims to executable tests and workflows.
- A tracked v1.0 production evidence manifest covering repository protection, independent security review, OpenSSF application evidence, the supported CPU/native profile, and the explicit CUDA validation boundary.
- An executable v1 production release validator with regression tests that fails closed on missing external evidence, version drift, release-note placeholders, unsupported stable tags, and unsupported CUDA validation claims.
- Prepared v1.0.0 release notes and a production release contract defining compatibility, supported deployment scope, security claim boundaries, and publication sequencing.

### Changed

- Package, runtime, CMake, Helm, and citation metadata are aligned at `0.9.0` while v1.0 external production gates remain in progress.
- Coordinator durable state snapshots now use schema v3 and independently persist `model_id`; schema-v1/v2 state can adopt the explicitly configured runtime model identity once and is then normalized to v3.
- Schema-v3 durable restart now fails closed on missing or changed model identity before state is advanced or normalized.
- Recovery bundle manifests use schema v2 and bind restored state to the persisted experiment identity/configuration fingerprint.
- The v0.9 release-candidate contract explicitly separates CPU/native CI evidence from CUDA hardware validation and limits privacy/encryption claims to implemented paths.
- Benchmark smoke evidence now emits and verifies an exact-commit reproducibility manifest instead of relying on benchmark outputs alone.
- Tag-triggered release publication now validates the tracked production contract and live v1 blocker issue states before GHCR authentication, then creates a GitHub Release only after immutable image publication, SBOM generation, signing, attestations, and checksum evidence succeed.

## Version History

Tagged release history will be recorded here as production release artifacts are published. Pre-1.0 package metadata now tracks the active engineering release line instead of the earlier inconsistent `0.3.0`/`0.4.0`/`0.7.0` values.
