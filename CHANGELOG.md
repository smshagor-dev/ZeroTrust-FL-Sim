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

### Changed

- Package metadata now declares Apache-2.0 licensing and project links.
- Python package and SDK version metadata are aligned at `0.7.0` while v1.0 production gates remain in progress.
- Coordinator durable state snapshots now use schema v2; legacy schema-v1 state can be normalized once by the coordinator using the explicitly configured runtime experiment identity.
- Recovery bundle manifests now use schema v2 and bind restored state to the persisted experiment identity/configuration fingerprint.

## Version History

Tagged release history will be recorded here as production release artifacts are published. Pre-1.0 package metadata now tracks the active engineering release line instead of the earlier inconsistent `0.3.0`/`0.4.0` values.
