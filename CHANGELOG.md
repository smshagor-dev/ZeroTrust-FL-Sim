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

### Changed

- Package metadata now declares Apache-2.0 licensing and project links.
- Coordinator durable state snapshots now use schema v2; legacy schema-v1 state can be normalized once by the coordinator using the explicitly configured runtime experiment identity.
- Recovery bundle manifests now use schema v2 and bind restored state to the persisted experiment identity/configuration fingerprint.

## Version History

The Python package metadata currently identifies version `0.4.0`. Historical release notes should be added here as tagged releases are published or reconstructed from repository history.
