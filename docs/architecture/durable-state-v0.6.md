# Durable coordinator state foundation

This document describes the durable-state contract for the v0.6 single-coordinator reference profile. The filesystem backend is described here; PostgreSQL metadata, S3-compatible model artifacts, durable audit export, credential lifecycle, and disaster recovery are documented in the adjacent v0.6 architecture documents. None of these components claims multi-coordinator high availability or consensus.

## What is persisted

When a durable backend is configured, the coordinator persists a schema-versioned snapshot containing:

- immutable experiment identity metadata: experiment ID, creation time, and configuration SHA-256;
- the current global-model protobuf, model version, round ID, payload format, and digest;
- pending per-worker update vectors and sample counts for a round that has not reached quorum;
- active certificate-bound registration leases and credential lifecycle state;
- recent request nonces that remain inside the replay-protection window;
- active per-worker update-rate windows; and
- recovery-critical coordinator policy: registration lease duration, maximum update size, quorum, update-rate limit, and aggregation method.

Experiment identity is explicit state. It is never synthesized from the current model version or round ID.

The filesystem backend is capped at 256 MiB per snapshot. A state file is sensitive because it contains worker registration state and may contain pending model updates. PostgreSQL can additionally provide the hash-chained durable audit trail, while PostgreSQL+S3 mode externalizes non-empty global-model payload bytes into content-addressed objects.

## Experiment identity

Durable coordinator startup accepts:

```text
ZTFL_EXPERIMENT_ID
ZTFL_EXPERIMENT_CONFIG_SHA256
```

or the equivalent flags:

```text
--experiment-id
--experiment-config-sha256
```

`ZTFL_EXPERIMENT_ID` defaults to `default` for compatibility. Once durable state is initialized, the experiment ID is immutable for that state instance.

`ZTFL_EXPERIMENT_CONFIG_SHA256` is an optional lowercase SHA-256 digest of a canonical experiment configuration. Orchestration code can use it to bind the durable Go coordinator to settings that live outside the coordinator itself, including dataset identity, partition mode and parameters, random seeds, privacy configuration, malicious-client/attack configuration, and other reproducibility-critical inputs. The digest is opaque to the coordinator; raw datasets, secrets, and credential material are not copied into the durable experiment metadata.

When no external configuration digest is supplied, the coordinator computes a deterministic fallback fingerprint from its own recovery-critical policy only: lease duration, maximum update size, quorum, update-rate limit, and aggregation method. This fallback deliberately excludes model version and round state. It is narrower than a full experiment manifest and should not be presented as a complete reproducibility fingerprint.

On restart, the runtime experiment ID and configuration digest must match the persisted identity. The persisted experiment creation time remains authoritative. Identity or configuration drift fails closed before recovered model/update state is accepted.

## State schema compatibility

New durable commits use coordinator state schema v2, which adds explicit experiment metadata to the existing recovery-policy envelope.

The filesystem and PostgreSQL state loaders can read schema v1 state produced before experiment identity was explicit. A normal coordinator startup may adopt the runtime-provided experiment identity exactly once for such a v1 snapshot and immediately commit a normalized v2 snapshot. This controlled upgrade does not derive identity from model version or round state.

Unknown future schema versions continue to fail closed.

The PostgreSQL representation does not require a new DDL column for experiment metadata. `policy` is already a transactional JSONB object and `state_schema_version` already accepts positive schema versions. Therefore the v1-to-v2 state transition is a coordinator snapshot-format upgrade, not a database table-layout migration.

Recovery tooling is intentionally stricter: disaster-recovery backup opens PostgreSQL without applying migrations or rewriting state. A schema-v1 source must first be opened successfully by the coordinator and normalized to v2 before a new recovery bundle is taken.

## Commit semantics

Mutating RPCs in durable mode are serialized through the durable service wrapper. The hardened coordinator validates and applies an operation in memory, then the complete state snapshot is committed before success is returned to the client.

The filesystem store commits with this sequence:

1. validate the complete snapshot;
2. serialize the global model with protobuf and the state envelope with JSON;
3. create a temporary file in the destination directory;
4. set the temporary file to mode `0600`;
5. write and `fsync` the temporary file;
6. atomically rename it over the previous snapshot; and
7. `fsync` the parent directory.

If persistence fails after a successful mutating operation, the service restores the previous in-memory snapshot and returns an error instead of acknowledging an uncommitted transition.

For PostgreSQL state, the whole recovery snapshot is committed in a `SERIALIZABLE` transaction. In PostgreSQL+S3 mode, the content-addressed model object is ensured before the PostgreSQL transaction publishes its reference. A failed PostgreSQL transaction may leave an unreferenced object, but it cannot publish a partially committed coordinator state.

For audited PostgreSQL mutations, the state-row update and successful transition audit append share the same transaction. An audit append failure therefore prevents state publication and follows the existing rollback path.

## Startup and recovery

With durable mode enabled:

- a missing state snapshot initializes a bootstrap snapshot with explicit experiment metadata;
- an existing v2 snapshot is strictly decoded and validated;
- an existing v1 snapshot may be normalized once using the runtime experiment identity;
- unknown fields, unsupported future schema versions, invalid model digests, malformed/non-finite pending updates, duplicate bindings, or impossible quorum state fail closed;
- experiment ID/configuration drift fails closed;
- recovery-critical coordinator policy drift fails closed;
- expired registration leases are discarded;
- stale nonce and rate-limit entries are discarded according to their existing windows; and
- successfully recovered state is normalized and committed again.

Artifact-backed PostgreSQL state additionally requires the configured object store to return the exact referenced object length and SHA-256. Missing/corrupt objects or a missing artifact backend fail startup rather than producing an empty or silently different model.

In PostgreSQL mode, bootstrap initialization and successful restart recovery/normalization append durable audit events. These events record transition metadata, not model payloads, JWTs, request nonces, private keys, or plaintext secret material.

## Filesystem safety

The reference store rejects a final state path that is a symbolic link or non-regular file, performs bounded reads, rejects unknown JSON fields, and writes committed files with `0600` permissions. The parent path remains operator-controlled. Hardened `openat`/`O_NOFOLLOW` traversal is outside this reference filesystem implementation.

The Docker image creates `/var/lib/zerotrust-fl` owned by the non-root coordinator UID. A dedicated `coordinator_state` volume can therefore retain the committed snapshot across ordinary container restarts.

## Backup and restore

For the filesystem backend, a backup is a protected copy of the last committed state file. Prefer copying while the coordinator is stopped or otherwise quiesced. Restore only into a runtime whose experiment identity and recovery-critical policy match the saved state.

For PostgreSQL+S3, use the verified disaster-recovery workflow in [`disaster-recovery-v0.6.md`](disaster-recovery-v0.6.md). The recovery bundle binds PostgreSQL state, migration ledger, experiment identity, model artifact, and audit-chain head to the same exported MVCC snapshot and verifies them again after restore.

## CI recovery gates

The filesystem restart gate verifies model, policy, explicit experiment metadata, and pending-round continuity across coordinator restart before workers resume.

The PostgreSQL/S3 job exercises transactional state persistence, artifact externalization, reconnect recovery, audit durability, and clean-room backup/destroy/restore. Recovery verification checks experiment identity/configuration metadata in addition to model version/round, migration ledger, artifact digest, registration lifecycle state, and audit-chain head.

## Deliberate boundaries

The v0.6 durable-state profile is intentionally limited to a supported single-coordinator reference deployment. It does not provide:

- multi-coordinator fencing, leader election, consensus, or HA;
- CRL/OCSP-based PKI revocation or JWT signing-key rotation;
- external KMS/HSM integration;
- encrypted backup media or authenticated/signed recovery manifests;
- guaranteed or measured RPO/RTO;
- automatic artifact garbage collection; or
- a claim that the fallback coordinator-only configuration fingerprint covers the full Python experiment configuration.

The `StateStore` and `ModelArtifactStore` interfaces remain replaceable without creating a second coordinator state machine.
