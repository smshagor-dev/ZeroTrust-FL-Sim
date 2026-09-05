# v0.6 PostgreSQL + S3 disaster recovery

This document describes the supported single-coordinator disaster-recovery workflow for the v0.6 reference stack.

The recovery bundle captures PostgreSQL coordinator state, explicit experiment identity, the migration ledger, tamper-evident audit chain, and the content-addressed global-model artifact referenced by the same PostgreSQL snapshot. It does not contain TLS private keys, JWT signing keys, database passwords, S3 credentials, or raw experiment datasets.

## Consistency model

`ztfl-recovery backup` opens PostgreSQL without running migrations, starts a `REPEATABLE READ` read-only transaction, and calls `pg_export_snapshot()`. The exported snapshot identifier is passed to `pg_dump --snapshot`, so the coordinator state row, experiment metadata, migration ledger, audit-chain head, and custom-format PostgreSQL dump are read from the same MVCC point in time.

The backup command requires the migration ledger visible in that snapshot to match the exact migrations embedded in the running recovery binary. An older, incomplete, renamed, or unknown future migration ledger fails closed. Backup never silently repairs, migrates, or normalizes its source database.

Recovery backup also requires the current coordinator state schema. Schema-v1 coordinator state predates explicit experiment identity and must first be opened by the coordinator, which can adopt the explicitly configured runtime experiment identity once and normalize the durable snapshot to schema v2. The recovery tool itself never infers experiment identity from model version or round state.

The model object is content-addressed and immutable. The coordinator writes and verifies the object before committing the PostgreSQL row that references it. Therefore an artifact reference visible in the exported PostgreSQL snapshot identifies an object that must already exist. Orphan objects created before a failed metadata transaction are not included because they are not referenced by the snapshot.

This consistency model removes the need to stop the coordinator solely for backup consistency in the supported single-writer reference profile. It is not a distributed snapshot or consensus protocol and does not make a multi-coordinator HA claim.

## Bundle layout

A successfully published bundle is a directory containing:

```text
manifest.json
manifest.sha256
postgres.dump
audit.ndjson
artifacts/
  sha256/
    <64-lowercase-hex-sha256>.npy
```

`postgres.dump` contains only the ZeroTrust-FL durable PostgreSQL tables:

- `ztfl_coordinator_state`
- `ztfl_schema_migrations`
- `ztfl_audit_events`

`audit.ndjson` is independently decoded and hash-chain verified before restore. The manifest records its terminal sequence and hash.

The manifest records:

- bundle schema version and creation time;
- PostgreSQL server version and numeric version;
- coordinator state schema version;
- experiment ID, experiment creation time, and experiment configuration SHA-256;
- model version and round;
- exact applied migration ledger;
- dump path, size, and SHA-256;
- audit export path, size, SHA-256, terminal sequence, and terminal event hash; and
- S3 bucket/key plus artifact size and SHA-256 when the model is externalized.

The experiment configuration SHA-256 is an opaque fingerprint. When supplied by orchestration it may cover dataset/partition settings, seeds, privacy parameters, malicious-client/attack configuration, and other reproducibility-critical inputs without storing those raw values in the Go coordinator. If the coordinator generated the fallback digest, it covers only its recovery-critical policy and must not be represented as a complete experiment manifest.

`manifest.sha256` detects accidental or unilateral modification of `manifest.json`. It is an integrity checksum, not an authenticated signature. An attacker able to replace both files can replace the checksum too. Signed recovery manifests remain future supply-chain hardening work.

## Atomic publication

Backup output is first written into a temporary directory beside the requested destination. Files are verified, the manifest/checksum are written last, the directory is synchronized, and the temporary directory is atomically renamed to the final path. An existing destination is never overwritten.

A failed backup leaves no published bundle at the requested destination.

## Backup

The recommended operator surface is the pinned recovery image. It uses the same PostgreSQL 18.6 Alpine image family as the v0.6 reference database, so `pg_dump`/`pg_restore` do not depend on the host package version.

Build it:

```bash
docker build -f docker/Dockerfile.recovery -t zerotrust-fl-recovery:local .
```

Run a backup with the database/S3 network reachable from the container and a writable backup mount. Runtime environment variables mirror the coordinator storage configuration:

```text
ZTFL_POSTGRES_DSN
ZTFL_S3_ENDPOINT
ZTFL_S3_BUCKET
ZTFL_S3_PREFIX
ZTFL_S3_REGION
ZTFL_S3_ACCESS_KEY_ID
ZTFL_S3_SECRET_ACCESS_KEY
ZTFL_S3_SESSION_TOKEN          # optional
ZTFL_S3_ALLOW_INSECURE_HTTP    # local/test only
ZTFL_S3_FORCE_PATH_STYLE       # commonly true for MinIO
```

Experiment identity is read from the committed coordinator state and does not need to be supplied separately to the recovery CLI.

The CLI form is:

```text
ztfl-recovery backup --output /recovery/backup-YYYYMMDD-HHMMSS
```

The PostgreSQL password is removed from the DSN passed in `pg_dump` process arguments and is supplied through `PGPASSWORD` to reduce accidental process-argument exposure. Credentials are never written into the recovery bundle.

## Restore

Restore validates both recovery authorities before mutating either of them:

1. the manifest checksum and strict JSON schema are verified;
2. experiment ID, configuration SHA-256, and experiment creation time are validated;
3. the exact migration ledger is checked against the migrations embedded in the recovery binary;
4. dump/audit/artifact paths, sizes, and SHA-256 values are verified;
5. every bundle path component is checked with `Lstat`; symlinked roots, parent directories, and files are rejected;
6. `audit.ndjson` is decoded and the complete hash chain is verified;
7. the target PostgreSQL major version must be at least the backup source major version;
8. the target PostgreSQL `public` schema must contain zero supported relations and zero functions;
9. when an external model artifact is present, the configured S3 content-addressed prefix must be empty;
10. only after both authorities pass clean-target checks is the model artifact written, and the resulting bucket/key/digest/size must exactly match the manifest;
11. `pg_restore --exit-on-error --no-owner --no-privileges` restores the durable tables;
12. restored PostgreSQL state is reopened without auto-migration and the migration ledger is checked again;
13. the model artifact is loaded and digest-verified through the normal coordinator storage path; and
14. experiment metadata, model version/round, migration ledger, artifact reference, audit length, and audit terminal hash are compared with the manifest.

The restore command requires explicit approval:

```text
ztfl-recovery restore --input /recovery/backup-YYYYMMDD-HHMMSS --allow-destructive
```

The target database and configured S3 model namespace must be dedicated and clean. The tool does not automatically drop PostgreSQL objects or merge a bundle into an existing S3 namespace.

The restore uses the same S3 bucket and content-addressed prefix contract recorded in PostgreSQL metadata. It refuses hidden bucket/prefix remapping. If a different object namespace is required, use an explicit migration procedure rather than rewriting recovery metadata silently.

After restore, normal coordinator startup must use an experiment ID/configuration digest matching the recovered durable experiment identity. A mismatched runtime configuration fails closed.

## Tool compatibility

The recovery CLI reads the source PostgreSQL numeric server version. `pg_dump` and `pg_restore` older than the source PostgreSQL major version are rejected. The restore target PostgreSQL major version must also be no older than the source backup major version.

The supplied recovery image is pinned to `postgres:18.6-alpine` for the v0.6 reference profile. CI wrappers likewise execute PostgreSQL 18.6 tooling in a container rather than depending on an arbitrary host client version.

The recovery format is intentionally strict. Automatic cross-version bundle upgrades are not provided in v0.6; unsupported recovery/state schema versions fail closed.

## CI disaster-recovery gate

The PostgreSQL/S3 CI job performs destructive recovery tests against disposable fixtures:

1. creates audited coordinator state with explicit experiment metadata, an externalized model artifact, and registration lifecycle state;
2. creates a recovery bundle using an exported PostgreSQL MVCC snapshot and PostgreSQL 18.6 `pg_dump`;
3. verifies the bundle records the experiment identity/configuration metadata;
4. proves that an incomplete source migration ledger makes backup fail without auto-migrating the source;
5. drops the ZeroTrust-FL PostgreSQL tables and deletes the referenced S3 object;
6. proves a dirty PostgreSQL target is rejected before the S3 authority is mutated;
7. proves a dirty S3 prefix is rejected before PostgreSQL is restored;
8. restores the bundle into clean database/object authorities;
9. validates restored experiment metadata, model version/round, registration generation, migration ledger, object digest, and audit-chain head; and
10. builds the pinned recovery image.

This gate supplements, rather than replaces, the coordinator restart-recovery and Docker benchmark gates.

## Security and operational boundaries

- The bundle contains durable coordinator state and must be protected as sensitive operational data.
- No private PKI/JWT key material is included by this workflow.
- S3/PostgreSQL credentials are runtime inputs and are not serialized into bundle files.
- Experiment configuration is represented only by its identifier, creation timestamp, and SHA-256 fingerprint; the full manifest is not copied into the bundle by this tranche.
- `manifest.sha256` is not a digital signature or remote attestation.
- The workflow does not implement encrypted backups. Operators should use encrypted storage and transport appropriate to their environment.
- The exact embedded migration ledger and supported state schema are required; this tranche does not implement automatic cross-version bundle upgrades.
- RPO depends on backup frequency. RTO depends on database/object size, network/storage throughput, PostgreSQL restore speed, and operator procedures. No measured RPO/RTO guarantee is claimed.
- The reference implementation is single-coordinator/single-writer. Multi-coordinator fencing, consensus, and distributed backup coordination remain outside v0.6.
