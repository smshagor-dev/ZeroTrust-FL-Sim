# v0.6 PostgreSQL + S3 disaster recovery

This document describes the supported single-coordinator disaster-recovery workflow for the v0.6 reference stack.

The recovery bundle captures the PostgreSQL coordinator state, migration ledger, tamper-evident audit chain, and the content-addressed global-model artifact referenced by that same PostgreSQL snapshot. It does not contain TLS private keys, JWT signing keys, database passwords, or S3 credentials.

## Consistency model

`ztfl-recovery backup` opens a PostgreSQL `REPEATABLE READ` read-only transaction and calls `pg_export_snapshot()`. The generated snapshot identifier is passed to `pg_dump --snapshot`, so the coordinator state row, migration ledger, audit-chain head, and custom-format PostgreSQL dump are read from the same MVCC point in time.

The model object is content-addressed and immutable. The coordinator writes/verifies the object before committing the PostgreSQL row that references it. Therefore, an artifact reference visible in the exported PostgreSQL snapshot identifies an object that must already exist. Orphan objects created before a failed metadata transaction are not included because they are not referenced by the PostgreSQL snapshot.

This removes the need to stop the coordinator solely for backup consistency in the supported single-writer reference profile. It is not a distributed snapshot or consensus protocol and does not make a multi-coordinator HA claim.

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

`postgres.dump` is a PostgreSQL custom-format archive containing only the ZeroTrust-FL durable tables:

- `ztfl_coordinator_state`
- `ztfl_schema_migrations`
- `ztfl_audit_events`

`audit.ndjson` is independently decoded and hash-chain verified before restore. The manifest records its terminal sequence and hash.

The manifest records:

- bundle schema version and creation time
- PostgreSQL server version and numeric version
- coordinator state schema version
- model version and round
- exact applied migration ledger
- dump path, size, and SHA-256
- audit export path, size, SHA-256, terminal sequence, and terminal event hash
- S3 bucket/key plus artifact size and SHA-256 when the model is externalized

`manifest.sha256` detects accidental or unilateral modification of `manifest.json`. It is an integrity checksum, not an authenticated signature. An attacker able to replace both files can replace the checksum too. Signed recovery manifests are a future supply-chain/release hardening concern.

## Atomic publication

Backup output is first written into a temporary directory beside the requested destination. Files are verified, the manifest/checksum are written last, the directory is synchronized, and the temporary directory is atomically renamed to the final path. An existing destination is never overwritten.

A failed backup leaves no published bundle at the requested destination.

## Backup

The recommended operator surface is the pinned recovery image. It uses the same PostgreSQL 18.6 Alpine image family as the v0.6 reference database, so `pg_dump`/`pg_restore` do not depend on the host package version.

Build it:

```bash
docker build -f docker/Dockerfile.recovery -t zerotrust-fl-recovery:local .
```

Run a backup with the database/S3 network reachable from the container and a writable backup mount. Example environment variables mirror the coordinator configuration:

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

The CLI form is:

```text
ztfl-recovery backup --output /recovery/backup-YYYYMMDD-HHMMSS
```

The PostgreSQL password is removed from the DSN passed in the `pg_dump` process arguments and is supplied through `PGPASSWORD` to reduce accidental process-argument exposure. Credentials are never written into the recovery bundle.

## Restore

Restore is intentionally stricter than backup:

1. manifest checksum and strict JSON schema are verified;
2. dump/audit/artifact file paths, sizes, and SHA-256 values are verified;
3. `audit.ndjson` is decoded and the complete hash chain is verified;
4. the model artifact is restored first and its resulting bucket/key/digest/size must exactly match the manifest;
5. the target PostgreSQL public schema must contain zero tables;
6. `pg_restore --exit-on-error --no-owner --no-privileges` restores the three durable tables;
7. the normal PostgreSQL state-store migration checks run;
8. the model artifact is loaded and digest-verified through the normal coordinator storage path;
9. model version/round, migration ledger, artifact reference, audit length, and audit terminal hash are compared with the manifest.

The restore command requires an explicit approval flag:

```text
ztfl-recovery restore --input /recovery/backup-YYYYMMDD-HHMMSS --allow-destructive
```

The target database must be dedicated and clean. The tool refuses to restore into a PostgreSQL database whose `public` schema already contains tables. It does not automatically drop production data.

The restore uses the same S3 bucket and content-addressed prefix contract recorded in the PostgreSQL metadata. It intentionally refuses hidden bucket/prefix remapping. If a different object namespace is required, use an explicit migration procedure rather than rewriting recovery metadata silently.

## Tool compatibility

The recovery CLI reads the source PostgreSQL numeric server version. `pg_dump` and `pg_restore` older than the source PostgreSQL major version are rejected. The supplied recovery image is pinned to `postgres:18.6-alpine` for the v0.6 reference profile.

The CI wrappers also execute PostgreSQL 18.6 tooling in a container instead of relying on whatever PostgreSQL client happens to be installed on the GitHub runner.

## CI disaster-recovery gate

The PostgreSQL/S3 CI job performs a destructive recovery test against disposable fixtures:

1. creates audited coordinator state with an externalized model artifact and registration lifecycle metadata;
2. creates a recovery bundle using PostgreSQL 18.6 `pg_dump`;
3. drops all ZeroTrust-FL PostgreSQL tables;
4. deletes the referenced S3 object;
5. restores the bundle into the now-clean database/object namespace;
6. validates restored state, model version/round, registration generation, migration ledger, object digest, and audit-chain head;
7. builds the pinned recovery image.

This gate supplements, rather than replaces, the existing coordinator restart-recovery and Docker benchmark gates.

## Security and operational boundaries

- The backup bundle contains durable coordinator state. Registration IDs are opaque bearer-like runtime credentials and are already part of the supported durable state format. Protect the bundle as sensitive operational data.
- No private PKI/JWT key material is included by this workflow.
- S3/PostgreSQL credentials are runtime inputs and are not serialized into the manifest or bundle files.
- `manifest.sha256` is not a digital signature or remote attestation.
- The workflow does not implement encrypted backups. Operators should use encrypted storage/transport appropriate to their environment.
- RPO depends on backup frequency. RTO depends on database/object size, network/storage throughput, PostgreSQL restore speed, and operator procedures. This tranche does not publish measured RPO/RTO guarantees.
- The reference implementation is single-coordinator/single-writer. Multi-coordinator fencing, consensus, and distributed backup coordination remain outside v0.6.
