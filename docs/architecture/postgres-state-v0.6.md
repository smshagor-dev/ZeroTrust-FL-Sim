# PostgreSQL durable coordinator state

This document describes the PostgreSQL metadata slice of the v0.6 durability roadmap. It extends the filesystem `StateStore` foundation without changing coordinator RPC validation, aggregation, replay protection, or recovery semantics.

Non-empty global-model payloads can be separated into the S3-compatible artifact layer documented in [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md). Successful recovery-critical PostgreSQL transitions can additionally be recorded in the durable audit chain documented in [`durable-audit-v0.6.md`](durable-audit-v0.6.md). PostgreSQL remains the authoritative metadata/state-publication store. These capabilities still do not provide multi-coordinator high availability or complete v0.6 readiness.

## Backend selection

The coordinator supports these startup modes:

- volatile: both `ZTFL_STATE_FILE` and `ZTFL_POSTGRES_DSN` are empty;
- filesystem: `ZTFL_STATE_FILE` is set;
- PostgreSQL inline: `ZTFL_POSTGRES_DSN` is set without S3 configuration; and
- PostgreSQL + S3-compatible artifacts: PostgreSQL is set together with a complete S3 configuration.

Filesystem and PostgreSQL configuration are mutually exclusive. S3 model artifacts require PostgreSQL and cannot be enabled with volatile or filesystem state. Partial S3 configuration causes startup to fail before serving requests.

PostgreSQL initialization is fail-closed: the coordinator must connect, apply/validate migrations, and recover or initialize the durable snapshot before the gRPC service starts. In PostgreSQL mode the issue #46 durable audit chain is automatically attached to successful recovery-critical state transitions; no separate audit DSN is used.

## Storage model

The PostgreSQL backend preserves the existing `StateStore` whole-snapshot contract. A singleton `ztfl_coordinator_state` row contains recovery-critical state:

- state schema version;
- coordinator policy;
- serialized global-model protobuf;
- pending worker updates;
- active registration leases;
- replay nonces;
- rate-limit windows; and
- optional model-artifact bucket/key/digest/size fields.

`ztfl_audit_events` is a separate append-only-by-application-contract chain of successful recovery-critical transition metadata. It is not used to reconstruct coordinator state and therefore does not create a second state machine.

JSONB is used for structured coordinator/audit metadata and `BYTEA` for protobuf/digest fields. Without an artifact backend, PostgreSQL remains backward-compatible with inline `weights_payload`. With an artifact backend, the stored protobuf retains model version/round/format/SHA metadata but removes `weights_payload`; the payload is reconstructed from the validated content-addressed object on load.

## Commit and recovery semantics

Before every PostgreSQL commit, the same `StateSnapshot` validation used by the filesystem backend runs. Invalid policy, malformed model metadata, digest mismatch, non-finite pending values, duplicate registrations/nonces, or impossible quorum state are rejected before database mutation.

An ordinary metadata commit uses a PostgreSQL `SERIALIZABLE` transaction and an upsert of the singleton state row. For successful mutating transitions that carry durable audit metadata, the state-row update and one or more audit appends share the **same** serializable transaction. The durable service acknowledges a mutating RPC only after that transaction succeeds.

If an audited transition cannot append its audit event, PostgreSQL rolls back the state-row update. The durable-service rollback path then restores the previous in-memory snapshot and returns an internal error rather than acknowledging an unaudited durable transition.

In artifact mode, the content-addressed object is ensured before the PostgreSQL transaction writes its reference. PostgreSQL is still the publication boundary. A database failure can leave an unreferenced immutable object, but cannot publish a state row or audit chain that was only partially committed.

On startup, a missing singleton row maps to `ErrStateNotFound`, so the durable service initializes the bootstrap model. PostgreSQL bootstrap initialization commits the state together with a `coordinator.state.initialized` audit event. Existing state is strictly decoded, protobuf-decoded, validated, policy-checked, normalized, and recommitted; successful recovery normalization appends `coordinator.state.recovered`.

Legacy inline rows remain readable after the artifact-reference migration. When an artifact backend is configured, recovery normalization externalizes the legacy non-empty payload automatically. Conversely, an artifact-backed row cannot be loaded without its configured artifact store.

## Migrations

Versioned SQL migrations live under:

```text
pkg/coordinator/migrations/
```

The binary embeds those migrations and maintains `ztfl_schema_migrations` in PostgreSQL. Migration execution uses a transaction-scoped advisory lock so simultaneous coordinator startups do not race schema changes.

Current migrations include:

- `001_coordinator_state.sql`: durable singleton state table;
- `002_model_artifact_reference.sql`: nullable, all-or-none model artifact reference columns with digest/size constraints; and
- `003_audit_events.sql`: durable audit sequence, canonical event payload, previous-hash and event-hash storage/indexes.

Startup fails if the database contains:

- an applied migration version that is unknown to the running binary; or
- a known migration version with a different migration filename.

This prevents an older or mismatched coordinator binary from silently operating against a schema it does not understand.

Schema migration and coordinator state schema are separate concepts. `ztfl_schema_migrations` tracks database DDL evolution, while `state_schema_version` identifies the serialized coordinator snapshot contract. Audit payloads have their own explicit audit schema version.

## Docker reference overlay

`docker-compose.postgres.yml` adds PostgreSQL on the existing internal control-plane network and switches the coordinator from `ZTFL_STATE_FILE` to `ZTFL_POSTGRES_DSN`.

The overlay intentionally requires the operator to provide database credentials/DSN instead of shipping a production password. PostgreSQL is not published on a host port by the overlay.

For local-only evaluation, configure values such as:

```text
ZTFL_POSTGRES_USER=ztfl
ZTFL_POSTGRES_DB=zerotrust_fl
ZTFL_POSTGRES_PASSWORD=<local-secret>
ZTFL_POSTGRES_DSN=postgres://ztfl:<url-encoded-local-secret>@postgres:5432/zerotrust_fl?sslmode=disable
```

`sslmode=disable` is appropriate only for an isolated local Docker network. Multi-host or production deployments must use authenticated PostgreSQL TLS and externally managed credentials appropriate to that environment.

The S3-compatible artifact path is configured separately. Plain HTTP object-store access is rejected unless an explicit local/test opt-in is enabled. Production deployments should use HTTPS and externally managed object-store credentials.

## Backup and restore

Audited PostgreSQL backups must include:

- `ztfl_coordinator_state`;
- `ztfl_audit_events`; and
- `ztfl_schema_migrations`.

Treat backups as sensitive because registration/update metadata and pending model updates are present. The audit table stores hashes of registration identifiers rather than plaintext registration bearer IDs, but it still contains operational identities/timing/model metadata.

A PostgreSQL custom-format backup can be taken with an operator-controlled DSN:

```text
pg_dump --format=custom --no-owner --no-acl --file=zerotrust-fl-state.dump "$ZTFL_POSTGRES_DSN"
```

Restore into a compatible PostgreSQL database while the coordinator is stopped or otherwise prevented from mutating the state:

```text
pg_restore --clean --if-exists --no-owner --no-acl --dbname="$ZTFL_POSTGRES_DSN" zerotrust-fl-state.dump
```

After restore, start a coordinator binary that contains every migration recorded in `ztfl_schema_migrations` and uses the same recovery-critical coordinator policy. Startup validation rejects unsupported migration/state versions or policy drift.

For artifact-backed rows, the database backup must be paired with an object-store backup that contains every referenced model object. Restore referenced objects before starting the coordinator. Detailed ordering and integrity requirements are in [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md).

For audited deployments, keep state, audit, migration ledger, and referenced object-store backup at a consistent recovery point. After restore, run the verified exporter from sequence zero or another independently trusted checkpoint to detect chain discontinuity or tampering. The SHA-256 chain is tamper-evident; it is not an external authenticity anchor or protection against a fully privileged database actor rewriting a complete replacement history.

Backup encryption, retention, point-in-time recovery, replica strategy, object versioning, immutable backup policy, and periodic restore drills remain operator responsibilities until later roadmap work automates them.

## CI coverage

The durable-state CI workflow runs PostgreSQL plus a pinned S3-compatible local fixture and verifies:

- automatic database migrations, including migration `003`;
- missing-state handling;
- inline snapshot commit/load round-trip;
- overwrite semantics;
- pool close/reconnect recovery;
- legacy inline model migration to object storage;
- metadata-only PostgreSQL model storage after externalization;
- artifact-backed reconnect recovery;
- rejection when the artifact backend is missing;
- rejection of corrupted object bytes/digest mismatch;
- state+audit transaction atomicity when audit insertion is forced to fail;
- bootstrap/restart audit chain continuity;
- cursor validation and missing-cursor rejection;
- audit payload tamper detection;
- rejection of invalid snapshots and unsupported state schema versions; and
- rejection of unknown future database migrations.

The existing Docker integration job continues to exercise filesystem durability, coordinator restart recovery, worker recovery, PKI stability, and benchmark smoke tests. It also validates the PostgreSQL compose overlay. Filesystem mode does not claim the PostgreSQL durable audit chain.

## Remaining v0.6 work

The PostgreSQL, S3-compatible artifact, and durable-audit slices do not claim full v0.6 completion. Remaining gates include:

- explicit credential rotation and revocation lifecycle persistence;
- stronger automated backup/restore validation;
- automatic artifact lifecycle/garbage collection if it becomes a supported operational feature; and
- optional distributed lease/rate-limit state and any future multi-coordinator fencing design.

Comprehensive durable auditing of requests rejected before a successful state transition and externally anchored/signed audit checkpoints are not claimed by issue #46.

No high-availability or consensus guarantee is provided by this PostgreSQL backend. The durable coordinator remains a single-writer reference service.
