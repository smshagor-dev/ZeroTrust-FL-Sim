# PostgreSQL durable coordinator state

This document describes the PostgreSQL metadata slice of the v0.6 durability roadmap. It extends the filesystem `StateStore` foundation without changing coordinator RPC validation, aggregation, replay protection, or recovery semantics.

This slice is not the complete v0.6 storage architecture. In particular, model artifacts are still stored with the coordinator snapshot and have not yet been moved to the planned S3-compatible artifact store.

## Backend selection

The coordinator supports three startup modes:

- volatile: both `ZTFL_STATE_FILE` and `ZTFL_POSTGRES_DSN` are empty;
- filesystem: `ZTFL_STATE_FILE` is set; and
- PostgreSQL: `ZTFL_POSTGRES_DSN` is set.

Filesystem and PostgreSQL configuration are mutually exclusive. Supplying both causes startup to fail before the coordinator begins serving requests.

PostgreSQL initialization is also fail-closed: the coordinator must connect, apply/validate migrations, and recover or initialize the durable snapshot before the gRPC service starts.

## Storage model

The PostgreSQL backend preserves the existing `StateStore` whole-snapshot contract. A single `ztfl_coordinator_state` row contains the recovery-critical state:

- state schema version;
- coordinator policy;
- serialized global-model protobuf;
- pending worker updates;
- active registration leases;
- replay nonces; and
- rate-limit windows.

JSONB is used for structured coordinator metadata and `BYTEA` for the serialized global-model protobuf. Keeping one singleton row means one committed PostgreSQL transaction represents one coordinator state transition. Readers observe either the previous committed snapshot or the new committed snapshot, never a partially updated set of recovery fields.

The model protobuf in PostgreSQL is an intentional transitional design. The v0.6 target still requires an S3-compatible artifact store so large model payloads can be separated from transactional metadata while preserving digest/version references.

## Commit and recovery semantics

Before every PostgreSQL commit, the same `StateSnapshot` validation used by the filesystem backend runs. Invalid policy, malformed model metadata, digest mismatch, non-finite pending values, duplicate registrations/nonces, or impossible quorum state are rejected before database mutation.

A commit uses a PostgreSQL `SERIALIZABLE` transaction and an upsert of the singleton state row. The durable service acknowledges a mutating RPC only after the store commit succeeds. If persistence fails, the existing durable-service rollback path restores the previous in-memory snapshot and returns an internal error.

On startup, a missing singleton row maps to `ErrStateNotFound`, so the durable service initializes and commits the bootstrap model. Existing state is strictly decoded, protobuf-decoded, validated, policy-checked, normalized, and recommitted through the same recovery path used by the filesystem backend.

## Migrations

Versioned SQL migrations live under:

```text
pkg/coordinator/migrations/
```

The binary embeds those migrations and maintains `ztfl_schema_migrations` in PostgreSQL. Migration execution uses a transaction-scoped advisory lock so simultaneous coordinator startups do not race schema changes.

Startup fails if the database contains:

- an applied migration version that is unknown to the running binary; or
- a known migration version with a different migration filename.

This prevents an older or mismatched coordinator binary from silently operating against a schema it does not understand.

Schema migration and coordinator state schema are separate concepts. `ztfl_schema_migrations` tracks database DDL evolution, while `state_schema_version` identifies the serialized coordinator snapshot contract.

## Docker reference overlay

`docker-compose.postgres.yml` adds a PostgreSQL 18.6 service on the existing internal control-plane network and switches the coordinator from `ZTFL_STATE_FILE` to `ZTFL_POSTGRES_DSN`.

The overlay intentionally requires the operator to provide database credentials/DSN instead of shipping a production password. PostgreSQL is not published on a host port by the overlay.

For local-only evaluation, configure values such as:

```text
ZTFL_POSTGRES_USER=ztfl
ZTFL_POSTGRES_DB=zerotrust_fl
ZTFL_POSTGRES_PASSWORD=<local-secret>
ZTFL_POSTGRES_DSN=postgres://ztfl:<url-encoded-local-secret>@postgres:5432/zerotrust_fl?sslmode=disable
```

Then start the reference stack with both compose files. `sslmode=disable` is appropriate only for the isolated local Docker network used by this reference overlay. Multi-host or production deployments must use authenticated PostgreSQL TLS and externally managed credentials appropriate to that environment.

## Backup and restore

Backups must include both `ztfl_coordinator_state` and `ztfl_schema_migrations`. Treat backups as sensitive because registration identifiers and pending model updates are present.

A PostgreSQL custom-format backup can be taken with an operator-controlled DSN:

```text
pg_dump --format=custom --no-owner --no-acl --file=zerotrust-fl-state.dump "$ZTFL_POSTGRES_DSN"
```

Restore into a compatible PostgreSQL database while the coordinator is stopped or otherwise prevented from mutating the state:

```text
pg_restore --clean --if-exists --no-owner --no-acl --dbname="$ZTFL_POSTGRES_DSN" zerotrust-fl-state.dump
```

After restore, start a coordinator binary that contains every migration recorded in the restored `ztfl_schema_migrations` table and uses the same recovery-critical coordinator policy. Startup validation will reject unsupported migration/state versions or policy drift.

For production operations, backup encryption, retention, access control, point-in-time recovery, replica strategy, and periodic restore drills remain operator responsibilities until a later roadmap slice provides automated tooling.

## CI coverage

The CI workflow runs PostgreSQL as an isolated service and verifies:

- automatic migration application;
- missing-state handling;
- snapshot commit/load round-trip;
- overwrite semantics;
- pool close/reconnect recovery;
- rejection of invalid snapshots;
- fail-closed handling of unsupported state schema versions; and
- rejection of unknown future database migrations.

The existing Docker integration job continues to exercise filesystem durability, coordinator restart recovery, worker recovery, PKI stability, and benchmark smoke tests. It also validates that the PostgreSQL compose overlay resolves correctly.

## Remaining v0.6 work

This slice does not claim full v0.6 completion. Remaining gates include:

- S3-compatible immutable model artifact storage with transactional metadata references;
- durable audit event export;
- explicit credential rotation and revocation lifecycle persistence;
- stronger automated backup/restore validation; and
- optional distributed lease/rate-limit state and any future multi-coordinator fencing design.

No high-availability or consensus guarantee is provided by this PostgreSQL backend. The durable coordinator remains a single-writer reference service.
