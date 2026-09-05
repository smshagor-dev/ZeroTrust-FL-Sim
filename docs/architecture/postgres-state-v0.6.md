# PostgreSQL durable coordinator state

This document describes the PostgreSQL metadata backend for the v0.6 single-coordinator durability profile. It extends the filesystem `StateStore` contract without changing coordinator RPC validation, aggregation, replay protection, or authorization semantics.

Non-empty global-model payloads can be separated into the S3-compatible artifact layer documented in [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md). Successful recovery-critical PostgreSQL transitions can additionally be recorded in the durable audit chain documented in [`durable-audit-v0.6.md`](durable-audit-v0.6.md). PostgreSQL remains the authoritative metadata/state-publication store.

## Backend selection

The coordinator supports these startup modes:

- volatile: both `ZTFL_STATE_FILE` and `ZTFL_POSTGRES_DSN` are empty;
- filesystem: `ZTFL_STATE_FILE` is set;
- PostgreSQL inline: `ZTFL_POSTGRES_DSN` is set without S3 configuration; and
- PostgreSQL + S3-compatible artifacts: PostgreSQL is set together with complete S3 configuration.

Filesystem and PostgreSQL configuration are mutually exclusive. S3 model artifacts require PostgreSQL. Partial S3 configuration causes startup to fail before serving requests.

PostgreSQL initialization is fail-closed: the coordinator connects, applies/validates database migrations, and recovers or initializes the durable snapshot before the gRPC service starts. The durable audit chain is attached to successful recovery-critical PostgreSQL state transitions automatically.

## Storage model

The PostgreSQL backend preserves the `StateStore` whole-snapshot contract. A singleton `ztfl_coordinator_state` row contains recovery-critical state:

- coordinator state schema version;
- coordinator policy, including explicit experiment identity metadata;
- serialized global-model protobuf;
- pending worker updates;
- active registration/credential lifecycle state;
- replay nonces;
- rate-limit windows; and
- optional model-artifact bucket/key/digest/size fields.

Experiment metadata contains:

- immutable experiment ID;
- authoritative experiment creation time; and
- experiment configuration SHA-256.

The configuration digest can be supplied by orchestration to bind the Go durable state to a wider canonical experiment manifest. If it is omitted, the coordinator records a narrower deterministic fingerprint of its own recovery-critical policy. Experiment identity is never inferred from model version or round state.

`ztfl_audit_events` is a separate append-only-by-application-contract chain of successful recovery-critical transition metadata. It is not used to reconstruct coordinator state and does not create a second state machine.

JSONB is used for structured coordinator/audit metadata and `BYTEA` for protobuf/digest fields. Without an artifact backend, PostgreSQL can keep model payload bytes inline. With an artifact backend, the stored protobuf retains model version/round/format/SHA metadata but removes `weights_payload`; the payload is reconstructed from the verified content-addressed object on load.

## State schema v2

New durable commits use coordinator state schema v2. The v2 snapshot contract adds the explicit experiment metadata nested inside the existing `policy` JSONB object.

No new DDL migration is required for this state-format change. The original table already stores policy as an object-valued JSONB column and permits positive `state_schema_version` values. Database DDL migrations and coordinator state schema versions remain separate concepts:

- `ztfl_schema_migrations` tracks PostgreSQL table/index evolution;
- `state_schema_version` tracks the serialized coordinator snapshot contract; and
- audit payloads retain their own schema version.

A normal coordinator startup can read a legacy state-schema-v1 row, adopt the explicitly configured runtime experiment identity once, and immediately normalize the row to state schema v2. The runtime experiment ID/configuration digest must thereafter remain stable for that durable state instance.

Recovery backup intentionally does not perform this normalization. Disaster-recovery tooling opens the source without migrations or writes, so a v1 source must first be normalized by a coordinator before backup.

Unknown future state schema versions fail closed.

## Commit and recovery semantics

Before every PostgreSQL commit, the same `StateSnapshot` validation used by the filesystem backend runs. Invalid experiment metadata/policy, malformed model metadata, digest mismatch, non-finite pending values, duplicate registrations/nonces, or impossible quorum state are rejected before mutation.

An ordinary metadata commit uses a PostgreSQL `SERIALIZABLE` transaction and an upsert of the singleton row. For successful transitions carrying durable audit metadata, the state-row update and audit append share the same transaction. The durable service acknowledges a mutating RPC only after commit succeeds.

If an audited transition cannot append its event, PostgreSQL rolls back the state-row update. The durable-service rollback path restores the previous in-memory snapshot and returns an error rather than acknowledging an unaudited durable transition.

In artifact mode, the content-addressed object is ensured before PostgreSQL publishes its reference. A database failure can leave an unreferenced immutable object but cannot publish partially committed coordinator state.

On startup, a missing singleton row maps to `ErrStateNotFound`, so the durable service initializes bootstrap state including explicit experiment metadata. Existing state is strictly decoded, validated, checked against runtime experiment identity and recovery policy, normalized, and recommitted. Persisted experiment creation time remains authoritative across restart.

Experiment ID or configuration-digest drift is rejected before recovered model/update state is accepted.

Legacy inline model rows remain readable after the artifact-reference migration. When an artifact backend is configured, recovery normalization externalizes a legacy non-empty payload automatically. Conversely, an artifact-backed row cannot be loaded without its configured artifact store.

## Database migrations

Versioned SQL migrations live under:

```text
pkg/coordinator/migrations/
```

The binary embeds them and maintains `ztfl_schema_migrations`. Migration execution uses a transaction-scoped advisory lock so simultaneous coordinator startups do not race schema changes.

Current migrations include:

- `001_coordinator_state.sql`: durable singleton state table;
- `002_model_artifact_reference.sql`: nullable all-or-none model artifact reference columns with digest/size constraints; and
- `003_audit_events.sql`: durable audit sequence, canonical event payload, previous-hash and event-hash storage/indexes.

Startup fails if the database contains an unknown applied migration version or a known version with a different filename. This prevents an older/mismatched binary from silently operating against a database schema it does not understand.

## Docker reference overlay

`docker-compose.postgres.yml` adds PostgreSQL on the internal control-plane network and switches the coordinator from filesystem state to `ZTFL_POSTGRES_DSN`.

The overlay requires operator-provided database credentials/DSN instead of shipping a production password. PostgreSQL is not published on a host port by the overlay.

For local-only evaluation:

```text
ZTFL_POSTGRES_USER=ztfl
ZTFL_POSTGRES_DB=zerotrust_fl
ZTFL_POSTGRES_PASSWORD=<local-secret>
ZTFL_POSTGRES_DSN=postgres://ztfl:<url-encoded-local-secret>@postgres:5432/zerotrust_fl?sslmode=disable
ZTFL_EXPERIMENT_ID=default
ZTFL_EXPERIMENT_CONFIG_SHA256=
```

`sslmode=disable` is appropriate only for an isolated local Docker network. Multi-host or production deployments must use authenticated PostgreSQL TLS and externally managed credentials.

For reproducible experiment runs, provide a stable `ZTFL_EXPERIMENT_ID` and a canonical full-configuration SHA-256 rather than relying on the coordinator-only fallback fingerprint.

## Backup and restore

The supported verified workflow is documented in [`disaster-recovery-v0.6.md`](disaster-recovery-v0.6.md). A recovery point binds:

- `ztfl_coordinator_state`;
- `ztfl_audit_events`;
- `ztfl_schema_migrations`;
- experiment identity/configuration metadata; and
- every referenced content-addressed model object.

The backup workflow uses an exported PostgreSQL MVCC snapshot and verifies the exact embedded migration ledger. It does not auto-migrate or rewrite the source. Restore targets must be clean and restored state is reopened without auto-migration before model, experiment, artifact, migration, and audit metadata are compared with the recovery manifest.

Treat backups as sensitive operational data. The workflow does not include PKI/JWT private keys or storage credentials, but durable registration/update state is present.

## CI coverage

The PostgreSQL/S3 durable-state CI gate verifies:

- automatic database migrations through migration `003`;
- missing-state handling;
- state-schema-v2 commit/load round-trip;
- overwrite and reconnect recovery;
- explicit experiment metadata persistence;
- legacy state-schema-v1 normalization by the coordinator path;
- experiment identity/configuration drift rejection;
- legacy inline model externalization;
- artifact-backed reconnect recovery;
- rejection when the artifact backend is missing;
- rejection of corrupt object bytes/digest mismatch;
- state+audit transaction atomicity;
- bootstrap/restart audit continuity;
- cursor and audit-chain tamper validation;
- rejection of invalid snapshots and unsupported future state schemas;
- rejection of unknown future database migrations; and
- clean-room disaster-recovery verification including experiment identity.

The existing Docker integration gate continues to exercise coordinator restart recovery, worker recovery, PKI stability, and benchmark smoke behavior.

## Boundaries

This PostgreSQL backend remains a single-writer reference service. It does not provide multi-coordinator fencing, consensus, or HA. It also does not claim signed recovery manifests, encrypted backup media, KMS/HSM integration, automatic artifact garbage collection, or measured RPO/RTO guarantees.
