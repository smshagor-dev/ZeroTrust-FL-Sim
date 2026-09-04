# Durable coordinator audit chain and export

This document describes the durable-audit slice of the v0.6 roadmap. It adds a PostgreSQL-backed, append-only-by-application-contract audit chain for successful recovery-critical coordinator transitions and a verified NDJSON export command. It does not change coordinator authentication, authorization, replay protection, aggregation, or model validation semantics.

This slice is intentionally scoped. It is **not** a claim of comprehensive security-event auditing: requests rejected before a successful durable state transition, including many authentication and authorization failures, are not durably recorded by this mechanism. The filesystem state backend also does not receive this PostgreSQL audit chain.

## Audited transitions

When PostgreSQL is the durable state backend, the coordinator appends events for:

- bootstrap durable-state initialization;
- restart recovery and normalization;
- successful node registration;
- successful registration-lease renewal;
- each accepted local model update; and
- round aggregation/model advancement when an accepted update reaches quorum.

Read-only `GetGlobalModel` calls are not part of the durable transition chain. Rejected RPCs are not claimed as comprehensively audited by this slice.

## Secret-minimized event model

Audit events use a versioned fixed schema. Records may include node ID, update ID, update/model SHA-256 digests, round/model version, sample count, quorum, aggregation method, lease expiry, and a SHA-256 hash of the registration identifier.

The durable audit payload intentionally excludes:

- plaintext registration bearer identifiers;
- request nonces;
- JWTs or bearer-token contents;
- model/update payload bytes;
- private keys or certificate private material;
- PostgreSQL credentials; and
- object-store credentials.

The registration identifier hash is an audit correlation value, not a password-storage construction. Operators should still treat audit exports as sensitive operational data because node identities, timing, model versions, and update metadata are present.

## Atomic publication semantics

For successful mutating coordinator RPCs in PostgreSQL mode, the state snapshot and associated audit event or events are committed in the **same PostgreSQL `SERIALIZABLE` transaction**.

The sequence is:

1. hardened coordinator logic validates and applies the transition in memory;
2. the durable wrapper captures the resulting state and builds secret-minimized audit metadata;
3. model artifact bytes are ensured first when S3-compatible storage is enabled;
4. PostgreSQL begins one serializable transaction;
5. the singleton coordinator state row is updated;
6. the audit chain head is locked with a transaction-scoped advisory lock;
7. one or more audit records are appended; and
8. the transaction commits before the RPC is acknowledged.

If the audit append fails, the PostgreSQL transaction rolls back the state-row update. The existing durable-service rollback path then restores the previous in-memory state and returns an internal error instead of acknowledging an unaudited durable transition.

As with model artifacts, an S3 object ensured before the PostgreSQL transaction can remain as an unreferenced content-addressed orphan if the database transaction fails. PostgreSQL remains the publication authority.

## Hash chain

Each audit row has a monotonically increasing sequence, deterministic event ID, optional previous-event hash, and event hash. The event hash is SHA-256 over a canonical envelope containing:

- sequence;
- event ID;
- previous hash; and
- the canonical versioned audit event payload.

The chain therefore detects payload modification, sequence gaps, event-ID changes, and broken previous-hash links when verified from a trusted starting point.

This mechanism is **tamper-evident, not tamper-proof**. A database principal with enough privilege to rewrite the complete history could recalculate an internally consistent replacement chain. This slice does not provide an external signed checkpoint, transparency log, WORM storage guarantee, HSM/KMS signature, or cryptographic non-repudiation claim.

## Database migration

The audit table is introduced by:

```text
pkg/coordinator/migrations/003_audit_events.sql
```

`ztfl_audit_events` stores the sequence, event ID, timestamp, event type, JSONB event payload, previous hash, and event hash. Hash lengths and key uniqueness are constrained by PostgreSQL. The application only appends records; automatic retention/deletion and immutable-database policy are not implemented in this tranche.

## Verified NDJSON export

The standalone exporter reads from PostgreSQL, verifies the requested cursor and every returned record, and only then emits NDJSON:

```text
ZTFL_POSTGRES_DSN='<operator-managed-dsn>' \
  go run ./cmd/audit-export \
  --after-sequence 0 \
  --limit 1000 \
  --output audit.ndjson
```

Use `--output -` to write NDJSON to stdout. File output uses create-new semantics and mode `0600`; an existing path is not overwritten. Partial output is removed if export fails.

`--limit` must be between 1 and 10000. For pagination, use the `last_sequence` printed to stderr as the next `--after-sequence` value. A non-zero cursor must exist and its own event hash/link is verified before subsequent records are accepted. Missing or tampered cursor state fails closed.

The DSN is accepted through `ZTFL_POSTGRES_DSN`, not a command-line DSN flag, to avoid putting database credentials directly in a normal process argument list.

## Backup and restore

A PostgreSQL backup for an audited deployment must include:

- `ztfl_coordinator_state`;
- `ztfl_audit_events`; and
- `ztfl_schema_migrations`.

Take database and referenced object-store backups from an operationally consistent recovery point. After restore, restore every model object referenced by the PostgreSQL state before starting the coordinator. Then run a verified audit export from sequence zero (or another independently trusted checkpoint) as a restore validation step.

The hash chain detects inconsistent or modified restored audit rows, but it is not an external authenticity anchor. Backup encryption, retention, point-in-time recovery, immutable backup policy, and automated restore drills remain separate operational work.

## CI coverage

The PostgreSQL durability job exercises the audit path against a real PostgreSQL service and verifies:

- migration `003` application;
- atomic state plus audit commit;
- rollback of the state update when the audit insert is forced to fail;
- bootstrap and restart-recovery event continuity;
- bounded cursor-based reads;
- missing-cursor rejection;
- payload tamper detection; and
- existing PostgreSQL/S3 model-artifact recovery behavior.

The Go unit suite also covers event validation, canonical chain hashing, secret minimization, round-aggregation metadata, and NDJSON serialization.

## Remaining v0.6 work

This durable-audit slice does not complete v0.6. Remaining release work includes explicit credential rotation/revocation lifecycle persistence and stronger automated backup/restore validation. Optional distributed lease/rate-limit storage, artifact garbage collection, multi-coordinator fencing, external audit anchoring, and comprehensive rejected-request security auditing remain outside this slice unless separately promoted to supported roadmap requirements.
