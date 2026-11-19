# CARL-FL IEEE P2 — PostgreSQL commit acknowledgment uncertainty

**Research phase:** P2, database-backed implementation evidence (2026-11-19)  
**Base revision:** `d90e230aceedd2722731d76e80226ae7429051f7`, merged P1 file-store experiment (#136)  
**Result status:** New tests registered in source and commit-pinned CI. Do **not** report outcomes as successful until the PR's PostgreSQL job and race-detector run complete.

## Hypotheses and source boundary

This experiment evaluates what the present Go `DurableService` does after a `PostgresStateStore.CommitWithAudit` returns an error despite the underlying **real serializable PostgreSQL transaction already having completed successfully**. It contrasts verified compensating rollback and uncertain compensating rollback through independently opened PostgreSQL connections.

A wrapper implements both `StateStore` and `auditedStateStore` and passes all reads/writes through real `PostgresStateStore` methods, preserving production **joint state and audit transaction** behavior. The wrapper can report:

- **E0:** a deliberately injected error **before** the database transaction begins.
- **E1:** a deliberately injected error **after** the underlying committed transaction returned success.

E1 is an application-level *lost completion signal*. It is **not** a real PostgreSQL server crash, a connection drop during `COMMIT`, or proof of cross-host exactly-once messaging. No source code is altered to bypass authentication, nonce gates, or durability controls.

## Falsifiable scenarios

| ID | Initial commit | Compensating rollback | Expected serving state | Independent DB snapshot |
| --- | --- | --- | --- | --- |
| PG-R1 | E1 after durable revocation transaction | Confirmed | No successful revocation RPC; not fenced | Original worker credential and accepted pending update present |
| PG-R2 | E1 after durable revocation transaction | E0, no rollback write | No successful revocation RPC; fenced | Worker revoked; pending update absent |
| PG-R3 | E1 after durable revocation transaction | E1 after rollback write | No successful revocation RPC; fenced | Original worker credential and pending update present |
| PG-U1 | E1 after durable quorum=1 model transaction | E0, no rollback write | No successful model-update RPC; fenced | Round 1 and consumed nonce recovered; identical replay must return `AlreadyExists` without round 2 |

Each PG-R scenario initializes a real PostgreSQL schema, enrolls an administrator and worker, persists a legitimate pending worker contribution using the actual authenticated coordinator request path, injects the controlled failures, checks the serving-process fence, independently reads the persisted policy state and opens another coordinator from that database. PG-U1 reconstructs a genuine same-identity authenticated retry after an independently initialized coordinator restarts.

## Audit interpretation: an important separate observable

`PostgresStateStore.CommitWithAudit` writes state and an append-only, hash-linked audit record atomically in one transaction. If E1 happens and the coordinator subsequently restores the *previous* state in a second transaction, the **first audit event can survive** while the corresponding revocation state has been undone.

The test deliberately logs `revoked_success_audit_events` independently from `disk_active`. This is a potentially misleading success-labelled audit history, not evidence of a successful client-acknowledged revocation. **Do not equate audit event count with accepted RPC count or current authorization state.** The existing audit event schema supports success-labelled events only; it has no compensating or supersession event for this situation. A separate design and test gate is needed before claiming unambiguous audit provenance under rollback.

## Reproduction and provenance

The PostgreSQL integration test is opt-in outside configured CI:

```bash
export ZTFL_TEST_POSTGRES_DSN='postgres://...'
go test -race -count=2 -v ./pkg/coordinator \
  -run '^TestPostgresIEEE(RevocationCommitAckAndRecovery|AmbiguousUpdateAckRejectsPostRecoveryReplay)$'
```

Under GitHub CI `.github/workflows/ci.yml`, the PostgreSQL and S3 durable-state job provides a PostgreSQL 18 test service and runs the tests. It captures an unfiltered JSONL stream in `research-artifacts/ieee-p2-postgres-commit-events.jsonl` and commit and Go version provenance. The tests reset the **isolated CI test database** for every case; never point `ZTFL_TEST_POSTGRES_DSN` at production.

## Explicit limits and next work

This covers one server process talking to a real PostgreSQL test instance with a deterministic post-commit acknowledgment-loss wrapper. It does **not** simulate actual PostgreSQL network partitions or prepared transactions, client-side transport errors, S3 artifact inconsistencies, physical power loss, leader splits, Byzantine storage, or end-to-end FL training. The comparison to real published FL protocols remains outstanding; successful tests cannot be offered as IEEE-level originality or external validation.

Next: (a) distinguish durable state convergence from **compensating audit semantics**; (b) explore real PostgreSQL commit outcome reconciliation and multi-instance fencing; (c) run scientifically faithful, separately reproducible published protocol baselines on realistic datasets, comparing security and learning costs.
