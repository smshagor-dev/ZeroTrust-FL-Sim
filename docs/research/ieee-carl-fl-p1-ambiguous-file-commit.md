# IEEE CARL-FL P1 — ambiguous durable write and acknowledgement recovery

**Stage:** software validation, P1; `main` base `fa4047b8d418ded43fd59d52fdb5b01b0991519c`, 2026-11-19.  
**Status:** new runnable tests and CI instrumentation. Results are **not established** until the new GitHub CI has passed and its raw logs are inspected.

## Research question

When a state store has **already durably applied** a revocation or model update but reports an error to the coordinator, can the serving coordinator safely differentiate a fully confirmed rollback from an ambiguous outcome? After an uncertain model-update acknowledgment and a fail-stop fence, can recovery reconstruct the committed model and nonce in a way that prevents a retry from adding the same contribution again?

This study advances [P0 preregistration](ieee-carl-fl-experiment-preregistration.md) and [P1 ordering evidence](ieee-carl-fl-p1-durable-ordering.md). Unlike the previous `researchPermanentlyFailingStore` test, it wraps an **actual `FileStateStore`** and independently reloads its persisted state after each injected outcome.

## Injected fault model

The test-only `p1FaultingFileStore` forwards to a real file store with two *controlled* behaviors:

- `failBeforeWrite`: return an error without invoking underlying `Commit`.
- `failAfterWrite`: complete the underlying `Commit`, including its file and directory synchronization requirements, then return an injected error **instead of reporting success**.

The latter simulates a lost durable-operation completion signal, **not** disk, kernel, hardware or filesystem failure. It cannot establish correctness under physical power loss. The wrapper implements `StateStore`, not `auditedStateStore`, so these are coordinator-state tests and do not establish external audit-ledger atomicity.

## Falsifiable scenarios

| Scenario | First state transition (revocation) | Rollback write | Expected live coordinator | Authoritative file after operation |
| --- | --- | --- | --- | --- |
| R1 | Applied, then reports error | Succeeds | Does not acknowledge revocation; not fenced | Pre-revocation worker credential and accepted pending update |
| R2 | Applied, then reports error | Refused before write | Does not acknowledge revocation; fenced | Revoked credential and absent pending update |
| R3 | Applied, then reports error | Applied, then reports error | Does not acknowledge revocation; fenced | Pre-revocation credential and accepted pending update |
| U1 | Quorum=1 model update applied, then reports error | Refused before write | Does not acknowledge update; fenced | Model round 1 and consumed nonce |

**R1/R2/R3 restart gate:** a separately constructed coordinator must reload exactly the state observed by an independent file reader. In R2 and R3, the original live process must deny model reads while fenced. In R1, the original process must remain operational after confirmed rollback.

**U1 retry gate:** a newly authenticated client that retries the original `nonce`, `round_id`, and `base_model_version` after restart must be rejected with `AlreadyExists` and must not advance the recovered model round again.

Caveat: U1's persisted update is **not acknowledged** even though it is recoverable, so this test does **not** show exactly-once client delivery or server-side client knowledge. It examines durable duplicate prevention under one controlled ambiguity.

## Reproduction

```bash
go test -race -count=3 -v ./pkg/coordinator \
  -run '^TestIEEEFileBacked(RevocationUncertainWriteAndRecovery|AmbiguousModelUpdateAckRejectsReplayAfterRestart)$'
```

The CI research workflow records `research-artifacts/ieee-p1-ambiguous-file-events.jsonl` plus provenance. The run must pass `go test -race` and all standard CI checks before these *selected software* properties can be reported as measured.

## Limitations and next falsification targets

- This is a one-process, one-host test using a deterministic fault wrapper, **not an inter-process, multi-host, Byzantine, partition or power-loss study**.
- This is an implementation-specific test, not a published algorithm comparison or proof of a new IEEE-level contribution.
- It does not inject a failed filesystem `fsync`, partial `rename`, PostgreSQL transaction uncertainty, object-store commit, concurrent administrator leadership, cross-host message loss, or malicious storage.
- Pending-update state, tombstones, nonce history and model commit are covered only through the selected real file store transition and its current schema.
- A future investigation must examine the difference between rollback after a lost acknowledgment and *query/reconciliation* of uncertain operations, and compare exact guarantees against an independently implemented published security protocol. Do not claim novelty from this experiment alone.

**Submission gate:** hold the IEEE manuscript until independent baselines, systematic results, and original scientific contribution are established.
