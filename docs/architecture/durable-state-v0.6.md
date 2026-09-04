# Durable coordinator state foundation

This document describes the durable-state recovery contract established for the v0.6 roadmap. The reference filesystem backend is described here, the PostgreSQL metadata backend and migration layer are documented in [`postgres-state-v0.6.md`](postgres-state-v0.6.md), S3-compatible global-model separation is documented in [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md), and PostgreSQL durable transition auditing is documented in [`durable-audit-v0.6.md`](durable-audit-v0.6.md). None of these slices provides multi-coordinator high availability.

## What is persisted

When `ZTFL_STATE_FILE` or `--state-file` is configured, the coordinator persists a schema-versioned snapshot containing:

- the current global-model protobuf, model version, round ID, payload format, and digest;
- pending per-worker update vectors and sample counts for a round that has not reached quorum;
- active certificate-bound registration leases;
- recent request nonces that are still inside the replay-protection window;
- active per-worker update-rate windows; and
- recovery-critical coordinator policy: registration lease duration, maximum update size, quorum, update-rate limit, and aggregation method.

The filesystem backend is capped at 256 MiB per snapshot. A state file is treated as sensitive because it contains worker registration IDs and pending model updates. The filesystem backend does **not** provide the PostgreSQL hash-chained durable audit trail introduced by issue #46.

In PostgreSQL+S3 mode, recovery metadata is committed in PostgreSQL while non-empty global-model payload bytes are stored as content-addressed objects. PostgreSQL remains the state-publication authority and the loaded object is verified before the normal snapshot validator runs. Successful recovery-critical PostgreSQL transitions can also append audit records atomically with state publication.

## Commit semantics

Mutating RPCs in durable mode are serialized through the durable service wrapper. The existing hardened coordinator validates and applies the operation in memory, then the complete state snapshot is committed before success is returned to the client.

The filesystem store commits with this sequence:

1. validate the complete snapshot;
2. serialize the global model with protobuf and the envelope with JSON;
3. create a temporary file in the destination directory;
4. set the temporary file to mode `0600`;
5. write and `fsync` the temporary file;
6. atomically rename it over the previous snapshot; and
7. `fsync` the parent directory.

If persistence fails after a successful mutating operation, the service restores the previous in-memory snapshot and returns an internal error instead of acknowledging an uncommitted state transition.

Because the temporary file is created in the same directory as the destination, the rename stays on the same filesystem. Operators must place the state file on a filesystem that provides the expected atomic-rename and durability semantics.

For PostgreSQL+S3 mode, the content-addressed object is ensured before the PostgreSQL transaction publishes its reference. A failed PostgreSQL commit may therefore leave an unreferenced object, but it cannot publish a partially committed coordinator state. See [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md).

For PostgreSQL audited mutations, the state-row update and successful transition audit append share the same `SERIALIZABLE` transaction. An audit append failure therefore prevents state publication and triggers the existing durable-service rollback path. See [`durable-audit-v0.6.md`](durable-audit-v0.6.md).

## Startup and recovery

On startup with durable mode enabled:

- a missing state snapshot creates and commits a bootstrap snapshot;
- an existing supported snapshot is strictly decoded and validated;
- unknown fields, unsupported schema versions, invalid model digests, malformed/non-finite pending updates, duplicate bindings, or impossible quorum state cause startup to fail closed;
- expired registration leases are discarded;
- stale nonce and rate-limit entries are discarded according to their existing windows; and
- the recovered state is normalized and committed again.

Recovery-critical policy must exactly match the runtime configuration. For example, changing `ZTFL_MIN_UPDATES` or the aggregation method while reusing existing durable state is rejected. This prevents a partially collected round from being reinterpreted under different trust or quorum assumptions.

Artifact-backed PostgreSQL state additionally requires the configured object store to return the exact referenced object length and SHA-256. Missing/corrupt objects or a missing artifact backend fail startup rather than producing an empty or silently different model.

In PostgreSQL mode, bootstrap initialization and successful restart recovery/normalization append durable audit events. These events record transition metadata, not model payloads, JWTs, request nonces, private keys, or plaintext registration bearer identifiers.

## Filesystem safety

The reference store rejects a final state path that is a symbolic link or a non-regular file, uses a bounded read, rejects unknown JSON fields, and writes the committed file with `0600` permissions. The parent path is assumed to be operator-controlled. Hardened `openat`/`O_NOFOLLOW` traversal remains future work for the filesystem backend.

The Docker image creates `/var/lib/zerotrust-fl` owned by the non-root coordinator UID. Default Docker Compose sets:

```text
ZTFL_STATE_FILE=/var/lib/zerotrust-fl/coordinator-state.json
```

and mounts a dedicated `coordinator_state` named volume there. Ordinary coordinator container restarts therefore reuse the committed snapshot.

## Backup and restore

For the filesystem backend, a backup is a copy of the last committed state file. Prefer taking the copy while the coordinator is stopped or otherwise quiesced. The atomic rename means readers see either the previous complete snapshot or the new complete snapshot, not a partially written destination file.

Restore the snapshot only with the same supported state schema and recovery-critical coordinator policy. Keep backup copies protected as sensitive data.

The PostgreSQL backend has migration and database backup guidance in [`postgres-state-v0.6.md`](postgres-state-v0.6.md). Audited PostgreSQL backups must include the audit table and migration ledger from the same recovery point as coordinator state. Artifact-backed PostgreSQL backups must also retain every S3-compatible object referenced by the database snapshot; restore ordering and object-integrity requirements are documented in [`model-artifacts-v0.6.md`](model-artifacts-v0.6.md).

After an audited restore, a verified audit export can be used to detect a broken sequence, modified record, or inconsistent previous-hash link. This hash chain is tamper-evident but is not an external authenticity anchor.

## CI recovery gates

The Docker integration job freezes workers, copies selected filesystem durable state, restarts the coordinator, waits for health, and verifies that the model protobuf, recovery policy, and pending-round state survive the restart. Workers are then resumed and the existing benchmark smoke suite runs against the recovered cluster.

A separate durable-state CI job exercises PostgreSQL against a real PostgreSQL service. With model-artifact support enabled it also uses a pinned S3-compatible test fixture to verify inline-row migration, content-addressed externalization, reconnect recovery, missing-backend rejection, and object-digest corruption failure. The same PostgreSQL job additionally verifies audited state-transaction atomicity, restart audit continuity, cursor validation, and tamper detection.

## Deliberate limitations

The combined filesystem, PostgreSQL, S3-compatible artifact, and PostgreSQL durable-audit slices still do not claim full v0.6 completion. In particular, they do not yet provide:

- explicit credential-rotation and revocation lifecycle persistence;
- stronger automated backup scheduling and restore drills;
- Redis-backed distributed leases or rate limits;
- multi-coordinator fencing or consensus;
- automatic artifact garbage collection/lifecycle management;
- comprehensive durable auditing of requests rejected before a successful state transition; or
- an externally anchored/signed audit log.

The `StateStore` interface retains one recovery contract across the filesystem and PostgreSQL implementations, while `ModelArtifactStore` keeps model-object storage replaceable without rewriting hardened coordinator RPC semantics. PostgreSQL durable auditing is an additive capability attached to the PostgreSQL state store rather than a second coordinator state machine.
