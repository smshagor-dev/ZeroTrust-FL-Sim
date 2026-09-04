# Durable coordinator state foundation

This document describes the first durable-state slice for the v0.6 roadmap: the reference filesystem implementation and restart-recovery contract. The PostgreSQL metadata backend and database-migration layer are documented separately in [`postgres-state-v0.6.md`](postgres-state-v0.6.md). Neither backend provides multi-coordinator high availability.

## What is persisted

When `ZTFL_STATE_FILE` or `--state-file` is configured, the coordinator persists a schema-versioned snapshot containing:

- the current global-model protobuf, model version, round ID, payload format, and digest;
- pending per-worker update vectors and sample counts for a round that has not reached quorum;
- active certificate-bound registration leases;
- recent request nonces that are still inside the replay-protection window;
- active per-worker update-rate windows; and
- recovery-critical coordinator policy: registration lease duration, maximum update size, quorum, update-rate limit, and aggregation method.

The filesystem backend is capped at 256 MiB per snapshot. A state file is treated as sensitive because it contains worker registration IDs and pending model updates.

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

## Startup and recovery

On startup with durable mode enabled:

- a missing state snapshot creates and commits a bootstrap snapshot;
- an existing supported snapshot is strictly decoded and validated;
- unknown fields, unsupported schema versions, invalid model digests, malformed/non-finite pending updates, duplicate bindings, or impossible quorum state cause startup to fail closed;
- expired registration leases are discarded;
- stale nonce and rate-limit entries are discarded according to their existing windows; and
- the recovered state is normalized and committed again.

Recovery-critical policy must exactly match the runtime configuration. For example, changing `ZTFL_MIN_UPDATES` or the aggregation method while reusing existing durable state is rejected. This prevents a partially collected round from being reinterpreted under different trust or quorum assumptions.

## Filesystem safety

The reference store rejects a final state path that is a symbolic link or a non-regular file, uses a bounded read, rejects unknown JSON fields, and writes the committed file with `0600` permissions. The parent path is assumed to be operator-controlled. Hardened `openat`/`O_NOFOLLOW` traversal and remote object-store semantics are future work.

The Docker image creates `/var/lib/zerotrust-fl` owned by the non-root coordinator UID. Default Docker Compose sets:

```text
ZTFL_STATE_FILE=/var/lib/zerotrust-fl/coordinator-state.json
```

and mounts a dedicated `coordinator_state` named volume there. Ordinary coordinator container restarts therefore reuse the committed snapshot.

## Backup and restore

For the filesystem backend, a backup is a copy of the last committed state file. Prefer taking the copy while the coordinator is stopped or otherwise quiesced. The atomic rename means readers see either the previous complete snapshot or the new complete snapshot, not a partially written destination file.

Restore the snapshot only with the same supported state schema and recovery-critical coordinator policy. Keep backup copies protected as sensitive data.

The PostgreSQL backend has its own migration ledger and backup/restore guidance in [`postgres-state-v0.6.md`](postgres-state-v0.6.md).

## CI recovery gate

The Docker integration job freezes workers, copies selected filesystem durable state, restarts the coordinator, waits for health, and verifies that the model protobuf, recovery policy, and pending-round state survive the restart. Workers are then resumed and the existing benchmark smoke suite runs against the recovered cluster.

A separate CI job exercises the PostgreSQL backend against a real PostgreSQL service, including migration, round-trip, reconnect, overwrite, and fail-closed schema checks.

## Deliberate limitations

The combined filesystem and PostgreSQL slices still do not claim full v0.6 completion. In particular, they do not yet provide:

- an S3-compatible model artifact store;
- Redis-backed distributed leases or rate limits;
- multi-coordinator fencing or consensus;
- automated backup scheduling or restore drills;
- durable audit export; or
- credential-rotation and revocation lifecycle persistence.

The `StateStore` interface retains one recovery contract across the filesystem and PostgreSQL implementations so later artifact-store and operational changes do not need to rewrite hardened coordinator RPC semantics.
