# S3-compatible global-model artifacts

This document describes the model-artifact slice of the v0.6 durable coordinator roadmap. It externalizes non-empty global-model payloads from PostgreSQL while preserving the existing `StateStore`, coordinator RPC, digest-validation, recovery, and rollback contracts.

This remains a single-writer reference design. It does not claim multi-coordinator fencing, object garbage collection, automatic lifecycle management, or complete v0.6 readiness.

## Storage split

When PostgreSQL is configured without an artifact store, the backend remains backward-compatible with the previous inline representation: the serialized `GlobalModel` protobuf, including `weights_payload`, is stored in `ztfl_coordinator_state.model_proto`.

When an S3-compatible artifact store is configured, a non-empty model payload is stored as an immutable content-addressed object and PostgreSQL stores:

- the global-model protobuf with `weights_payload` removed;
- the model SHA-256 retained in the protobuf;
- artifact bucket;
- artifact key;
- artifact SHA-256; and
- artifact byte length.

Bootstrap models have no weights payload and therefore require no artifact object.

## Content-addressed namespace

The object key is derived exclusively from the validated model digest:

```text
<prefix>/sha256/<64-lowercase-hex-sha256>.npy
```

The configured bucket, prefix, digest, and size form the complete `ModelArtifactRef`. A loaded reference is accepted only when:

- the bucket exactly matches the configured bucket;
- the digest is exactly 32 bytes;
- size is positive and within the coordinator model bound; and
- the key exactly equals the key derived from the configured prefix and digest.

This prevents a database row from turning the coordinator into an arbitrary object reader or escaping the configured content-addressed namespace.

## Write ordering and publication

A model-bearing durable commit follows this order:

1. validate the complete in-memory `StateSnapshot`;
2. compute/use the already validated model SHA-256;
3. ensure the content-addressed object exists with the expected bytes;
4. serialize a metadata-only global-model protobuf;
5. execute the existing PostgreSQL `SERIALIZABLE` state upsert with the artifact reference; and
6. acknowledge the coordinator mutation only after PostgreSQL commit succeeds.

PostgreSQL remains the authoritative publication point. Uploading an object does not make it the current model until a committed PostgreSQL snapshot references it.

If object upload succeeds but the database transaction fails, the content-addressed object may remain unreferenced. Such an object is an orphan, not a published coordinator state. Automatic orphan garbage collection is deliberately outside this tranche.

## Read and recovery integrity

For an artifact-backed row, startup/load:

1. strictly decodes PostgreSQL metadata;
2. rejects incomplete artifact references;
3. rejects a row that contains both an inline payload and an artifact reference;
4. requires a configured artifact backend;
5. verifies the protobuf digest equals the artifact-reference digest;
6. fetches the object with a bounded read;
7. requires the exact recorded byte length;
8. recomputes and verifies SHA-256;
9. hydrates `GlobalModel.weights_payload`; and
10. runs the existing complete `StateSnapshot` validator.

A missing, truncated, oversized, redirected, or digest-mismatched object causes recovery to fail closed.

## Legacy PostgreSQL rows

Migration `002_model_artifact_reference.sql` adds nullable artifact-reference columns. Existing inline rows remain readable after the migration.

When the coordinator is restarted with both PostgreSQL and the artifact store configured, the durable recovery path loads the legacy inline snapshot normally. Recovery then performs its existing normalization commit, which externalizes the non-empty model payload and writes the artifact reference. No protobuf protocol migration is required.

An artifact-backed row cannot be opened by a coordinator that has PostgreSQL configured without the corresponding artifact store. Startup fails instead of silently treating the payload as absent.

## Configuration

Artifact storage is supported only together with PostgreSQL durable state.

Non-secret settings:

```text
ZTFL_S3_ENDPOINT=https://object-store.example
ZTFL_S3_BUCKET=zerotrust-fl-models
ZTFL_S3_PREFIX=models
ZTFL_S3_REGION=us-east-1
ZTFL_S3_ALLOW_INSECURE_HTTP=false
ZTFL_S3_FORCE_PATH_STYLE=false
```

Credentials are read from environment variables rather than command-line flags:

```text
ZTFL_S3_ACCESS_KEY_ID
ZTFL_S3_SECRET_ACCESS_KEY
ZTFL_S3_SESSION_TOKEN
```

The standard `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` variables are accepted as fallbacks.

The coordinator does not log the access key, secret key, or session token.

Plain HTTP endpoints are rejected by default. `ZTFL_S3_ALLOW_INSECURE_HTTP=true` exists only for explicitly isolated local/test object stores. Production deployments should use authenticated HTTPS and externally managed credentials.

## Backup and restore ordering

A PostgreSQL backup is not sufficient once rows reference external artifacts. A recoverable backup set must include both:

- PostgreSQL state/migration metadata; and
- every object referenced by that database snapshot.

The object-store backup/snapshot must not be older than the PostgreSQL backup if that would omit objects referenced by the database. A conservative operational sequence is to retain/version model objects first, then take the PostgreSQL backup that references them.

Restore the object set before starting a coordinator against the restored PostgreSQL state. If a referenced object is absent or corrupted, startup intentionally fails closed.

Backup encryption, retention, object versioning, cross-region replication, lifecycle policies, automated restore drills, and garbage collection remain operator responsibilities or later roadmap work.

## CI coverage

The durable-state CI job runs a real PostgreSQL service plus a pinned S3-compatible local fixture and covers:

- database migration application;
- legacy inline model loading;
- externalization into a content-addressed object;
- metadata-only PostgreSQL model storage;
- artifact-backed load and reconnect recovery;
- failure when the artifact backend is omitted; and
- fail-closed digest validation after deliberate object corruption.

Unit tests separately cover endpoint security policy, bucket/prefix validation, content-addressed reference confinement, and invalid payload handling.

## Deliberate limitations

This tranche does not provide:

- multi-coordinator consensus or fencing;
- automatic orphan/object garbage collection;
- automatic bucket creation in production code;
- server-side object-lock policy enforcement;
- KMS-managed object encryption configuration;
- automated backup/restore verification;
- durable audit export; or
- credential-rotation lifecycle persistence.

Those capabilities must not be inferred from the existence of an S3-compatible backend.
