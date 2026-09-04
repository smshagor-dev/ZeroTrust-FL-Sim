# Registration credential lifecycle

This document describes the v0.6 runtime registration-credential lifecycle. It extends the existing mTLS/JWT workload identity boundary with explicit rotation and lease-scoped revocation of the coordinator-issued `registration_id`.

This is **not** PKI certificate revocation or signing-key rotation. It does not provide CRL/OCSP, CA rotation, JWT signing-key rotation, KMS/HSM integration, or multi-coordinator revocation consensus.

## Credential model

A successful `RegisterNode` binds a runtime registration credential to:

- node ID from the verified client certificate;
- workload role from the certificate role OU and JWT claims;
- client-certificate SHA-256 fingerprint;
- opaque coordinator-issued `registration_id`;
- lease expiry; and
- a registration credential generation.

Legacy durable registrations that predate credential generations are interpreted as generation `1` during recovery. A replacement registration or explicit rotation increments the generation while the active registration lifecycle is retained.

The raw registration credential remains a bearer-like secret. It is persisted only as part of recovery-critical coordinator state and is never written in plaintext to the durable audit event payload.

## Rotation

`RotateRegistration` is available to an already registered `edge-worker`, `observer`, or `admin` identity.

The request must pass the normal zero-trust authorization path:

1. verified TLS 1.3 client certificate;
2. valid JWT bound to the same node ID and role;
3. an active certificate-bound registration;
4. request `node_id` matching the authenticated identity;
5. the current `registration_id`; and
6. fresh `SecurityMetadata` timestamp and nonce.

On success the coordinator creates a new cryptographically random registration ID, increments the credential generation, renews the lease, and invalidates the old registration ID immediately.

The lifecycle nonce is consumed through the existing durable replay cache. Reusing the same nonce is rejected even if the caller supplies the newly rotated credential.

A same-certificate/same-role `RegisterNode` call may also replace an active registration credential. This preserves worker restart recovery when a process has lost its in-memory registration ID. The replacement increments the generation and invalidates the previous ID. An active registration cannot be replaced by a different certificate fingerprint or role.

## Lease-scoped revocation

`RevokeRegistration` is restricted to an authenticated, currently registered `admin` identity. The service performs a defense-in-depth admin-role check in addition to the authorization policy.

A successful revocation stores:

- the target registration generation;
- revocation timestamp;
- a bounded operator reason in sensitive durable coordinator state; and
- the original registration lease expiry.

The revoked registration remains as a tombstone until its original lease expires. During that window:

- `IsRegistered` returns false;
- the old registration ID fails validation;
- heartbeat, model retrieval, model-update submission, and rotation are denied;
- `RegisterNode` cannot bypass the tombstone; and
- any pending model update and active update-rate window for the target are removed.

After the tombstone lease expires it is discarded by normal snapshot/recovery cleanup and the identity may enroll again if its mTLS/JWT credentials are otherwise valid. The generation is scoped to the retained registration lifecycle; after an expired tombstone is discarded, a later clean enrollment starts a new lifecycle.

This is intentionally not a permanent node denylist. Operators that require durable identity denial beyond the lease window need a future certificate/identity revocation control plane.

## Concurrency and replay behavior

Rotation, revocation, and model-update commit paths synchronize with the coordinator round mutation lock. `SubmitLocalUpdate` revalidates the registration after acquiring that lock, preventing an update that passed an earlier authorization check from being committed after its credential was rotated or revoked.

Rotate and revoke requests use the existing timestamp/nonce replay window. Nonce state is already part of the durable coordinator snapshot, so successful lifecycle mutations and their consumed nonces survive restart.

## Durable commit semantics

When the coordinator runs through `DurableService`, rotation and revocation are serialized by the existing persistence mutex.

For a successful lifecycle RPC:

1. capture the previous complete recovery snapshot;
2. apply the in-memory lifecycle transition;
3. capture the resulting snapshot;
4. commit the snapshot before acknowledging the RPC; and
5. when PostgreSQL audit support is active, append the lifecycle audit event in the same audited state transaction.

If persistence fails, the previous registration map, nonce cache, pending updates, rate windows, and other recovery-critical state are restored before an error is returned.

Filesystem snapshots and PostgreSQL registration JSON preserve generation and active revocation tombstones without creating a second lifecycle database. Strict nested JSON decoding rejects unknown registration fields and malformed revocation metadata while remaining compatible with legacy registrations that have no generation field.

## Audit events

Successful lifecycle transitions add secret-minimized audit event types:

- `registration.credential.rotated`; and
- `registration.revoked`.

Rotation audit metadata records the node ID, SHA-256 hash of the new opaque registration ID, lease expiry, and credential generation. Revocation records the admin actor node ID, target node ID, revoked generation, and blocked-until lease timestamp.

The operator revocation reason is deliberately not copied into the audit payload. It remains only in the sensitive recovery state. New optional lifecycle audit fields were appended to the version-1 event schema with `omitempty`, preserving canonical JSON and hash verification for existing audit records that predate this slice.

## Protocol compatibility

The protobuf service adds:

- `RotateRegistration`;
- `RevokeRegistration`;
- `credential_generation` on `RegisterNodeResponse`; and
- `credential_generation` on `HeartbeatResponse`.

All additions use new protobuf field numbers. Existing request fields and previously assigned field numbers are unchanged.

Clients that understand the new lifecycle should retain the latest returned `registration_id` and generation. A successful rotation makes the previous registration ID unusable immediately.

## Validation coverage

The lifecycle test suite covers:

- initial generation assignment;
- explicit rotation and immediate old-ID invalidation;
- same-binding restart replacement;
- rejection of active different-certificate/different-role replacement;
- nonce replay rejection on rotation;
- admin-only revocation policy;
- model-access denial after revocation;
- `RegisterNode` revocation-bypass rejection;
- removal of a revoked target's pending update/rate state;
- durable rollback after an injected persistence failure;
- filesystem restart recovery of an active revocation tombstone;
- legacy registration generation normalization;
- malformed lifecycle-state rejection;
- audit secret minimization and legacy canonical-JSON compatibility; and
- PostgreSQL lifecycle audit-chain ordering.

## Deliberate limitations

This slice does not claim:

- permanent node or certificate revocation;
- CRL or OCSP integration;
- CA/private-key rotation;
- JWT signing-key rotation or token denylisting;
- external KMS/HSM-backed credential issuance;
- distributed revocation propagation or multi-coordinator fencing; or
- administrator credential provisioning in the default Docker testbed.

An admin lifecycle RPC therefore requires an externally provisioned admin workload identity that satisfies the same mTLS/JWT policy. The coordinator image does not receive an administrator private key by default.
