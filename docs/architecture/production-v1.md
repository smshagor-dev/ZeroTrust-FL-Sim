# Production v1 Target Architecture

This document separates the **current implementation** from the **v1 target architecture**. Items labeled target are roadmap commitments, not present-tense production claims.

## Design principles

- zero trust between workload identity and model correctness
- fail closed on identity, schema, freshness, and model-version ambiguity
- immutable model versions and auditable round transitions
- deterministic research configuration without confusing deterministic simulation with security randomness
- robust aggregation assumptions validated before a round starts
- portable CPU baseline with optional native/CUDA acceleration
- no privileged signing material in worker runtimes
- observability that does not expose control or secrets by default

## Logical components

```text
                         Operator / CI
                              |
                     authenticated control
                              |
                    +---------v---------+
                    |   Coordinator     |
                    |   control plane   |
                    +----+----------+---+
                         |          |
                  durable state     | model artifacts
                    target          | target
                         |          |
                  +------v--+    +--v-----------+
                  | metadata |    | object store |
                  | database |    | checkpoints  |
                  +----------+    +--------------+
                         |
                  TLS 1.3 + mTLS
                         |
       +-----------------+------------------+
       |                 |                  |
 +-----v------+    +-----v------+     +-----v------+
 | Worker A   |    | Worker B   |     | Worker C   |
 | untrusted  |    | untrusted  |     | untrusted  |
 +------------+    +------------+     +------------+
```

Native C++/CUDA aggregation is an implementation backend, not an identity trust boundary. Privacy/encryption components are separate policy boundaries and must be documented according to the actual path used.

## Round state machine target

The durable v1 coordinator should expose an explicit state machine:

```text
CREATED
  -> ACCEPTING_UPDATES
  -> QUORUM_REACHED
  -> AGGREGATING
  -> COMMITTED
  -> PUBLISHED

Failure exits:
  TIMED_OUT
  ABORTED
  ROLLED_BACK
```

A transition to `COMMITTED` must atomically bind the experiment, round, input model version, accepted update IDs/digests, aggregation policy/version, output model digest, and next model version. Restart recovery must never publish a partially committed model.

## Identity and authorization

Each workload receives only its own certificate/private key/token plus public trust material. Coordinator/server credentials are separate. CA and JWT signing private keys belong in an offline/KMS/Vault boundary for non-development deployments.

Authorization is role based and RPC specific. Model correctness is never inferred from possession of a valid certificate. Registration binds node identity, role, certificate fingerprint, registration lease, and request identity.

For state-changing model updates, application metadata includes freshness and a random nonce so an otherwise valid captured request cannot be reused inside the replay window.

## Model envelope target

The current pre-v1 network path uses a constrained one-dimensional float32 NumPy representation. Stable v1 should replace/encapsulate this with a canonical model envelope containing at least:

```text
protocol_version
model_id
model_version
architecture_id
schema_hash
round_id
tensor_manifest[]:
  name
  dtype
  shape
  byte_length
payload_encoding
payload_digest
created_at
```

No pickle or executable object format should cross the trust boundary. Unknown schema/encoding must be rejected. The envelope must define how parameters and registered buffers are synchronized; until then, paths that cannot safely synchronize buffers should fail closed.

## Aggregation policy

The system distinguishes:

- **FedAvg / weighted mean** for cooperative/trusted-client assumptions
- **median / trimmed mean / Krum / Multi-Krum** for documented Byzantine threat assumptions

A client-reported sample count is untrusted metadata in a zero-trust network. Distributed weighting by sample count must therefore be either explicitly configured for a trusted/attested mode or bounded/verified by coordinator-owned enrollment metadata. Robust distributed aggregation is a v1 gate.

## Persistence target

Reference durable state should separate metadata from large model artifacts.

Metadata entities:

- experiments
- nodes and identity bindings
- registrations/leases
- rounds and transitions
- model versions
- update submissions and digests
- aggregation decisions
- security/audit events

Large payloads/checkpoints should live in content-addressed object storage with digests stored transactionally in metadata. PostgreSQL is the planned reference metadata store; S3-compatible object storage is the planned artifact interface. Redis may be used for leases/rate limits but must not become the sole source of durable model truth.

## Availability and quorum

A failed or slow worker does not automatically fail a round. A round continues while the configured minimum quorum is achievable and the selected aggregation algorithm's safety preconditions still hold. When quorum becomes impossible, the round aborts without publishing a new model.

Coordinator high availability is a post-persistence target. The current in-memory coordinator is a single process and should not be described as crash-durable or HA.

## Privacy modes

Privacy configuration must distinguish:

- reproducible simulation mode, where deterministic seeds may be intentionally recorded
- privacy/security mode, where randomness must not depend on public deterministic seeds
- full Byzantine mode, where a malicious client is allowed to ignore local clipping/DP unless enforcement comes from a trusted runtime

Any epsilon/delta claim must identify the accountant, adjacency definition, clipping policy, release count, and whether malicious workers can bypass client-side enforcement.

## Encrypted aggregation target

CKKS is considered end-to-end integrated only when the distributed worker sends ciphertext, the aggregation path performs the intended operation without plaintext access inconsistent with the threat model, and decryption-key custody is explicitly defined. Standalone cryptographic primitives or local tests do not justify a network-level encrypted-aggregation claim.

## Deployment tiers

### Development

- local Docker Compose
- ephemeral development PKI
- credentials isolated by workload volume
- coordinator/observability bound to loopback where exposed

### Server / lab

- externally provisioned certificates
- durable state once v0.6 lands
- explicit operator authentication and backup policy

### Production target

- Kubernetes/Helm
- external KMS/Vault or SPIFFE-compatible workload identity
- PostgreSQL/object storage
- NetworkPolicy, restricted security contexts, resource limits and disruption budgets
- immutable image digests
- signed artifacts, SBOM and build provenance

## Observability

Metrics/traces/logs are operational data, not an authorization channel. Telemetry endpoints should bind only to intended management networks, carry no private keys/tokens/model payloads, and support correlation by experiment/round/update identifiers. Dashboard control is disabled unless an explicit control credential is configured.

## Release boundary

A stable v1 release is allowed only after the implementation satisfies the hard gates in `ROADMAP.md`. This architecture document intentionally records target behavior that may not yet be implemented so reviewers can identify gaps rather than infer guarantees from project branding.
