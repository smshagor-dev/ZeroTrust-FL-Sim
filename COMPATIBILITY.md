# Compatibility Policy

ZeroTrust-FL-Sim is pre-1.0. Interfaces may still change while the production protocol is being stabilized, but incompatible changes must be documented in release notes and should include a migration path when practical.

## Compatibility domains

The project treats compatibility in five independent domains:

1. **Wire protocol** — protobuf field numbering, RPC semantics, model/update serialization, authentication metadata, and version negotiation.
2. **Python API** — documented imports, configuration types, and CLI behavior intended for users.
3. **Native ABI** — C++/pybind11/CUDA extension boundaries. The Python wheel version is the compatibility unit; a stable cross-version native ABI is not currently promised.
4. **Deployment configuration** — Docker Compose, environment variables, Kubernetes/Helm values, persistence schema, and secret layout.
5. **Research reproducibility** — experiment configuration, partition strategy, attack parameters, seeds, aggregation semantics, and benchmark metadata.

## Protocol evolution

For protobuf changes:

- existing field numbers are never repurposed
- removed fields are reserved before a stable v1 protocol is declared
- new optional fields must have safe behavior for older peers
- security-required fields may become mandatory only with an explicit protocol/version transition
- a server must reject an update it cannot validate rather than silently interpreting an unknown payload format

The network model envelope currently uses `protocol_version = 1`. Payload-bearing `GlobalModel` and `SubmitLocalUpdateRequest` messages bind the transfer to an immutable `model_id`, a canonical tensor manifest, and a SHA-256 schema digest. The current tensor manifest describes one flattened `float32` vector transported as `application/x-npy-f32`; it does not claim arbitrary multi-tensor serialization support.

Envelope-v1 update submissions are fail-closed: workers must send the supported protocol version, the coordinator's exact model ID, a manifest consistent with the payload, and the matching schema SHA-256. A payload-free bootstrap global model carries protocol/model identity but no invented tensor schema. Once a payload-bearing global model exists, submitted updates must match that authoritative schema.

The canonical schema digest is language-neutral rather than protobuf-serialization-dependent. It hashes the domain `ztfl-model-schema-v1\0`, the manifest entry count, length-delimited UTF-8 tensor name and dtype, dimension count and big-endian uint64 dimensions, and big-endian uint64 element count. Go and Python tests pin the same digest vector.

The new envelope fields are additive. Existing protobuf field numbers remain unchanged, and legacy durable model records that contain the supported NPY payload format can still be recovered because the coordinator derives envelope metadata at the network boundary when serving them. This does not mean arbitrary pre-envelope clients are supported for new update submissions: workers submitting updates must implement envelope v1.

Coordinator and worker processes must use the same `ZTFL_MODEL_ID`. Changing that identity is an operator-visible compatibility change and should be treated as selecting a different model contract, not as a transparent rename.

## Platform tiers

Until release automation publishes a broader matrix, the reference CI platform is Linux x86_64. Python, Go, compiler, CUDA, and operating-system versions are supported only when they are exercised by a release's documented test matrix.

Planned v1 tiers:

- Tier 1: Linux x86_64 CPU; Docker/OCI
- Tier 1 target: Linux ARM64 CPU
- Tier 1 target: Kubernetes on supported Linux nodes
- Tier 2 target: CUDA-enabled Linux where the published CUDA matrix passes
- Tier 2 target: Windows and macOS client/development workflows where release artifacts exist

A planned target is not a current support claim.

## Deprecation

After v1.0, documented stable APIs should receive at least one minor-release deprecation period before removal unless continued behavior creates a security vulnerability or data-corruption risk. Security emergency changes may be immediate and must include an advisory/migration note.

## Version skew

Before v1.0, coordinator and worker components should normally use the same repository/release version. Envelope protocol versioning prevents silent interpretation of unknown model schemas, but it is not yet a negotiated worker/server compatibility window. Stable v1 will define an explicit supported skew window once protocol negotiation is implemented.
