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

The current network model format `application/x-npy-f32` is a constrained pre-v1 transport representation, not the final stable model-envelope contract.

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

Before v1.0, coordinator and worker components should normally use the same repository/release version. Stable v1 will define an explicit supported worker/server skew window once protocol negotiation is implemented.
