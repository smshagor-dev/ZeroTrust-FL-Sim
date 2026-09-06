# Protocol Compatibility Policy

The public gRPC package `zerotrust.fl.v1` is an append-only compatibility surface for the v0.7 line. Changes must preserve existing wire identities and generated-client expectations until a new protocol package is introduced.

## Allowed changes

- add new messages or enums
- add new fields using previously unused field numbers and names
- add new enum values using previously unused numeric values and names
- add new RPC methods without changing existing methods
- add comments and non-wire documentation

New fields must remain safe when absent from older peers. A server must not silently reinterpret an existing field or require a newly added field from an older v1 peer without explicit protocol-level negotiation or a documented compatibility transition.

## Breaking changes

The following changes are not permitted in `zerotrust.fl.v1`:

- changing the protobuf package or syntax
- removing or renaming an existing message or enum
- removing, renaming, or renumbering an existing field
- changing an existing field type, cardinality, oneof membership, or proto3 optional presence
- removing, renaming, or renumbering an existing enum value
- removing or renaming an existing RPC
- changing an RPC request type, response type, or streaming mode
- reusing an existing field or enum number for different semantics

Deprecation does not authorize removal inside the v1 package. A compatibility-breaking redesign requires a new versioned protobuf package such as `zerotrust.fl.v2`, with an explicit migration plan and coexistence period where needed.

## CI enforcement

Pull-request CI compiles both the target branch version and the proposed version of `proto/fl_service.proto` into protobuf descriptor sets. The repository-owned compatibility checker compares the target descriptor against the proposed descriptor and fails closed on any breaking change listed above. Additive changes pass.

The checker is intentionally independent of generated Go or Python source so compatibility is evaluated at the protobuf contract boundary rather than by language-specific code generation details.

## Operator and SDK compatibility

Wire compatibility does not by itself guarantee behavioral compatibility. Changes that alter authentication requirements, model-envelope validation, error semantics, or required runtime behavior must also update the Python SDK, operator documentation, tests, and deployment examples in the same change.
