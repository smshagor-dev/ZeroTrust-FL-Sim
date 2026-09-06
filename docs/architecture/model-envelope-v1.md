# Model Envelope v1

The ZeroTrust-FL-Sim network model envelope makes model identity and tensor-schema assumptions explicit at the coordinator/worker boundary. It is intentionally narrower than a general checkpoint format: the current transport remains one flattened `float32` vector serialized as non-pickle NumPy `.npy` bytes.

## Envelope fields

A payload-bearing `GlobalModel` carries:

- `protocol_version = 1`
- `model_id`
- `model_version` and `round_id`
- `weights_format = application/x-npy-f32`
- `weights_payload`
- payload `sha256`
- `schema_sha256`
- `tensor_manifest`

A `SubmitLocalUpdateRequest` carries the same protocol/model/schema identity in addition to its update digest, base model version, round, metrics, registration identity, and security metadata.

The current manifest contains one entry:

- name: `flat_weights`
- dtype: `float32`
- dimensions: `[N]`
- element count: `N`

`N` is derived from the decoded NPY vector. Workers and the coordinator do not trust a caller-provided dimension independently of the payload.

## Validation order

Before a local update reaches the existing coordinator aggregation path, the network envelope adapter validates:

1. the supported protocol version
2. the exact configured model ID
3. presence of a 32-byte schema SHA-256
4. successful decoding as the supported finite one-dimensional float32 NPY representation
5. exact manifest equality with the decoded payload
6. recomputed canonical schema digest equality
7. schema compatibility with the current payload-bearing global model

The wrapped coordinator then applies its existing registration, lease, replay, base-version, round, digest, finite-value, request-size, duplicate, rate-limit, and aggregation checks. Envelope validation does not replace those controls.

## Bootstrap behavior

A payload-free bootstrap global model has no tensor schema to describe. It therefore carries protocol/model identity with an empty schema digest and empty manifest. The first valid payload-bearing update can establish the vector shape used to produce the first global model. Once the coordinator serves a payload-bearing global model, later updates must match that schema.

No fake/default dimension is advertised during bootstrap.

## Canonical schema SHA-256

The schema digest is independent of protobuf binary serialization so Go and Python compute the same identifier deterministically.

The bytes hashed by SHA-256 are:

1. domain bytes `ztfl-model-schema-v1` followed by a NUL byte
2. manifest entry count as big-endian uint32
3. for every manifest entry, in order:
   - tensor-name UTF-8 byte length as big-endian uint32, then the bytes
   - dtype UTF-8 byte length as big-endian uint32, then the bytes
   - dimension count as big-endian uint32
   - each dimension as big-endian uint64
   - element count as big-endian uint64

For the manifest `flat_weights`, `float32`, dimensions `[3]`, element count `3`, the canonical digest is:

`cff606025d8af83f907bc6d4c6b82000e3c22b67d16bf8a3e9999f816c1c5e64`

Both language implementations pin this value in tests.

## Model identity

The coordinator accepts `--model-id` or `ZTFL_MODEL_ID`; the reference default is `global-model`. The Python worker runtime reads the same deployment setting. Coordinator and workers must use identical values.

The model ID is not inferred from round number, model version, dataset name, or durable experiment ID. It identifies the network model contract. The experiment identity remains a separate durable-state concern.

## Durable-state compatibility

The envelope is applied at the network boundary. Existing durable protobuf state from the v0.6 reference profile is not rewritten merely to add network metadata. When a recovered global-model record contains a supported NPY payload and valid payload digest, the coordinator derives the envelope manifest and schema digest before serving it.

This preserves the existing recovery path while making new network traffic explicit. It does not promise compatibility with arbitrary historical payload formats.

## Current limits

Envelope v1 does not yet provide:

- arbitrary named multi-tensor checkpoint transport
- sparse tensor encoding
- mixed dtype models
- automatic model-schema migration
- protocol-version negotiation or a supported cross-release skew window
- persistence of a separate schema registry

Those capabilities require explicit future protocol revisions rather than silent reinterpretation of envelope v1.
