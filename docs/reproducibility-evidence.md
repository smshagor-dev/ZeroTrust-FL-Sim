# Reproducibility and parity evidence

ZeroTrust-FL-Sim v0.9 treats benchmark and backend claims as evidence-bearing release statements. A benchmark number or acceleration claim is not portable unless the exact source revision, runtime, research configuration, and numerical comparison contract are recorded with it.

## CPU aggregation parity

The reference CPU release profile compares the PyTorch fallback and the C++20 native backend on one deterministic update corpus for:

- Krum;
- Multi-Krum;
- coordinate-wise trimmed mean;
- coordinate-wise median.

The release regression uses `rtol=2e-4` and `atol=2e-5`. The corpus contains seven bounded honest updates and two well-separated Byzantine outliers so the Krum selection is not intentionally placed on a numerical tie boundary. Both results must be finite, float32, shape-preserving, and within the stated tolerance.

This is numerical parity evidence for the tested algorithms and corpus. It is not a proof that every floating-point input produces bit-identical results across all compilers, CPUs, SIMD backends, or PyTorch versions.

## CUDA evidence boundary

CPU CI does not certify CUDA parity. `scripts/capture_cuda_parity_evidence.py` refuses to emit an artifact unless both conditions are true:

- PyTorch reports a real visible CUDA device;
- `zerotrust_fl_cpp` was compiled with the native CUDA backend enabled.

A successful CUDA evidence artifact records the full Git commit SHA, timestamp, deterministic seed, PyTorch and CUDA versions, native CUDA runtime version, GPU name/capability/memory, per-algorithm tolerances, and maximum absolute error. It compares CUDA Krum, Multi-Krum, and trimmed mean against the deterministic PyTorch CPU reference before writing the file.

Run it only on a real CUDA-capable runner:

```bash
python scripts/capture_cuda_parity_evidence.py \
  --commit-sha "$(git rev-parse HEAD)" \
  --seed 42 \
  --output benchmarks/results/cuda-parity.json
```

The presence of CUDA libraries in a Python wheel, CUDA toolkit metadata, or a compiled CUDA binary without an executing GPU is not accepted as CUDA parity evidence.

## Benchmark reproducibility manifest

`benchmarks/reproducibility.py` emits schema version 1 manifests. The manifest records:

- ZeroTrust-FL-Sim release version;
- exact 40-character Git commit SHA;
- generation timestamp;
- benchmark profile and selected sections;
- deterministic seed;
- dataset identity;
- partition configuration;
- privacy configuration;
- threat model;
- aggregation/backend configuration;
- benchmark command;
- Python, platform, architecture, processor, PyTorch, native extension, OpenMP, SIMD, and CUDA runtime facts;
- SHA-256 of the canonical benchmark research configuration.

The configuration digest intentionally excludes the timestamp and runtime facts. This allows two executions on different machines to prove that they used the same research configuration while still preserving their distinct hardware/runtime evidence.

Example:

```bash
python benchmarks/reproducibility.py \
  --commit-sha "$(git rev-parse HEAD)" \
  --profile quick \
  --sections aggregation convergence \
  --seed 42 \
  --dataset synthetic-classification \
  --partition-json '{"kind":"dirichlet","alpha":0.5,"seed":42}' \
  --privacy-json '{"local_dp":false,"ckks":false}' \
  --threat-model-json '{"malicious_fraction":0.2,"attack":"sign_flip"}' \
  --aggregation-json '{"method":"multi_krum","backend":"native","f":2,"k":3}' \
  --output benchmarks/results/benchmark-manifest.json
```

Short, non-hex, or otherwise ambiguous commit identifiers are rejected. The benchmark manifest explicitly states that it does not contain CUDA parity evidence; CUDA certification requires the separate real-device artifact above.

## Durable upgrade evidence

The v0.9 release regression pins the currently supported filesystem state upgrade window and the embedded PostgreSQL migration chain. Filesystem schema v1 remains the explicit legacy input and schema v2 is the current persisted form. Existing recovery tests verify that a v1 state without experiment identity is adopted exactly once under the configured runtime experiment and normalized to v2. Unsupported future schema versions fail closed.

The PostgreSQL release contract pins these migrations in contiguous order:

- `001_coordinator_state.sql`;
- `002_model_artifact_reference.sql`;
- `003_audit_events.sql`.

The migration executor also rejects database ledger versions unknown to the binary and rejects a migration-name mismatch for an already-applied version. Release changes must add a new migration; they must not silently rename, delete, or repurpose an applied migration.

## Protocol compatibility evidence

`internal/protocompat` remains the protocol compatibility gate. Its tests permit additive fields/messages/enum values/RPCs and reject package changes, message or field removal, field renumbering/renaming/type/cardinality changes, enum removal/renumbering, RPC removal/signature changes, and streaming-mode changes. CI compares the generated descriptor against the repository baseline.

## Known boundary: durable model identity

The v1 network model envelope enforces `model_id` at the transport/runtime boundary. The durable `StatePolicy` does not yet persist `model_id` as an independent restart identity. Therefore v0.9 must not claim that changing only `ZTFL_MODEL_ID` across a durable restart is separately detected by the state store. Closing that boundary requires an explicit durable-state schema/configuration change and migration, not a documentation assertion.
