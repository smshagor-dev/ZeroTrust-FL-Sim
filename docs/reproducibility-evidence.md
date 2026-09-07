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

`benchmarks/run_release_benchmark.py` is the release-evidence entrypoint. It runs the benchmark suite and writes `benchmark-manifest.json` into the same output directory. The release workflow refuses ambiguous/short commit identities and verifies the resulting canonical configuration digest before accepting the artifact.

Standalone manifest example:

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

## Durable upgrade and model identity evidence

The v0.9 release regression now pins a three-version filesystem/PostgreSQL state upgrade window:

- schema v1 predates explicit experiment identity and durable model identity;
- schema v2 persists experiment identity but predates independent durable `model_id`;
- schema v3 is the current form and requires canonical `policy.model_id`.

A v1/v2 state may adopt the configured runtime model ID exactly once during recovery and is immediately normalized to schema v3. Once schema v3 is persisted, changing only `ZTFL_MODEL_ID` causes fail-closed startup before the durable state is mutated. A schema-v3 record with a missing/invalid model ID is treated as corrupt rather than silently repaired.

Filesystem and PostgreSQL regression tests cover the v2 adoption path, same-model restart, model-ID drift rejection, and current-schema missing-identity rejection. The existing v1 regression additionally proves experiment identity and model identity can be adopted together during the supported legacy migration.

The PostgreSQL release contract pins these database migrations in contiguous order:

- `001_coordinator_state.sql`;
- `002_model_artifact_reference.sql`;
- `003_audit_events.sql`.

The durable state schema version is stored in the singleton state row and is independent of the database migration ledger. The migration executor rejects database ledger versions unknown to the binary and rejects a migration-name mismatch for an already-applied version. Release changes must add a new database migration when the SQL schema changes; they must not silently rename, delete, or repurpose an applied migration.

## Protocol compatibility evidence

`internal/protocompat` remains the protocol compatibility gate. Its tests permit additive fields/messages/enum values/RPCs and reject package changes, message or field removal, field renumbering/renaming/type/cardinality changes, enum removal/renumbering, RPC removal/signature changes, and streaming-mode changes. CI compares the generated descriptor against the repository baseline.

## Kubernetes supported-profile evidence

The `Release Evidence` workflow creates a real ephemeral Kind cluster, pushes the production coordinator and worker images through an isolated local registry, resolves immutable image digests, generates CI-only PKI, installs the Helm chart, and waits for both deployments to become Ready.

The worker must complete an authenticated model update and advance the persisted model beyond bootstrap. The workflow then removes the worker, restarts the coordinator container, verifies schema-v3 model identity and durable state preservation, restores the worker, and produces the benchmark manifest from the same immutable worker image.

This is evidence for the supported CI profile, not a claim of validation across every Kubernetes distribution, CNI, storage backend, cloud provider, or GPU runtime.
