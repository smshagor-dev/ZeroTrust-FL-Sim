# v0.9 release-candidate evidence contract

ZeroTrust-FL-Sim v0.9 is a pre-1.0 release-readiness line. It freezes the documented public SDK surface for the v0.9 line, aligns release metadata, and requires reproducible correctness/security evidence before a release candidate can be treated as ready. It is not a v1.0 production certification.

## Public API freeze

The public Python surface is the names exported by `zerotrust_fl.__all__` together with `SDK_API_VERSION = "1"`.

For the v0.9 line:

- existing documented public names must not be removed or silently change meaning;
- additive fields or helpers must remain backward-compatible with the current SDK contract;
- an incompatible pre-1.0 change requires an explicit changelog entry and migration note;
- security or data-integrity fixes may intentionally break unsafe behavior, but the release notes must explain the migration impact;
- native C++ ABI compatibility is not promised independently of the Python wheel version.

The repository test suite pins the current public export set and release version surfaces so accidental drift fails CI.

## Version contract

The following surfaces must report the same release version:

- Python package metadata in `setup.py`;
- runtime `zerotrust_fl.__version__`;
- CMake native project version;
- Helm chart `version` and `appVersion`;
- `CITATION.cff` software version.

For this line the value is `0.9.0`.

## Model synchronization contract

The local simulation protocol synchronizes trainable parameters as one flattened vector. Models with registered buffers are rejected before worker processes start because the current vector protocol does not synchronize arbitrary state-dict buffers.

A supported model therefore must satisfy all of the following:

- no registered non-empty buffers;
- identical trainable-parameter vector length across coordinator and workers;
- finite model/update values at validation boundaries;
- no silent reshape, truncation, or schema substitution.

Full arbitrary `state_dict` synchronization is not claimed by v0.9.

## Byzantine aggregation contract

Krum and Multi-Krum configuration is valid only when the successful-update quorum satisfies the implemented Byzantine population assumptions.

For Byzantine bound `f` and successful update count `n`:

- Krum/Multi-Krum require `n >= 2*f + 3`;
- the Krum neighbor count is `n - f - 2`;
- Multi-Krum candidate count must satisfy `1 <= k <= n - f - 2`.

The coordinator validates these bounds before worker processes start, and the native aggregation implementation performs independent runtime validation.

## CPU, native, and CUDA evidence

Linux x86_64 CPU/native is the repository's current mandatory CI evidence profile. CUDA tests are conditional on a native CUDA build and a visible CUDA device.

A skipped CUDA test is not CUDA validation. A release must not claim CUDA parity unless a real CUDA runner produces an evidence artifact that records at least:

- commit SHA and package version;
- GPU model and compute capability;
- driver and CUDA runtime/toolkit versions;
- PyTorch version;
- native extension CUDA metadata;
- tested aggregation methods, shapes, client counts, Byzantine parameters, and tolerances;
- pass/fail numerical comparison against the documented CPU/native reference.

The CUDA wrapper defaults to finite-value validation. Disabling finite validation is a deliberate performance/security tradeoff and must not be represented as the secure default.

## Differential privacy boundary

The implemented local privacy mechanism is release-level local differential privacy over a clipped whole model-update vector. It is not per-example DP-SGD.

Deterministic simulator seeds exist for reproducibility. They are not a cryptographically secure randomness source for a production privacy mechanism. A production client requires an appropriate secure random source and a threat model that assumes the client executes the release mechanism honestly.

## CKKS boundary

The native Microsoft SEAL CKKS path demonstrates additive encrypted aggregation with separated client encryptor, server-side ciphertext addition, and a distinct decryptor/key authority. It supports sum/weighted-FedAvg-style arithmetic.

The project does not claim that the current ordinary gRPC model-update wire path is end-to-end CKKS encrypted, nor that Krum, Multi-Krum, coordinate median, or trimmed mean execute over CKKS ciphertexts. Threshold decryption, distributed key generation, encrypted-update replay binding, key rotation, malicious-ciphertext proofs, and remote key custody are separate future controls.

## External gates

Repository-owned CI cannot satisfy every v1.0 gate. The following remain external until real evidence exists:

- repository administrator enforcement of protected `main` and required checks, tracked in issue #37;
- independent security assessment/reproduction evidence, tracked in issue #70;
- external OpenSSF Best Practices enrollment/application;
- real CUDA parity evidence when no eligible CUDA runner is available.

No v1.0 tag should be created while required external gates remain unresolved.
