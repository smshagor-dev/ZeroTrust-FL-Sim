# v0.9 release-readiness evidence map

This document maps repository-owned v0.9 release-readiness claims to executable evidence. External gates are tracked separately and are not self-certified by repository CI.

## Repository-owned evidence

| Contract | Executable evidence | Required result |
| --- | --- | --- |
| Public Python/operator API freeze | `tests/test_release_contract.py` | pinned exports, SDK API version, and release metadata pass |
| Model vector synchronization | `tests/test_release_correctness.py` | exact vector application; buffer-bearing models, wrong length, and non-finite updates fail closed |
| Byzantine configuration bounds | `tests/test_release_correctness.py` and native tests | valid Krum/Multi-Krum matrices pass; unsafe populations/configurations reject |
| CPU/native numerical parity | `tests/test_backend_parity.py` | Krum, Multi-Krum, trimmed mean, and median meet documented tolerances |
| CUDA evidence boundary | `tests/test_cuda_evidence_contract.py`, `scripts/capture_cuda_parity_evidence.py` | CPU-only runners cannot emit CUDA validation; real GPU/native CUDA required |
| Protocol upgrade compatibility | `internal/protocompat` and CI descriptor comparison | additive changes pass; incompatible removals/signature changes fail |
| Durable state upgrade | coordinator state tests | schema v1/v2 recover and normalize to v3; unsupported/corrupt current state fails closed |
| Durable model identity | `pkg/coordinator/durable_model_identity_test.go` | v2 adopts once; v3 persists ID; same ID restarts; drift/missing ID fail closed without mutation |
| PostgreSQL/S3 durability | coordinator PostgreSQL/S3 tests | migrations, state round-trip, model artifacts, and reconnect recovery pass |
| Commit failure rollback | durable service tests | failed durable write is not acknowledged and prior state is restored |
| Disaster recovery | `pkg/recovery` tests | clean-room backup/destroy/restore and source immutability pass |
| Worker loss/straggler liveness | Python FL engine tests | quorum/timeout reports stragglers and leaves no worker processes alive |
| Docker supported profile | `CI` integration job | mTLS cluster, durable restart recovery, benchmark smoke, logs and cleanup pass |
| Kubernetes supported profile | `Release Evidence` workflow | real Kind cluster, immutable image digests, CI-only PKI/secrets, Helm install, mTLS worker update, model advance, worker loss/recovery, coordinator container restart, state preservation pass |
| Reproducible benchmark evidence | `benchmarks/run_release_benchmark.py` and `Release Evidence` workflow | manifest pins commit/version/config/runtime and canonical config digest |
| Privacy/CKKS claim boundaries | privacy tests and release documentation | local DP and native CKKS are described without claiming ordinary gRPC end-to-end FHE |
| Runtime image vulnerability gate | `Security` workflow | configured HIGH/CRITICAL findings are zero for coordinator, worker, and recovery images |
| Source/dependency/security gates | `Security` workflow | dependency audit, license policy, SAST, secret scan, action validation, and fuzz gates pass |
| Helm production invariants | `Deployment Validation` | chart lint/render and hardening invariant validation pass |

## Release evidence workflow boundary

`Release Evidence` intentionally uses a real ephemeral Kubernetes cluster instead of treating `helm template` as deployment proof. Images are pushed to an isolated local registry and the chart receives immutable registry digests. CI-only development PKI is generated at runtime and never committed.

A successful Kubernetes evidence run must prove all of the following in the same commit:

- coordinator and worker production images build and are addressable by immutable digest;
- Helm deployment reaches Ready in an ephemeral Kind cluster;
- the worker authenticates over mTLS/JWT, obtains the global model, submits an accepted update, and advances the model beyond bootstrap;
- durable state is schema v3 and binds `model_id=ci-model`;
- worker removal does not prevent coordinator recovery;
- restarting the coordinator container preserves the acknowledged policy/model/pending state;
- the worker can be restored and become Ready again;
- the release benchmark runs from the same immutable worker image and emits a commit-bound manifest with a verified canonical configuration digest.

This Kubernetes test is an integration proof for the supported CI profile. It does not claim every Kubernetes distribution, CNI, storage class, GPU stack, or cloud environment is validated.

## Resilience boundary

Deterministic repository tests cover worker delay/loss, coordinator restart, stale or malformed model/update state, identity drift, vector mismatch/non-finite updates, and durable write rollback. Chaos Mesh manifests remain opt-in experiments for packet loss/jitter/pod failure. A CI environment without an installed chaos/network-policy implementation must not claim observed packet-loss enforcement merely because a manifest renders.

## External gates

The following are intentionally outside this repository-owned completion issue and remain separately tracked or externally evidenced:

- repository administrator enforcement of protected `main` and required checks (#37);
- independent security assessment/reproduction evidence (#70);
- external OpenSSF Best Practices enrollment/application;
- real CUDA hardware parity evidence when no eligible CUDA runner is available.

A v0.9 repository-owned readiness issue may close with those external gates still open, provided documentation does not represent them as satisfied.
