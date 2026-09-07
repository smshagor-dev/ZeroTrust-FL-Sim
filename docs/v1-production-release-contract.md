# v1.0 production release contract

This document defines the fail-closed publication contract for ZeroTrust-FL-Sim v1.0.0. It complements the executable release gate in `scripts/validate_v1_release.py` and the tracked evidence manifest in `release/v1.0-evidence.json`.

## Release baseline

The v0.9 repository-owned release-readiness baseline must remain green. That baseline includes Go coordinator and protocol tests, Python/PyTorch and C++20 native tests, durable PostgreSQL/S3 state and disaster recovery, Docker integration, benchmark reproducibility, security/SAST/dependency/license/secret/fuzz gates, production image vulnerability gates, deployment validation, and real Kind/Kubernetes supported-profile E2E evidence.

## Stable API and compatibility

The public Python SDK remains `SDK_API_VERSION = "1"` and the documented `zerotrust_fl.__all__` surface is frozen for the initial v1 release. Additive compatible changes may be introduced under semantic versioning. Breaking public API, protocol, durable-state, or operator-contract changes require an explicit compatibility/migration plan and an appropriate major-version decision.

The protobuf compatibility checker remains authoritative for supported wire evolution. Durable state schema v3 persists experiment identity and `model_id`; incompatible or missing current-schema identity fails closed.

## Supported production profile

v1.0.0 supports CPU/PyTorch/native C++ aggregation. The native C++ path is validated against the PyTorch reference within the documented numerical tolerances. Docker and Kubernetes deployment are supported within the documented single-coordinator reference architecture and resource/security constraints.

CUDA is experimental and unvalidated by default. It becomes a validated profile only after a real eligible CUDA device produces evidence with `scripts/capture_cuda_parity_evidence.py` and that reviewed evidence is linked in the v1 manifest. A skipped CUDA test, a CPU-only runner, or successful compilation alone is not validation.

## External and administrator gates

The following are hard v1.0 publication blockers:

- issue #37: repository administrator enables protection for `main`, requires the designated CI checks, requires PR-based changes, and blocks force pushes/deletion;
- issue #70: independent security assessment evidence is attached or linked, including reviewer identity, reviewed commit, methods/tool versions, findings, and disposition of critical/high findings;
- issue #73: a real OpenSSF Best Practices application/project record is created and its public status URL is recorded.

Self-authored repository documentation, scanners, Scorecard output, or CI results do not independently satisfy #70 or #73.

## Publication sequencing

1. Preserve `0.9.0` metadata while external gates are incomplete.
2. Complete #37, #70, and #73 and update `release/v1.0-evidence.json` with reviewed HTTPS evidence links and the independent-review commit SHA.
3. Prepare one final release commit that changes all version surfaces to `1.0.0`, changes Python package maturity to `Development Status :: 5 - Production/Stable`, and adds the dated `CHANGELOG.md` v1.0.0 section.
4. Run CI, Security, Deployment Validation, Docker integration, Release Evidence, and release-gate validation on that exact candidate.
5. Create/push `v1.0.0` only at the reviewed, all-green release commit.
6. The tag workflow validates tracked evidence plus live issue states before registry authentication, builds immutable images, generates SBOMs, signs images/source, creates provenance attestations, uploads release evidence, and creates the GitHub Release.

If any gate fails, publication stops before production artifacts are pushed.

## Claim boundaries

v1.0.0 is a production release of a federated-learning simulation and security-resilience platform, not a certification that every deployment is secure. Byzantine guarantees apply only within documented adversary/population assumptions. Differential privacy depends on configured mechanism/accounting parameters. CKKS support does not imply that the normal gRPC update path is end-to-end homomorphically encrypted. External assessment evidence is scoped to the reviewed commit and documented production profile.
