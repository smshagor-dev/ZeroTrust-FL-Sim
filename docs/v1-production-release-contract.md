# v1.0 production release contract

This document defines the publication contract for ZeroTrust-FL-Sim v1.0.0. It complements the executable release gate in `scripts/validate_v1_release.py` and the tracked evidence manifest in `release/v1.0-evidence.json`.

## Release baseline

The repository-owned release-readiness baseline must remain green. That baseline includes Go coordinator and protocol tests, Python/PyTorch and C++20 native tests, durable PostgreSQL/S3 state and disaster recovery, Docker integration, benchmark reproducibility, security/SAST/dependency/license/secret/fuzz gates, production image vulnerability gates, deployment validation, and real Kind/Kubernetes supported-profile E2E evidence.

## Stable API and compatibility

The public Python SDK remains `SDK_API_VERSION = "1"` and the documented `zerotrust_fl.__all__` surface is frozen for the initial v1 release. Additive compatible changes may be introduced under semantic versioning. Breaking public API, protocol, durable-state, or operator-contract changes require an explicit compatibility/migration plan and an appropriate major-version decision.

The protobuf compatibility checker remains authoritative for supported wire evolution. Durable state schema v3 persists experiment identity and `model_id`; incompatible or missing current-schema identity fails closed.

## Supported production profile

v1.0.0 supports CPU/PyTorch/native C++ aggregation. The native C++ path is validated against the PyTorch reference within the documented numerical tolerances. Docker and Kubernetes deployment are supported within the documented single-coordinator reference architecture and resource/security constraints.

CUDA is experimental and unvalidated by default. It becomes a validated profile only after a real eligible CUDA device produces evidence with `scripts/capture_cuda_parity_evidence.py` and that reviewed evidence is linked in the v1 manifest. A skipped CUDA test, a CPU-only runner, or successful compilation alone is not validation.

## Assurance gate dispositions

The canonical v1 assurance items remain:

- issue #37: repository administrator protection for `main`, designated CI checks, PR-based changes, and force-push/deletion blocking;
- issue #70: independent security assessment evidence including reviewer identity, reviewed commit, methods/tool versions, findings, and disposition of critical/high findings;
- issue #73: a real OpenSSF Best Practices application/project record and public status URL.

The preferred disposition is evidence-backed satisfaction. Repository-owned documentation, scanners, Scorecard output, or CI results do not independently satisfy #70 or #73.

A repository-owner waiver is permitted only as an explicit release-governance exception. A waiver is not evidence satisfaction and must not be represented as one. Every waived item must record, in `release/v1.0-evidence.json`:

- `satisfied: false` and `waived: true`;
- the repository owner identity accepting the risk;
- the acceptance date;
- the canonical issue URL;
- a substantive reason for proceeding;
- a substantive limitation disclosure describing what assurance remains absent.

The corresponding release notes must disclose the missing assurance in user-facing language. A waived independent assessment must not contain a `reviewed_commit`, and the release must not be described as independently audited or certified. A waived OpenSSF item must not claim a Best Practices badge or completed application. A waived branch-protection item must disclose that GitHub does not technically enforce the specified repository controls.

For v1.0.0, the repository owner directed publication on 2026-09-08 with #37, #70, and #73 explicitly waived under this policy. Their tracked manifest entries are the authoritative release-time disclosure.

## Publication sequencing

1. Align all release version surfaces to `1.0.0`, set Python package maturity to `Development Status :: 5 - Production/Stable`, and add the dated `CHANGELOG.md` v1.0.0 section.
2. Record every canonical assurance item as exactly one of evidence-backed `satisfied` or owner-authorized `waived` in `release/v1.0-evidence.json`.
3. For waived items, record the risk-acceptance disclosure and close the corresponding gate issue using the repository's explicit waiver disposition rather than claiming evidence that does not exist.
4. Run CI, Security, Deployment Validation, Docker integration, Release Evidence, and release-contract validation on the exact release candidate commit.
5. Create `v1.0.0` only at that all-green exact release commit.
6. The tag workflow validates tracked evidence/dispositions and live GitHub issue state before registry authentication, builds immutable images, generates SBOMs, signs images/source, creates provenance attestations, uploads release evidence, and creates the GitHub Release.

If any required exact-release-commit workflow fails, publication stops before production artifacts are pushed.

## Claim boundaries

v1.0.0 is a stable release of a federated-learning simulation and security-resilience platform, not a certification that every deployment is secure. Byzantine guarantees apply only within documented adversary/population assumptions. Differential privacy depends on configured mechanism/accounting parameters. CKKS support does not imply that the normal gRPC update path is end-to-end homomorphically encrypted.

Repository-owner waivers are governance decisions, not substitute evidence. Downstream policies requiring protected branches, independent security review, an OpenSSF Best Practices record, or validated CUDA hardware should treat those requirements as unmet when the corresponding manifest entry is waived or experimental.
