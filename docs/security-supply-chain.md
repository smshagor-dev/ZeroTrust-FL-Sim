# Security and Software Supply Chain

This document records the repository-owned security controls used for the v0.8 production-hardening track. It is an engineering mapping, not a claim of NIST certification, OpenSSF certification, or independent security approval.

## Automated security gates

Pull requests and `main` are checked by `.github/workflows/security.yml`.

The workflow fails closed on:

- unreviewed direct Python or dashboard runtime dependencies;
- direct dependencies assigned to license expressions outside `security/runtime-license-policy.json`;
- Python dependencies reported vulnerable by `pip-audit`;
- reachable Go vulnerabilities reported by `govulncheck`;
- dashboard runtime dependency vulnerabilities at npm audit level `high` or above;
- high-severity/high-confidence Python Bandit findings;
- detected repository secrets through Gitleaks;
- sanitizer or crash findings in the Go NumPy model decoder fuzz target;
- sanitizer or crash findings in the C++ Byzantine aggregation fuzz target;
- HIGH or CRITICAL vulnerabilities in coordinator, worker, or recovery OCI images reported by Trivy.

The direct-dependency license policy is intentionally explicit. A dependency addition requires a reviewed SPDX license entry. Release SBOMs provide transitive package/license evidence; the direct policy does not replace SBOM review.

## Release evidence

Tag-triggered image publishing produces an immutable digest for each supported image and then requires all of the following in the same release workflow:

- SPDX JSON SBOM generated from the immutable image digest;
- keyless Sigstore/Cosign signature on the immutable digest;
- SBOM attestation attached to that digest;
- GitHub build-provenance attestation pushed to the registry;
- SHA-256 checksums for the release evidence files;
- retained workflow artifact containing image metadata, digests, SBOMs, and checksums.

A mutable tag alone is never the deployment identity. Production Helm values must continue to consume image digests.

## OpenSSF Scorecard

`.github/workflows/scorecard.yml` runs OpenSSF Scorecard on `main`, on a weekly schedule, and when branch-protection rules change. The SARIF result is retained as review evidence and published through the Scorecard action.

Scorecard is a posture signal rather than a release certificate. Findings should be converted into repository issues when they represent an actionable control gap. Known administrative gaps, such as branch protection that cannot be changed by the repository connector, remain tracked separately rather than being hidden by workflow configuration.

## NIST SSDF practice mapping

The following mapping uses the NIST Secure Software Development Framework practice families as an engineering checklist. It does not assert formal assessment or compliance.

| SSDF practice family | ZeroTrust-FL-Sim evidence |
| --- | --- |
| PO.1 / PO.2 Prepare the organization | `SECURITY.md`, contribution/governance files, roadmap release gates, explicit security issues |
| PO.3 Implement supporting toolchains | pinned GitHub Actions, CI, dependency/SAST/secret/container scans, fuzzing, release attestations |
| PS.1 Protect code from unauthorized access/tampering | GitHub repository permissions, immutable release digests, signed images; required branch protection remains separately tracked until enabled |
| PS.2 Provide mechanisms to verify release integrity | Cosign signatures, SBOM attestations, provenance attestations, SHA-256 evidence checksums |
| PW.4 Reuse well-secured software | Python/Go/npm vulnerability audits, explicit direct-license policy, Dependabot |
| PW.5 Create source code using secure coding practices | fail-closed validation, mTLS/RBAC/replay controls, code review through pull requests, linters and tests |
| PW.7 Review/analyze human-readable code | Go vet/tests, Ruff, Bandit, protocol compatibility checks, Python/native tests |
| PW.8 Test executable code | Docker integration, durable recovery tests, native sanitizer fuzzing, model-parser fuzzing, benchmark smoke |
| PW.9 Configure software securely by default | non-root/read-only Kubernetes workloads, dropped capabilities, NetworkPolicies, digest-only production images, external secret requirements |
| RV.1 Identify and confirm vulnerabilities | private vulnerability reporting policy, pip-audit, govulncheck, npm audit, Trivy, Gitleaks, Scorecard |
| RV.2 Assess/remediate vulnerabilities | severity-gated CI, dependency updates, issue/PR remediation workflow |
| RV.3 Analyze vulnerabilities for root cause | security findings are expected to record affected commit, path, threat model, remediation, and regression coverage |

## Claims boundary

Automated security tooling is not an independent security assessment. The production requirement tracked in issue #70 remains open until an independent reviewer or independently reproduced assessment provides evidence for the reviewed commit/tag and records the disposition of findings.
