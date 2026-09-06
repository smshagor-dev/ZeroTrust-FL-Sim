# OpenSSF Improvement Plan

ZeroTrust-FL-Sim uses the OpenSSF Scorecard workflow as a recurring posture signal. The project does not treat a Scorecard result as a certification or as a replacement for independent security review.

## Baseline and evidence

`.github/workflows/scorecard.yml` runs on `main`, weekly, on branch-protection changes, and on manual dispatch. Each run retains the SARIF result for 90 days and publishes results through the Scorecard action.

The first green run after this control lands is the baseline. Future regressions should be triaged into one of three categories:

- repository-code/configuration issue that can be fixed in Git;
- repository-administration issue such as branch protection or rulesets that requires owner/admin action;
- intentional architecture choice with documented rationale and compensating controls.

## Improvement priorities

Highest-priority Scorecard-related controls for the v1 line are:

1. enable protected `main` with required CI/security checks once repository administration access is available;
2. keep all third-party GitHub Actions pinned to full commit SHAs and review Dependabot updates;
3. maintain private vulnerability reporting and `SECURITY.md`;
4. keep dependency update automation enabled across Go, Python, npm, and GitHub Actions;
5. retain signed, SBOM-backed, provenance-attested release evidence;
6. avoid dangerous workflow triggers or write permissions on untrusted pull-request code;
7. keep fuzzing and security scanning required before production release;
8. complete the external OpenSSF Best Practices application and independent security assessment before v1.0.0 claims readiness.

## Target

The project target is no unresolved actionable High-risk Scorecard finding for the supported production profile and continuous improvement from the first recorded baseline. A numeric score alone does not override explicit release blockers such as issue #37 or issue #70.
