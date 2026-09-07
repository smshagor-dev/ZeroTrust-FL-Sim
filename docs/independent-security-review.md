# Independent Security Review Evidence

Issue #70 is the production gate for an external security review or an independently reproduced security assessment. Repository-owned CI, fuzzing, documentation, and self-review do not satisfy this gate by themselves.

## Required review identity

Record:

- reviewer or organization name;
- review date/window;
- reviewed commit SHA and, when applicable, release tag;
- whether the reviewer is independent of the implementation under review;
- public report/reference URL or an attached private report reference.

## Minimum technical scope

The assessment should cover, at minimum:

- coordinator mTLS peer identity and certificate validation;
- registration, RBAC/token policy, credential rotation and revocation;
- nonce/replay and request rate controls;
- protobuf compatibility and model-envelope validation;
- NumPy/model payload parsing and malformed-input handling;
- Byzantine aggregation assumptions, validation, and native memory safety;
- privacy accounting and the boundary between simulation, differential privacy, and CKKS claims;
- durable filesystem/PostgreSQL/S3 state, audit-chain integrity, backup and clean-room restore;
- Docker runtime configuration and Kubernetes/Helm security boundaries;
- production secret handling and per-worker credential isolation;
- dependency, build, OCI, SBOM, signing, and provenance supply chain;
- operator CLI and SDK trust boundaries;
- documented failure modes, diagnostics, and incident/recovery procedures.

## Reproduction information

The report should include enough information to reproduce material findings:

- host/OS/architecture;
- compiler/runtime versions;
- scanner/fuzzer/test versions and command lines;
- configuration files or relevant non-secret settings;
- seed/corpus when relevant;
- expected and observed behavior;
- affected file/function/protocol surface;
- minimal reproduction or proof of concept when safe to disclose.

Never attach real credentials, private keys, production certificates, personal data, or unrelated sensitive information.

## Deterministic reviewer handoff bundle

A maintainer can prepare a commit-pinned evidence pack without editing the evidence by hand:

```bash
python scripts/prepare_security_review_bundle.py \
  --output-dir /tmp/ztfl-review-bundle \
  --archive /tmp/ztfl-review-bundle.tar.gz
```

For a detached checkout or a separately agreed review baseline, pass the full reviewed SHA explicitly with `--commit <40-character-sha>`.

The generated bundle contains:

- `REVIEW_BASELINE.json` with the exact reviewed SHA, supported-profile declaration, included evidence paths, and the external attestation fields that remain mandatory;
- `REVIEW_REPORT_TEMPLATE.md` for the independent reviewer to complete;
- the security/release documentation and workflow definitions needed to understand the reviewed controls and claims;
- `SHA256SUMS` covering every evidence file in the bundle;
- a deterministic `.tar.gz` archive with normalized archive metadata.

The bundle generator fails closed when required evidence is missing or the supplied commit is not a canonical full SHA. Re-running it from the same source tree and commit produces byte-identical archive content.

The archive is only a repository-authored handoff mechanism. It does not establish reviewer independence, validate findings, close issue #70, or replace a final externally authored report/reference.

## Finding record

For each finding, record:

- stable identifier;
- severity and rationale;
- affected commit/tag;
- attack prerequisites and threat model;
- impact;
- reproduction status;
- remediation PR/commit or explicit risk-acceptance rationale;
- regression test or verification evidence;
- final disposition: open, fixed, mitigated, accepted, or not applicable.

## v1.0.0 completion rule

Before the independent-review gate can be closed:

- the review must identify the exact commit/tag assessed;
- all Critical and High findings must be fixed and verified, or explicitly accepted with a documented release-blocking risk decision;
- the final report or independently reproducible evidence must be attached or linked from issue #70;
- repository CI must remain green on the reviewed/fixed commit;
- the release candidate must not silently expand its security claims beyond the reviewed scope.

A self-authored checklist marked complete is not sufficient evidence.
