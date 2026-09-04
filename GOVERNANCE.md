# Governance

ZeroTrust-FL-Sim is maintained as an open engineering and research project under the Apache License 2.0. Governance is designed to keep security-sensitive changes reviewable, reproducible, and technically accountable.

## Roles

- **Project Lead** owns the project direction, release approval, maintainer appointments, and final decisions when consensus cannot be reached.
- **Maintainers** review and merge changes, triage issues, keep CI healthy, and maintain compatibility/security policy.
- **Contributors** participate through issues and pull requests and are expected to follow `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`.

Current maintainers are listed in `MAINTAINERS.md`.

## Decision model

Routine implementation changes are accepted through normal pull-request review once required automated checks pass. Architecture, cryptography, protocol compatibility, security boundaries, release policy, and public API changes require an explicit rationale in the pull request and should be recorded as an Architecture Decision Record when they materially affect long-term behavior.

Security takes precedence over compatibility when retaining old behavior would expose credentials, bypass authorization, permit replay, corrupt model state, or make a documented security boundary false. Such changes must include migration notes.

## Protected areas

Changes in the following areas are considered security or release sensitive:

- `pkg/security/`
- `pkg/coordinator/`
- `proto/`
- `cpp/`
- `docker/` and `docker-compose*.yml`
- `.github/workflows/`
- privacy/cryptography implementations
- release, packaging, and provenance configuration

They require successful relevant tests and careful review of threat-model implications.

## Merge policy

The intended stable-branch policy is:

- changes reach `main` through pull requests
- required CI checks must pass
- force pushes and branch deletion are disabled for `main`
- unresolved review conversations block merge
- security-sensitive changes receive maintainer/code-owner review
- release tags are immutable

Repository-hosting rules should enforce this policy where account/plan capabilities allow it. The policy document remains authoritative even when a hosting feature is unavailable.

## Releases

Release requirements are defined in `RELEASES.md`; production-v1 gates are defined in `ROADMAP.md`. A release must not claim a capability, certification, privacy property, post-quantum property, or production guarantee that is not implemented and tested in that release.

## Security reports

Potential vulnerabilities must follow `SECURITY.md`, not public issue disclosure before coordinated review. Maintainers should preserve evidence, assess affected versions, prepare a fix/advisory, and communicate mitigation without overstating impact or guarantees.

## Changes to governance

Governance changes use the same pull-request process as code. Material changes should explain motivation, migration impact, and how the change affects contributor or maintainer responsibilities.
