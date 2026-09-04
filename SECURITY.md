# Security Policy

ZeroTrust-FL-Sim is a security and resilience research platform. Security reports are welcome, especially for issues affecting authentication, authorization, transport security, cryptographic policy, native memory safety, unsafe deserialization, secret handling, container boundaries, or the integrity of experiment results.

## Supported Versions

| Version | Security support |
| --- | --- |
| `main` | Supported |
| Latest tagged release | Supported |
| Older releases | Best effort only |

Security fixes are normally developed against `main` and may be backported when a maintained release requires it.

## Reporting a Vulnerability

Do not disclose a suspected vulnerability in a public GitHub issue, pull request, discussion, benchmark artifact, or log.

Preferred reporting path:

1. Open the repository's **Security** tab.
2. Use **Report a vulnerability** / private vulnerability reporting when available, or create a private Security Advisory if you have maintainer access.
3. Include enough information to reproduce and assess the issue.

If private vulnerability reporting is unavailable to you, contact the repository maintainer privately using a contact method published on the maintainer's GitHub profile.

A useful report includes:

- affected commit, tag, or version;
- affected component and configuration;
- threat model and required attacker capabilities;
- minimal reproduction steps or proof of concept;
- expected versus observed behavior;
- impact assessment;
- suggested mitigation, if known;
- whether the issue has been disclosed elsewhere.

Please remove real credentials, production keys, personal data, or unrelated sensitive information from reports.

## Disclosure Process

The maintainer will validate the report, determine severity and affected versions, prepare a fix or mitigation when appropriate, and coordinate disclosure. Public disclosure should occur after users have a reasonable opportunity to apply a fix or mitigation, unless earlier disclosure is required by law or needed to address active harm.

No fixed response-time SLA is promised; reports are handled on a best-effort basis.

## Research-Specific Security Boundaries

The repository deliberately contains malicious-client simulation, Byzantine attacks, chaos experiments, and cryptographic/security test code. These capabilities are intended for controlled, authorized environments.

A result is not automatically a security vulnerability merely because an experiment intentionally exceeds an algorithm's stated fault assumptions. For example, the documented 50% Byzantine collusion mode is an extreme stress condition outside Krum's formal fault bound.

Do not use repository attack or fault-injection tooling against systems you do not own or have explicit permission to test.

## Secrets and Test PKI

Never commit production credentials, private keys, access tokens, or real certificate material. Development certificates and generated test PKI should remain isolated and disposable.

## Dependency Vulnerabilities

Reports about third-party dependencies are useful when they show a reachable impact in this repository. When possible, include the vulnerable package/version, advisory identifier, affected execution path, and the minimum safe version.
