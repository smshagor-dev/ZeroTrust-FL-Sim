# Security Policy Assets

This directory contains repository-owned machine-readable security policy data used by CI.

`runtime-license-policy.json` is an explicit reviewed allowlist for direct runtime/development dependencies tracked in the repository. Changes to dependency manifests must update this policy when a new direct dependency is introduced. The policy does not replace transitive SBOM review, vulnerability scanning, legal review, or the independent assessment gate.
