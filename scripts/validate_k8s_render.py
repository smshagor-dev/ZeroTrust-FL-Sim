#!/usr/bin/env python3
"""Fail closed on unsafe properties in the rendered production Helm chart."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def _documents(path: Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(doc, dict)]


def _labels(resource: dict[str, Any]) -> dict[str, str]:
    return resource.get("metadata", {}).get("labels", {}) or {}


def validate(path: Path) -> list[str]:
    docs = _documents(path)
    errors: list[str] = []
    kinds = [str(doc.get("kind", "")) for doc in docs]
    if "Secret" in kinds:
        errors.append("production chart must not render Secret resources")

    deployments = [doc for doc in docs if doc.get("kind") == "Deployment"]
    pdbs = [doc for doc in docs if doc.get("kind") == "PodDisruptionBudget"]
    policies = [doc for doc in docs if doc.get("kind") == "NetworkPolicy"]
    services = [doc for doc in docs if doc.get("kind") == "Service"]
    if not deployments:
        errors.append("no Deployment resources rendered")
    if not services:
        errors.append("no Service resources rendered")
    if len(pdbs) < len(deployments):
        errors.append("every deployment must have a PodDisruptionBudget")
    if len(policies) < 3:
        errors.append("expected default-deny, coordinator, and worker NetworkPolicies")

    worker_secrets: set[str] = set()
    coordinator_secret = ""
    for deployment in deployments:
        name = deployment.get("metadata", {}).get("name", "<unnamed>")
        spec = deployment.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", {})
        component = _labels(deployment).get("app.kubernetes.io/component", "")
        if template_spec.get("automountServiceAccountToken") is not False:
            errors.append(f"{name}: service account token automount must be disabled")
        pod_security = template_spec.get("securityContext", {})
        if pod_security.get("runAsNonRoot") is not True:
            errors.append(f"{name}: runAsNonRoot must be true")
        if pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
            errors.append(f"{name}: seccompProfile RuntimeDefault is required")
        containers = template_spec.get("containers", [])
        if len(containers) != 1:
            errors.append(f"{name}: expected exactly one primary container")
            continue
        container = containers[0]
        image = str(container.get("image", ""))
        if "@sha256:" not in image or len(image.rsplit("@sha256:", 1)[-1]) != 64:
            errors.append(f"{name}: image must be pinned by sha256 digest")
        security = container.get("securityContext", {})
        if security.get("allowPrivilegeEscalation") is not False:
            errors.append(f"{name}: allowPrivilegeEscalation must be false")
        if security.get("readOnlyRootFilesystem") is not True:
            errors.append(f"{name}: readOnlyRootFilesystem must be true")
        if "ALL" not in security.get("capabilities", {}).get("drop", []):
            errors.append(f"{name}: all Linux capabilities must be dropped")
        resources = container.get("resources", {})
        if not resources.get("requests") or not resources.get("limits"):
            errors.append(f"{name}: resource requests and limits are required")
        if not container.get("readinessProbe") or not container.get("livenessProbe"):
            errors.append(f"{name}: readiness and liveness probes are required")

        secret_names = [
            volume.get("secret", {}).get("secretName", "")
            for volume in template_spec.get("volumes", [])
            if volume.get("secret")
        ]
        if component == "coordinator":
            if int(spec.get("replicas", 0)) != 1:
                errors.append("coordinator reference profile must remain single-replica")
            coordinator_secret = secret_names[0] if secret_names else ""
        elif component == "worker":
            if int(spec.get("replicas", 0)) != 1:
                errors.append(f"{name}: each worker identity must be one replica")
            if len(secret_names) != 1:
                errors.append(f"{name}: worker must mount exactly one isolated credential secret")
            elif secret_names[0] in worker_secrets:
                errors.append(f"{name}: worker credential secret is reused")
            else:
                worker_secrets.add(secret_names[0])

    if coordinator_secret and coordinator_secret in worker_secrets:
        errors.append("coordinator PKI secret must not be mounted by workers")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rendered_yaml", type=Path)
    args = parser.parse_args()
    errors = validate(args.rendered_yaml)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("production Helm render security checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
