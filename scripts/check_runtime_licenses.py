#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "security" / "runtime-license-policy.json"
REQUIREMENTS_PATH = ROOT / "requirements.txt"
PACKAGE_JSON_PATH = ROOT / "frontend" / "package.json"

NAME_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)")


def normalize_python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def python_direct_dependencies() -> set[str]:
    dependencies: set[str] = set()
    for raw_line in REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = NAME_PATTERN.match(line)
        if match is None:
            raise SystemExit(f"could not parse requirement line: {raw_line!r}")
        dependencies.add(normalize_python_name(match.group(1)))
    return dependencies


def npm_runtime_dependencies() -> set[str]:
    package = json.loads(PACKAGE_JSON_PATH.read_text(encoding="utf-8"))
    dependencies = package.get("dependencies")
    if not isinstance(dependencies, dict):
        raise SystemExit("frontend/package.json dependencies must be an object")
    return set(dependencies)


def validate_group(name: str, actual: set[str], reviewed: dict[str, str], approved: set[str]) -> list[str]:
    errors: list[str] = []
    reviewed_names = set(reviewed)
    missing = sorted(actual - reviewed_names)
    stale = sorted(reviewed_names - actual)
    if missing:
        errors.append(f"{name}: unreviewed direct dependencies: {', '.join(missing)}")
    if stale:
        errors.append(f"{name}: stale license-policy entries: {', '.join(stale)}")
    for dependency in sorted(actual & reviewed_names):
        license_id = reviewed[dependency]
        if license_id not in approved:
            errors.append(f"{name}: {dependency} uses unapproved license expression {license_id!r}")
    return errors


def main() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if policy.get("schema_version") != 1:
        raise SystemExit("unsupported runtime license policy schema")

    approved = policy.get("approved_licenses")
    python_policy = policy.get("python")
    npm_policy = policy.get("npm")
    if not isinstance(approved, list) or not all(isinstance(item, str) for item in approved):
        raise SystemExit("approved_licenses must be a string array")
    if not isinstance(python_policy, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in python_policy.items()
    ):
        raise SystemExit("python license policy must be a string map")
    if not isinstance(npm_policy, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in npm_policy.items()
    ):
        raise SystemExit("npm license policy must be a string map")

    errors = []
    errors.extend(
        validate_group(
            "python",
            python_direct_dependencies(),
            {normalize_python_name(key): value for key, value in python_policy.items()},
            set(approved),
        )
    )
    errors.extend(validate_group("npm", npm_runtime_dependencies(), npm_policy, set(approved)))
    if errors:
        raise SystemExit("runtime license policy failed:\n- " + "\n- ".join(errors))

    print("runtime direct-dependency license policy passed")


if __name__ == "__main__":
    main()
