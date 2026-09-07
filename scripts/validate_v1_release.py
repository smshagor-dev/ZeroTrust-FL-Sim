from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
TARGET_VERSION = "1.0.0"
EVIDENCE_PATH = Path("release/v1.0-evidence.json")
RELEASE_NOTES_PATH = Path("docs/releases/v1.0.0.md")
RELEASE_WORKFLOW_PATH = Path(".github/workflows/release-images.yml")
EXPECTED_GATES = {
    "branch_protection": 37,
    "independent_security_assessment": 70,
    "openssf_best_practices": 73,
}
EXPECTED_CPU_BACKENDS = ["pytorch-cpu", "native-cpp-cpu"]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)$")


class ReleaseGateError(RuntimeError):
    """Raised when the production release contract is not satisfied."""


def _read(root: Path, path: Path | str) -> str:
    return (root / path).read_text(encoding="utf-8")


def _match_version(text: str, pattern: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if match is None:
        raise ReleaseGateError(f"could not resolve {label} version")
    return match.group(1)


def metadata_versions(root: Path = ROOT) -> dict[str, str]:
    setup = _read(root, "setup.py")
    package = _read(root, "fl/zerotrust_fl/__init__.py")
    cmake = _read(root, "cpp/CMakeLists.txt")
    chart = _read(root, "deploy/helm/zerotrust-fl/Chart.yaml")
    citation = _read(root, "CITATION.cff")
    return {
        "setup.py": _match_version(setup, r'\bversion="([^"]+)"', "setup.py"),
        "python package": _match_version(package, r'^__version__\s*=\s*"([^"]+)"', "Python package"),
        "CMake": _match_version(cmake, r'\bVERSION\s+([0-9]+\.[0-9]+\.[0-9]+)\b', "CMake"),
        "Helm chart": _match_version(chart, r'^version:\s*([^\s]+)\s*$', "Helm chart"),
        "Helm appVersion": _match_version(chart, r'^appVersion:\s*"([^"]+)"\s*$', "Helm appVersion"),
        "CITATION.cff": _match_version(citation, r'^version:\s*"([^"]+)"\s*$', "CITATION.cff"),
    }


def load_evidence(root: Path = ROOT) -> dict[str, Any]:
    try:
        value = json.loads(_read(root, EVIDENCE_PATH))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"load v1 evidence manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseGateError("v1 evidence manifest must be a JSON object")
    return value


def _valid_https_url(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_evidence_schema(evidence: dict[str, Any]) -> None:
    if evidence.get("schema_version") != 1:
        raise ReleaseGateError("v1 evidence schema_version must be 1")
    if evidence.get("target_version") != TARGET_VERSION:
        raise ReleaseGateError(f"v1 evidence target_version must be {TARGET_VERSION}")

    profile = evidence.get("supported_profile")
    if not isinstance(profile, dict):
        raise ReleaseGateError("supported_profile must be an object")
    if profile.get("aggregation_backends") != EXPECTED_CPU_BACKENDS:
        raise ReleaseGateError(
            "v1 supported aggregation profile must remain PyTorch CPU plus native C++ CPU"
        )
    cuda_status = profile.get("cuda_status")
    if cuda_status not in {"experimental-unvalidated", "validated-real-device"}:
        raise ReleaseGateError("cuda_status must be experimental-unvalidated or validated-real-device")
    cuda_url = profile.get("cuda_evidence_url")
    if cuda_status == "experimental-unvalidated" and cuda_url is not None:
        raise ReleaseGateError("experimental CUDA profile must not attach validation evidence")
    if cuda_status == "validated-real-device" and not _valid_https_url(cuda_url):
        raise ReleaseGateError("validated CUDA profile requires an HTTPS real-device evidence URL")

    gates = evidence.get("hard_gates")
    if not isinstance(gates, dict) or set(gates) != set(EXPECTED_GATES):
        raise ReleaseGateError("hard_gates must contain exactly the three canonical v1 production gates")
    for name, issue_number in EXPECTED_GATES.items():
        gate = gates.get(name)
        if not isinstance(gate, dict):
            raise ReleaseGateError(f"hard gate {name} must be an object")
        if gate.get("issue") != issue_number:
            raise ReleaseGateError(f"hard gate {name} must reference issue #{issue_number}")
        if not isinstance(gate.get("satisfied"), bool):
            raise ReleaseGateError(f"hard gate {name} satisfied must be boolean")
        if gate["satisfied"] and not _valid_https_url(gate.get("evidence_url")):
            raise ReleaseGateError(f"hard gate {name} requires an HTTPS evidence URL when satisfied")

    security = gates["independent_security_assessment"]
    reviewed_commit = security.get("reviewed_commit")
    if security["satisfied"] and not (
        isinstance(reviewed_commit, str) and SHA_RE.fullmatch(reviewed_commit)
    ):
        raise ReleaseGateError(
            "independent security assessment requires the reviewed 40-character commit SHA"
        )


def validate_repository_contract(root: Path = ROOT) -> None:
    evidence = load_evidence(root)
    validate_evidence_schema(evidence)

    versions = metadata_versions(root)
    unique_versions = set(versions.values())
    if len(unique_versions) != 1:
        rendered = ", ".join(f"{name}={version}" for name, version in versions.items())
        raise ReleaseGateError(f"release metadata versions are not aligned: {rendered}")
    current_version = next(iter(unique_versions))
    if current_version not in {"0.9.0", TARGET_VERSION}:
        raise ReleaseGateError(
            f"v1 closure branch must remain at 0.9.0 until final bump or be exactly {TARGET_VERSION}"
        )

    workflow = _read(root, RELEASE_WORKFLOW_PATH)
    gate_marker = "python scripts/validate_v1_release.py --mode publish"
    auth_marker = "Authenticate to GHCR"
    if gate_marker not in workflow:
        raise ReleaseGateError("release workflow does not invoke the v1 publication gate")
    if auth_marker not in workflow:
        raise ReleaseGateError("release workflow is missing the GHCR authentication step")
    if workflow.index(gate_marker) > workflow.index(auth_marker):
        raise ReleaseGateError("v1 publication gate must execute before registry authentication")
    if "issues: read" not in workflow:
        raise ReleaseGateError("release workflow must have issues: read permission for live blocker checks")
    if "gh api" not in workflow:
        raise ReleaseGateError("release workflow must verify live GitHub blocker issue states")

    notes = _read(root, RELEASE_NOTES_PATH)
    required_note_phrases = (
        "CPU/PyTorch/native C++",
        "CUDA",
        "#37",
        "#70",
        "#73",
    )
    for phrase in required_note_phrases:
        if phrase not in notes:
            raise ReleaseGateError(f"v1 release notes are missing required boundary: {phrase}")


def _assert_reviewed_commit_is_ancestor(root: Path, reviewed: str, release_commit: str) -> None:
    if not SHA_RE.fullmatch(release_commit):
        raise ReleaseGateError("release commit must be a full lowercase 40-character SHA")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", reviewed, release_commit],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise ReleaseGateError(
            "independent security assessment commit is not an ancestor of the release commit"
        )


def validate_publish_gate(tag: str, commit: str, root: Path = ROOT) -> None:
    validate_repository_contract(root)
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise ReleaseGateError("release tag must use stable vMAJOR.MINOR.PATCH form")
    version = tag.removeprefix("v")
    versions = metadata_versions(root)
    mismatched = {name: value for name, value in versions.items() if value != version}
    if mismatched:
        rendered = ", ".join(f"{name}={value}" for name, value in mismatched.items())
        raise ReleaseGateError(f"tag {tag} does not match release metadata: {rendered}")

    if int(match.group("major")) == 0:
        return
    if version != TARGET_VERSION:
        raise ReleaseGateError(
            f"stable major-version publication is locked to v{TARGET_VERSION}; update the reviewed contract first"
        )

    evidence = load_evidence(root)
    gates = evidence["hard_gates"]
    incomplete = [name for name, gate in gates.items() if not gate["satisfied"]]
    if incomplete:
        raise ReleaseGateError("v1 hard production gates are incomplete: " + ", ".join(incomplete))

    security = gates["independent_security_assessment"]
    _assert_reviewed_commit_is_ancestor(root, security["reviewed_commit"], commit)

    changelog = _read(root, "CHANGELOG.md")
    if re.search(rf"^## \[{re.escape(TARGET_VERSION)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE) is None:
        raise ReleaseGateError("CHANGELOG.md must contain a dated v1.0.0 release section")

    setup = _read(root, "setup.py")
    if "Development Status :: 5 - Production/Stable" not in setup:
        raise ReleaseGateError("v1.0.0 package metadata must declare Production/Stable")

    notes = _read(root, RELEASE_NOTES_PATH)
    for marker in ("TODO", "TBD", "PENDING RELEASE GATE"):
        if marker in notes:
            raise ReleaseGateError(f"v1.0.0 release notes still contain placeholder marker {marker!r}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate ZeroTrust-FL-Sim production release gates")
    parser.add_argument("--mode", choices=("repository", "publish"), required=True)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        if args.mode == "repository":
            validate_repository_contract()
            print("v1 repository release contract is structurally valid")
            return 0
        if not args.tag or not args.commit:
            raise ReleaseGateError("publish mode requires --tag and --commit")
        validate_publish_gate(args.tag, args.commit)
        print(f"production release gate passed for {args.tag} at {args.commit}")
        return 0
    except ReleaseGateError as exc:
        print(f"release gate failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
