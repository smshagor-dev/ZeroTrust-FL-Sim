from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_MARKER = ".ztfl-review-bundle"

EVIDENCE_PATHS = (
    "SECURITY.md",
    "docs/independent-security-review.md",
    "docs/threat-model/README.md",
    "docs/security-supply-chain.md",
    "docs/architecture/production-v1.md",
    "docs/reproducibility-evidence.md",
    "docs/v1-production-release-contract.md",
    "release/v1.0-evidence.json",
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/deployment-validation.yml",
    ".github/workflows/release-evidence.yml",
    ".github/workflows/release-images.yml",
    ".github/workflows/scorecard.yml",
    "requirements.txt",
    "go.mod",
    "go.sum",
)


class ReviewBundleError(RuntimeError):
    """Raised when the security-review handoff bundle cannot be produced safely."""


def _run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReviewBundleError(f"git {' '.join(args)}: {exc}") from exc
    return result.stdout


def _git_head(root: Path) -> str:
    commit = _run_git(root, "rev-parse", "HEAD").strip().lower()
    if SHA_RE.fullmatch(commit) is None:
        raise ReviewBundleError("git HEAD is not a full lowercase 40-character SHA")
    return commit


def _assert_tracked_checkout_clean(root: Path) -> None:
    status = _run_git(root, "status", "--porcelain", "--untracked-files=no")
    if status.strip():
        raise ReviewBundleError(
            "tracked checkout is dirty; review evidence must be generated from an exact commit"
        )


def _resolve_commit(root: Path, explicit_commit: str | None) -> str:
    actual = _git_head(root)
    if explicit_commit is None:
        return actual

    requested = explicit_commit.strip().lower()
    if SHA_RE.fullmatch(requested) is None:
        raise ReviewBundleError("reviewed commit must be a full lowercase 40-character SHA")
    if requested != actual:
        raise ReviewBundleError(
            f"requested reviewed commit {requested} does not match checked-out HEAD {actual}"
        )
    return actual


def _copy_required_files(root: Path, output_dir: Path) -> list[str]:
    copied: list[str] = []
    for relative in EVIDENCE_PATHS:
        source = root / relative
        if not source.is_file():
            raise ReviewBundleError(f"required review evidence is missing: {relative}")
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        copied.append(relative)
    return copied


def _load_supported_profile(root: Path) -> object:
    try:
        payload = json.loads((root / "release/v1.0-evidence.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewBundleError(f"load release evidence manifest: {exc}") from exc
    if not isinstance(payload, dict) or "supported_profile" not in payload:
        raise ReviewBundleError("release evidence manifest is missing supported_profile")
    return payload["supported_profile"]


def _write_baseline(root: Path, output_dir: Path, commit: str, copied: list[str]) -> None:
    baseline = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "repository": "smshagor-dev/ZeroTrust-FL-Sim",
        "review_gate_issue": 70,
        "reviewed_commit": commit,
        "supported_profile": _load_supported_profile(root),
        "included_paths": sorted(copied),
        "required_external_attestation": {
            "reviewer_identity": True,
            "review_window": True,
            "independence_statement": True,
            "methodology_and_tool_versions": True,
            "findings_with_severity_and_disposition": True,
            "critical_high_resolution_evidence": True,
            "final_report_or_reference": True,
        },
        "self_certification": False,
    }
    (output_dir / "REVIEW_BASELINE.json").write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_report_template(output_dir: Path, commit: str) -> None:
    template = f"""# Independent Security Assessment Report\n\nReviewed repository: `smshagor-dev/ZeroTrust-FL-Sim`\n\nReviewed commit: `{commit}`\n\n## Reviewer identity\n\nReviewer / organization: <required>\n\nReview window: <required>\n\nIndependence statement: <required>\n\nPublic report/reference URL or attached report reference: <required>\n\n## Methodology and environment\n\nHost / OS / architecture: <required>\n\nToolchain, scanner, fuzzer, compiler, runtime, and dependency-audit versions: <required>\n\nCommands, configuration, corpus/seeds, and non-secret settings needed for reproduction: <required>\n\n## Scope coverage\n\nDocument coverage of the minimum scope in `docs/independent-security-review.md`, including coordinator identity/authentication, credential lifecycle, replay controls, parsers/protocol validation, durable recovery, native aggregation, privacy/CKKS claim boundaries, Docker/Kubernetes, and release supply chain.\n\n## Findings\n\nFor every finding record a stable ID, severity/rationale, prerequisites, impact, reproduction status, affected surface, remediation or risk acceptance, regression evidence, and final disposition.\n\n## Critical and High disposition\n\nList every Critical/High finding and its verified remediation, or the explicit release-blocking risk-acceptance decision. Do not mark this section complete while any unresolved Critical/High finding remains.\n\n## Final assessment\n\nState whether the reviewed commit is acceptable for the claimed v1.0 supported profile, any residual risks, and any claim or deployment boundary that must remain restricted.\n\nThis report must be completed by the independent reviewer. The repository-generated template and evidence bundle do not satisfy issue #70 by themselves.\n"""
    (output_dir / "REVIEW_REPORT_TEMPLATE.md").write_text(template, encoding="utf-8")


def _iter_bundle_files(output_dir: Path) -> Iterable[Path]:
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            yield path


def _write_checksums(output_dir: Path) -> None:
    lines: list[str] = []
    for path in _iter_bundle_files(output_dir):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(output_dir).as_posix()
        lines.append(f"{digest}  {relative}")
    (output_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_deterministic_archive(output_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
                    data = path.read_bytes()
                    info = tarfile.TarInfo(path.relative_to(output_dir).as_posix())
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def _archive_has_bundle_marker(archive_path: Path) -> bool:
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            member = archive.getmember(BUNDLE_MARKER)
            stream = archive.extractfile(member)
            if stream is None:
                return False
            expected = f"schema_version={BUNDLE_SCHEMA_VERSION}\n".encode()
            return stream.read() == expected
    except (OSError, KeyError, tarfile.TarError):
        return False


def _prepare_output_directory(root: Path, output_dir: Path, archive_path: Path, force: bool) -> None:
    if output_dir == root or output_dir in root.parents:
        raise ReviewBundleError("output directory must not be the repository root or its ancestor")
    if archive_path == output_dir or output_dir in archive_path.parents:
        raise ReviewBundleError("archive path must be outside the review bundle directory")

    if archive_path.exists():
        if archive_path.is_dir():
            raise ReviewBundleError(f"archive path is a directory: {archive_path}")
        if not force:
            raise ReviewBundleError(f"archive already exists: {archive_path}")
        if not _archive_has_bundle_marker(archive_path):
            raise ReviewBundleError(
                "refusing to replace an archive that is not a prior review bundle"
            )

    if output_dir.exists():
        if not force:
            raise ReviewBundleError(f"output directory already exists: {output_dir}")
        marker = output_dir / BUNDLE_MARKER
        if not marker.is_file():
            raise ReviewBundleError(
                "refusing to replace an existing directory without the review-bundle marker"
            )
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    (output_dir / BUNDLE_MARKER).write_text(
        f"schema_version={BUNDLE_SCHEMA_VERSION}\n",
        encoding="utf-8",
    )


def build_review_bundle(
    root: Path,
    output_dir: Path,
    archive_path: Path,
    *,
    commit: str | None = None,
    force: bool = False,
) -> str:
    root = root.resolve()
    output_dir = output_dir.resolve()
    archive_path = archive_path.resolve()

    _assert_tracked_checkout_clean(root)
    reviewed_commit = _resolve_commit(root, commit)
    _prepare_output_directory(root, output_dir, archive_path, force)
    copied = _copy_required_files(root, output_dir)
    _write_baseline(root, output_dir, reviewed_commit, copied)
    _write_report_template(output_dir, reviewed_commit)
    _write_checksums(output_dir)
    _write_deterministic_archive(output_dir, archive_path)
    return reviewed_commit


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic evidence handoff bundle for independent security review"
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, default=Path("review-bundle"))
    parser.add_argument("--archive", type=Path, default=Path("review-bundle.tar.gz"))
    parser.add_argument(
        "--commit",
        help="optional full reviewed SHA; must exactly match the checked-out git HEAD",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace only outputs previously created by this bundle generator",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        commit = build_review_bundle(
            args.root,
            args.output_dir,
            args.archive,
            commit=args.commit,
            force=args.force,
        )
    except ReviewBundleError as exc:
        print(f"security review bundle failed: {exc}")
        return 1
    print(f"security review bundle prepared for {commit}: {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
