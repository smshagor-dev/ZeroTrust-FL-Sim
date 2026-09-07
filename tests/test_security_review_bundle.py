from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.prepare_security_review_bundle import (
    BUNDLE_MARKER,
    EVIDENCE_PATHS,
    ReviewBundleError,
    build_review_bundle,
)


def _seed_review_root(root: Path) -> None:
    for relative in EVIDENCE_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "release/v1.0-evidence.json":
            path.write_text(
                json.dumps(
                    {
                        "supported_profile": {
                            "aggregation_backends": ["pytorch-cpu", "native-cpp-cpu"],
                            "cuda_status": "experimental-unvalidated",
                            "cuda_evidence_url": None,
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        else:
            path.write_text(f"fixture for {relative}\n", encoding="utf-8")


def test_review_bundle_is_deterministic_and_pins_commit(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "a" * 40

    first_dir = tmp_path / "bundle-a"
    first_archive = tmp_path / "bundle-a.tar.gz"
    second_dir = tmp_path / "bundle-b"
    second_archive = tmp_path / "bundle-b.tar.gz"

    assert build_review_bundle(root, first_dir, first_archive, commit=commit) == commit
    assert build_review_bundle(root, second_dir, second_archive, commit=commit) == commit
    assert first_archive.read_bytes() == second_archive.read_bytes()

    baseline = json.loads((first_dir / "REVIEW_BASELINE.json").read_text(encoding="utf-8"))
    assert baseline["reviewed_commit"] == commit
    assert baseline["review_gate_issue"] == 70
    assert baseline["self_certification"] is False
    assert baseline["supported_profile"]["cuda_status"] == "experimental-unvalidated"
    assert baseline["included_paths"] == sorted(EVIDENCE_PATHS)

    checksums = (first_dir / "SHA256SUMS").read_text(encoding="utf-8")
    assert BUNDLE_MARKER in checksums
    assert "REVIEW_BASELINE.json" in checksums
    assert "REVIEW_REPORT_TEMPLATE.md" in checksums
    assert "docs/independent-security-review.md" in checksums


def test_review_bundle_fails_closed_when_required_evidence_is_missing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    (root / "SECURITY.md").unlink()

    with pytest.raises(ReviewBundleError, match="required review evidence is missing: SECURITY.md"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit="b" * 40,
        )


def test_review_bundle_rejects_noncanonical_commit(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)

    with pytest.raises(ReviewBundleError, match="full lowercase 40-character SHA"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit="abc123",
        )


def test_force_refuses_to_delete_unmarked_existing_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    protected_file = output_dir / "keep.txt"
    protected_file.write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(ReviewBundleError, match="without the review-bundle marker"):
        build_review_bundle(
            root,
            output_dir,
            tmp_path / "bundle.tar.gz",
            commit="c" * 40,
            force=True,
        )
    assert protected_file.read_text(encoding="utf-8") == "do not delete\n"


def test_force_replaces_only_previous_bundle_output(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    output_dir = tmp_path / "bundle"
    archive = tmp_path / "bundle.tar.gz"

    build_review_bundle(root, output_dir, archive, commit="d" * 40)
    stale = output_dir / "stale.txt"
    stale.write_text("stale\n", encoding="utf-8")

    build_review_bundle(root, output_dir, archive, commit="e" * 40, force=True)
    assert not stale.exists()
    baseline = json.loads((output_dir / "REVIEW_BASELINE.json").read_text(encoding="utf-8"))
    assert baseline["reviewed_commit"] == "e" * 40


def test_force_refuses_to_overwrite_unrelated_archive(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    archive = tmp_path / "evidence.tar.gz"
    archive.write_bytes(b"not a generated review bundle")

    with pytest.raises(ReviewBundleError, match="not a prior review bundle"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            archive,
            commit="e" * 40,
            force=True,
        )
    assert archive.read_bytes() == b"not a generated review bundle"


def test_archive_must_be_outside_bundle_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    output_dir = tmp_path / "bundle"

    with pytest.raises(ReviewBundleError, match="archive path must be outside"):
        build_review_bundle(
            root,
            output_dir,
            output_dir / "bundle.tar.gz",
            commit="f" * 40,
        )
