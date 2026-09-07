from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.prepare_security_review_bundle as review_bundle
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


def _mock_clean_git(monkeypatch: pytest.MonkeyPatch, commit: str) -> None:
    monkeypatch.setattr(review_bundle, "_git_head", lambda _root: commit)
    monkeypatch.setattr(review_bundle, "_assert_tracked_checkout_clean", lambda _root: None)


def test_review_bundle_is_deterministic_and_pins_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "a" * 40
    _mock_clean_git(monkeypatch, commit)

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


def test_review_bundle_uses_checked_out_head_when_commit_is_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "1" * 40
    _mock_clean_git(monkeypatch, commit)

    assert (
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
        )
        == commit
    )


def test_review_bundle_fails_closed_when_required_evidence_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "b" * 40
    _mock_clean_git(monkeypatch, commit)
    (root / "SECURITY.md").unlink()

    with pytest.raises(ReviewBundleError, match="required review evidence is missing: SECURITY.md"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit=commit,
        )


def test_review_bundle_rejects_noncanonical_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    _mock_clean_git(monkeypatch, "2" * 40)

    with pytest.raises(ReviewBundleError, match="full lowercase 40-character SHA"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit="abc123",
        )


def test_review_bundle_rejects_commit_that_does_not_match_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    _mock_clean_git(monkeypatch, "3" * 40)

    with pytest.raises(ReviewBundleError, match="does not match checked-out HEAD"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit="4" * 40,
        )


def test_review_bundle_rejects_dirty_tracked_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)

    def fake_git(_root: Path, *args: str) -> str:
        if args[:2] == ("status", "--porcelain"):
            return " M SECURITY.md\n"
        return "5" * 40 + "\n"

    monkeypatch.setattr(review_bundle, "_run_git", fake_git)

    with pytest.raises(ReviewBundleError, match="tracked checkout is dirty"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            tmp_path / "bundle.tar.gz",
            commit="5" * 40,
        )


def test_force_refuses_to_delete_unmarked_existing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "6" * 40
    _mock_clean_git(monkeypatch, commit)
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    protected_file = output_dir / "keep.txt"
    protected_file.write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(ReviewBundleError, match="without the review-bundle marker"):
        build_review_bundle(
            root,
            output_dir,
            tmp_path / "bundle.tar.gz",
            commit=commit,
            force=True,
        )
    assert protected_file.read_text(encoding="utf-8") == "do not delete\n"


def test_force_replaces_only_previous_bundle_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    output_dir = tmp_path / "bundle"
    archive = tmp_path / "bundle.tar.gz"

    first_commit = "7" * 40
    _mock_clean_git(monkeypatch, first_commit)
    build_review_bundle(root, output_dir, archive, commit=first_commit)
    stale = output_dir / "stale.txt"
    stale.write_text("stale\n", encoding="utf-8")

    second_commit = "8" * 40
    _mock_clean_git(monkeypatch, second_commit)
    build_review_bundle(root, output_dir, archive, commit=second_commit, force=True)
    assert not stale.exists()
    baseline = json.loads((output_dir / "REVIEW_BASELINE.json").read_text(encoding="utf-8"))
    assert baseline["reviewed_commit"] == second_commit


def test_force_refuses_to_overwrite_unrelated_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "9" * 40
    _mock_clean_git(monkeypatch, commit)
    archive = tmp_path / "evidence.tar.gz"
    archive.write_bytes(b"not a generated review bundle")

    with pytest.raises(ReviewBundleError, match="not a prior review bundle"):
        build_review_bundle(
            root,
            tmp_path / "bundle",
            archive,
            commit=commit,
            force=True,
        )
    assert archive.read_bytes() == b"not a generated review bundle"


def test_archive_must_be_outside_bundle_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _seed_review_root(root)
    commit = "f" * 40
    _mock_clean_git(monkeypatch, commit)
    output_dir = tmp_path / "bundle"

    with pytest.raises(ReviewBundleError, match="archive path must be outside"):
        build_review_bundle(
            root,
            output_dir,
            output_dir / "bundle.tar.gz",
            commit=commit,
        )
