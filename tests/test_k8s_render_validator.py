from __future__ import annotations

from pathlib import Path

from scripts.validate_k8s_render import validate


def test_validator_rejects_plaintext_secret_manifest(tmp_path: Path) -> None:
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: forbidden\nstringData:\n  token: secret\n",
        encoding="utf-8",
    )
    assert "production chart must not render Secret resources" in validate(rendered)
