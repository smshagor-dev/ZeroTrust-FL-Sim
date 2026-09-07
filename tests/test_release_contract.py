from __future__ import annotations

import re
from pathlib import Path

import zerotrust_fl


ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.9.0"
EXPECTED_PUBLIC_API = {
    "SDK_API_VERSION",
    "Enrollment",
    "HeartbeatStatus",
    "ModelSnapshot",
    "TensorManifest",
    "UpdateMetrics",
    "UpdateSubmission",
    "WorkerClient",
    "WorkerConfig",
    "__version__",
}


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_version_metadata_is_aligned() -> None:
    assert zerotrust_fl.__version__ == RELEASE_VERSION
    assert re.search(
        rf'\bversion="{re.escape(RELEASE_VERSION)}"',
        _read("setup.py"),
    )
    assert re.search(
        rf"\bVERSION\s+{re.escape(RELEASE_VERSION)}\b",
        _read("cpp/CMakeLists.txt"),
    )

    chart = _read("deploy/helm/zerotrust-fl/Chart.yaml")
    assert f"version: {RELEASE_VERSION}" in chart
    assert f'appVersion: "{RELEASE_VERSION}"' in chart
    assert f'version: "{RELEASE_VERSION}"' in _read("CITATION.cff")


def test_public_sdk_surface_is_frozen_for_v09() -> None:
    assert zerotrust_fl.SDK_API_VERSION == "1"
    assert set(zerotrust_fl.__all__) == EXPECTED_PUBLIC_API
