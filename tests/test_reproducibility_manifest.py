from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.reproducibility import (
    MANIFEST_SCHEMA_VERSION,
    build_manifest,
    config_digest,
    resolve_commit_sha,
    write_manifest,
)


COMMIT = "a" * 40


def _manifest(*, runtime: dict[str, object]) -> dict[str, object]:
    return build_manifest(
        commit_sha=COMMIT,
        profile="quick",
        sections=["aggregation", "convergence"],
        seed=42,
        dataset="synthetic-classification",
        partition={"kind": "dirichlet", "alpha": 0.5, "seed": 42},
        privacy={"local_dp": False, "ckks": False},
        threat_model={"malicious_fraction": 0.2, "attack": "sign_flip"},
        aggregation={"method": "multi_krum", "backend": "native", "f": 2, "k": 3},
        command=["python", "benchmarks/benchmark_suite.py", "--profile", "quick"],
        generated_at_utc="2026-09-07T00:00:00+00:00",
        runtime=runtime,
    )


def test_manifest_pins_release_commit_and_research_configuration() -> None:
    manifest = _manifest(runtime={"machine": "x86_64", "cuda_available": False})

    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION == 1
    assert manifest["release_version"] == "0.9.0"
    assert manifest["commit_sha"] == COMMIT
    assert manifest["cuda_parity_evidence"] == "not_collected_by_benchmark_manifest"

    benchmark = manifest["benchmark"]
    assert isinstance(benchmark, dict)
    assert benchmark["seed"] == 42
    assert benchmark["partition"] == {"kind": "dirichlet", "alpha": 0.5, "seed": 42}
    assert benchmark["threat_model"]["malicious_fraction"] == 0.2
    assert benchmark["aggregation"]["method"] == "multi_krum"
    assert manifest["benchmark_config_sha256"] == config_digest(benchmark)


def test_configuration_digest_is_independent_of_runtime_and_timestamp() -> None:
    first = _manifest(runtime={"machine": "x86_64", "cuda_available": False})
    second = build_manifest(
        commit_sha=COMMIT,
        profile="quick",
        sections=["aggregation", "convergence"],
        seed=42,
        dataset="synthetic-classification",
        partition={"kind": "dirichlet", "alpha": 0.5, "seed": 42},
        privacy={"local_dp": False, "ckks": False},
        threat_model={"malicious_fraction": 0.2, "attack": "sign_flip"},
        aggregation={"method": "multi_krum", "backend": "native", "f": 2, "k": 3},
        command=["python", "benchmarks/benchmark_suite.py", "--profile", "quick"],
        generated_at_utc="2026-09-08T00:00:00+00:00",
        runtime={"machine": "arm64", "cuda_available": True},
    )

    assert first["benchmark_config_sha256"] == second["benchmark_config_sha256"]
    assert first["runtime"] != second["runtime"]
    assert first["generated_at_utc"] != second["generated_at_utc"]


def test_manifest_writer_emits_canonical_json_document(tmp_path: Path) -> None:
    output = tmp_path / "evidence" / "benchmark-manifest.json"
    manifest = _manifest(runtime={"machine": "x86_64"})

    write_manifest(output, manifest)

    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded == manifest
    assert output.read_text(encoding="utf-8").endswith("\n")


@pytest.mark.parametrize(
    "value",
    ["abc", "A" * 40, "g" * 40, "a" * 39, "a" * 41],
)
def test_commit_identity_rejects_noncanonical_or_ambiguous_values(value: str) -> None:
    with pytest.raises(ValueError, match="40-character lowercase Git SHA"):
        resolve_commit_sha(value)
