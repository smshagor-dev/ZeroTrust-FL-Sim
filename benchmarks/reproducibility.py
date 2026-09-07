"""Reproducibility manifest generation for ZeroTrust-FL-Sim benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import torch
import zerotrust_fl
from zerotrust_fl.aggregators.native_cpp import native_extension_available


MANIFEST_SCHEMA_VERSION = 1
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def canonical_json(value: Any) -> str:
    """Return a stable JSON encoding suitable for cryptographic configuration digests."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def config_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def resolve_commit_sha(explicit: str | None = None) -> str:
    """Resolve an exact Git commit SHA or fail instead of emitting ambiguous evidence."""

    candidates = (
        explicit,
        os.getenv("ZTFL_COMMIT_SHA"),
        os.getenv("GITHUB_SHA"),
    )
    for candidate in candidates:
        if candidate:
            normalized = candidate.strip().lower()
            if _COMMIT_SHA_RE.fullmatch(normalized):
                return normalized
            raise ValueError("benchmark evidence requires a full 40-character lowercase Git SHA")

    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "could not resolve benchmark commit SHA; pass --commit-sha or ZTFL_COMMIT_SHA"
        ) from exc

    normalized = completed.stdout.strip().lower()
    if not _COMMIT_SHA_RE.fullmatch(normalized):
        raise RuntimeError("git rev-parse did not return a full 40-character commit SHA")
    return normalized


def runtime_facts() -> dict[str, Any]:
    native_version: str | None = None
    native_openmp: bool | None = None
    native_simd: str | None = None
    if native_extension_available():
        import zerotrust_fl_cpp as native

        native_version = str(native.__version__)
        native_openmp = bool(native.openmp_enabled)
        native_simd = str(native.simd_backend)

    cuda_available = bool(torch.cuda.is_available())
    cuda_device: dict[str, Any] | None = None
    if cuda_available:
        index = torch.cuda.current_device()
        properties = torch.cuda.get_device_properties(index)
        cuda_device = {
            "index": index,
            "name": properties.name,
            "capability": list(torch.cuda.get_device_capability(index)),
            "total_memory_bytes": int(properties.total_memory),
        }

    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "torch": torch.__version__,
        "native_extension": native_extension_available(),
        "native_version": native_version,
        "native_openmp": native_openmp,
        "native_simd": native_simd,
        "cuda_available": cuda_available,
        "torch_cuda_version": torch.version.cuda,
        "cuda_device": cuda_device,
    }


def build_manifest(
    *,
    commit_sha: str,
    profile: str,
    sections: list[str],
    seed: int,
    dataset: str,
    partition: dict[str, Any],
    privacy: dict[str, Any],
    threat_model: dict[str, Any],
    aggregation: dict[str, Any],
    command: list[str],
    generated_at_utc: str | None = None,
    runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    commit_sha = resolve_commit_sha(commit_sha)
    benchmark_config = {
        "profile": profile,
        "sections": list(sections),
        "seed": int(seed),
        "dataset": dataset,
        "partition": partition,
        "privacy": privacy,
        "threat_model": threat_model,
        "aggregation": aggregation,
        "command": list(command),
    }
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_version": zerotrust_fl.__version__,
        "commit_sha": commit_sha,
        "generated_at_utc": generated_at_utc or datetime.now(UTC).isoformat(),
        "benchmark_config_sha256": config_digest(benchmark_config),
        "benchmark": benchmark_config,
        "runtime": runtime if runtime is not None else runtime_facts(),
        "cuda_parity_evidence": "not_collected_by_benchmark_manifest",
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _json_object(raw: str, flag: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"{flag} must be valid JSON") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError(f"{flag} must decode to a JSON object")
    return value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--commit-sha")
    parser.add_argument("--profile", default="quick")
    parser.add_argument("--sections", nargs="+", default=["aggregation", "network", "convergence"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dataset", default="synthetic")
    parser.add_argument("--partition-json", default="{}")
    parser.add_argument("--privacy-json", default="{}")
    parser.add_argument("--threat-model-json", default="{}")
    parser.add_argument("--aggregation-json", default="{}")
    parser.add_argument("--command", nargs="*", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = build_manifest(
        commit_sha=resolve_commit_sha(args.commit_sha),
        profile=args.profile,
        sections=args.sections,
        seed=args.seed,
        dataset=args.dataset,
        partition=_json_object(args.partition_json, "--partition-json"),
        privacy=_json_object(args.privacy_json, "--privacy-json"),
        threat_model=_json_object(args.threat_model_json, "--threat-model-json"),
        aggregation=_json_object(args.aggregation_json, "--aggregation-json"),
        command=args.command or sys.argv,
    )
    write_manifest(Path(args.output), manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
