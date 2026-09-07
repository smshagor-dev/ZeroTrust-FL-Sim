"""Capture CUDA aggregation parity evidence on a real CUDA-capable runner."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import torch

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from zerotrust_fl.aggregators.native_cpp import (
    CudaByzantineAggregator,
    cuda_extension_available,
)
from zerotrust_fl.engine.coordinator import (
    AggregationConfig,
    _torch_aggregate,
)
from benchmarks.reproducibility import resolve_commit_sha


EVIDENCE_SCHEMA_VERSION = 1
PARITY_RTOL = 2e-4
PARITY_ATOL = 2e-5


def _corpus(seed: int) -> list[torch.Tensor]:
    generator = torch.Generator().manual_seed(seed)
    honest = [
        torch.randn(1024, generator=generator, dtype=torch.float32) * 0.02
        + float(index) * 0.01
        for index in range(7)
    ]
    return [*honest, torch.full((1024,), 25.0), torch.full((1024,), -30.0)]


def _case(
    *,
    cuda: CudaByzantineAggregator,
    cpu_updates: list[torch.Tensor],
    method: str,
    f: int,
    k: int,
    beta: float,
) -> dict[str, Any]:
    config = AggregationConfig(
        method=method,  # type: ignore[arg-type]
        backend="torch",
        f=f,
        k=k,
        beta=beta,
    )
    expected = _torch_aggregate(cpu_updates, config)
    device_updates = [update.cuda().contiguous() for update in cpu_updates]
    if method == "krum":
        actual = cuda.krum(device_updates, f=f, k=1)
    elif method == "multi_krum":
        actual = cuda.krum(device_updates, f=f, k=k)
    elif method == "trimmed_mean":
        actual = cuda.trimmed_mean(device_updates, beta=beta)
    else:
        raise ValueError(f"unsupported CUDA parity method: {method}")

    actual_cpu = actual.detach().cpu()
    torch.testing.assert_close(actual_cpu, expected, rtol=PARITY_RTOL, atol=PARITY_ATOL)
    max_abs_error = float(torch.max(torch.abs(actual_cpu - expected)).item())
    return {
        "method": method,
        "f": f,
        "k": k,
        "beta": beta,
        "max_abs_error": max_abs_error,
        "rtol": PARITY_RTOL,
        "atol": PARITY_ATOL,
        "passed": True,
    }


def capture(*, commit_sha: str, seed: int) -> dict[str, Any]:
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA parity evidence requires a real visible CUDA device")
    if not cuda_extension_available():
        raise RuntimeError(
            "CUDA parity evidence requires zerotrust_fl_cpp built with ZTFL_ENABLE_CUDA=ON"
        )

    cuda = CudaByzantineAggregator(validate_finite=True)
    device_index = torch.cuda.current_device()
    properties = torch.cuda.get_device_properties(device_index)
    cpu_updates = _corpus(seed)
    cases = [
        _case(cuda=cuda, cpu_updates=cpu_updates, method="krum", f=2, k=1, beta=0.1),
        _case(
            cuda=cuda,
            cpu_updates=cpu_updates,
            method="multi_krum",
            f=2,
            k=3,
            beta=0.1,
        ),
        _case(
            cuda=cuda,
            cpu_updates=cpu_updates,
            method="trimmed_mean",
            f=0,
            k=1,
            beta=0.2,
        ),
    ]
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": "cuda_aggregation_parity",
        "commit_sha": resolve_commit_sha(commit_sha),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "real_cuda_device": True,
        "seed": seed,
        "torch_version": torch.__version__,
        "torch_cuda_version": torch.version.cuda,
        "native_cuda_runtime_version": cuda.runtime_version,
        "device": {
            "index": device_index,
            "name": properties.name,
            "capability": list(torch.cuda.get_device_capability(device_index)),
            "total_memory_bytes": int(properties.total_memory),
        },
        "cases": cases,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--commit-sha")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = Path(args.output)
    output.unlink(missing_ok=True)
    evidence = capture(commit_sha=resolve_commit_sha(args.commit_sha), seed=args.seed)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
