from __future__ import annotations

import argparse
import json
import statistics
import time
from collections.abc import Callable
from functools import partial

import torch
from zerotrust_fl.aggregators.native_cpp import (
    CppByzantineAggregator,
    CudaByzantineAggregator,
    cuda_extension_available,
)


def _measure_cpu(operation: Callable[[], torch.Tensor], repeats: int) -> list[float]:
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - start)
    return samples


def _measure_cuda(operation: Callable[[], torch.Tensor], repeats: int) -> list[float]:
    operation()
    torch.cuda.synchronize()
    samples: list[float] = []
    for _ in range(repeats):
        start = torch.cuda.Event(enable_timing=True)
        end = torch.cuda.Event(enable_timing=True)
        start.record()
        operation()
        end.record()
        end.synchronize()
        samples.append(start.elapsed_time(end) / 1000.0)
    return samples


def _summary(samples: list[float]) -> dict[str, float]:
    return {
        "mean_seconds": statistics.fmean(samples),
        "median_seconds": statistics.median(samples),
        "min_seconds": min(samples),
        "max_seconds": max(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark SIMD and CUDA robust aggregation")
    parser.add_argument("--clients", type=int, default=7)
    parser.add_argument("--parameters", type=int, default=1_000_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--f", type=int, default=1)
    parser.add_argument("--k", type=int, default=2)
    parser.add_argument("--beta", type=float, default=0.2)
    parser.add_argument("--method", choices=("krum", "trimmed_mean"), default="krum")
    args = parser.parse_args()

    generator = torch.Generator().manual_seed(42)
    cpu_updates = [
        torch.randn(args.parameters, generator=generator, dtype=torch.float32)
        for _ in range(args.clients)
    ]
    cpu = CppByzantineAggregator(preserve_device=False, preserve_dtype=False)

    if args.method == "krum":
        cpu_operation = partial(cpu.krum, cpu_updates, f=args.f, k=args.k)
    else:
        cpu_operation = partial(cpu.trimmed_mean, cpu_updates, beta=args.beta)

    result: dict[str, object] = {
        "clients": args.clients,
        "parameters_per_client": args.parameters,
        "method": args.method,
        "cpu_simd_backend": cpu.simd_backend,
        "cpu": _summary(_measure_cpu(cpu_operation, args.repeats)),
        "cuda_compiled_and_visible": cuda_extension_available(),
    }

    if cuda_extension_available():
        cuda_updates = [update.cuda() for update in cpu_updates]
        gpu = CudaByzantineAggregator()
        if args.method == "krum":
            cuda_operation = partial(gpu.krum, cuda_updates, f=args.f, k=args.k)
        else:
            cuda_operation = partial(gpu.trimmed_mean, cuda_updates, beta=args.beta)
        result["cuda_runtime_version"] = gpu.runtime_version
        result["cuda"] = _summary(_measure_cuda(cuda_operation, args.repeats))

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
