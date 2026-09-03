from __future__ import annotations

import numpy as np
import pytest
import torch

native = pytest.importorskip("zerotrust_fl_cpp")

from zerotrust_fl.aggregators.native_cpp import (
    CppByzantineAggregator,
    CudaByzantineAggregator,
    cuda_extension_available,
)


def test_native_acceleration_metadata() -> None:
    assert native.simd_backend in {"scalar", "avx512", "neon"}
    assert isinstance(native.cuda_enabled, bool)
    assert isinstance(native.cuda_trimmed_mean_max_clients, int)


def test_simd_krum_matches_float64_reference() -> None:
    rng = np.random.default_rng(123)
    updates = [rng.normal(size=8193).astype(np.float32) for _ in range(7)]
    stacked = np.stack(updates).astype(np.float64)
    differences = stacked[:, None, :] - stacked[None, :, :]
    distances = np.einsum("ijk,ijk->ij", differences, differences, optimize=True)

    neighbor_count = 7 - 1 - 2
    scores = []
    for index in range(7):
        row = np.delete(distances[index], index)
        scores.append(np.partition(row, neighbor_count - 1)[:neighbor_count].sum())
    selected = np.argsort(np.asarray(scores), kind="stable")[:2]
    expected = stacked[selected].mean(axis=0).astype(np.float32)

    actual = native.krum_aggregate(updates, 1, 2)
    np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=1e-6)


def test_cpu_wrapper_exposes_runtime_simd_backend() -> None:
    aggregator = CppByzantineAggregator()
    assert aggregator.simd_backend in {"scalar", "avx512", "neon"}


def test_cuda_extension_availability_is_boolean() -> None:
    assert isinstance(cuda_extension_available(), bool)


@pytest.mark.skipif(
    not cuda_extension_available(),
    reason="native CUDA extension and a visible CUDA device are required",
)
def test_cuda_krum_matches_cpu_native() -> None:
    generator = torch.Generator(device="cuda").manual_seed(77)
    updates = [
        torch.randn(4097, generator=generator, device="cuda", dtype=torch.float32)
        for _ in range(7)
    ]

    gpu = CudaByzantineAggregator(validate_finite=True)
    gpu_result = gpu.krum(updates, f=1, k=2)
    torch.cuda.synchronize()

    cpu = CppByzantineAggregator(preserve_device=False, preserve_dtype=False)
    cpu_result = cpu.krum([update.cpu() for update in updates], f=1, k=2)

    assert gpu_result.device.type == "cuda"
    torch.testing.assert_close(gpu_result.cpu(), cpu_result, rtol=1e-5, atol=1e-5)


@pytest.mark.skipif(
    not cuda_extension_available(),
    reason="native CUDA extension and a visible CUDA device are required",
)
def test_cuda_trimmed_mean_matches_torch_reference() -> None:
    generator = torch.Generator(device="cuda").manual_seed(88)
    updates = [
        torch.randn((31, 17), generator=generator, device="cuda", dtype=torch.float32)
        for _ in range(10)
    ]
    beta = 0.2

    aggregator = CudaByzantineAggregator(validate_finite=True)
    actual = aggregator.trimmed_mean(updates, beta=beta)

    stacked = torch.stack(updates)
    sorted_values = torch.sort(stacked, dim=0).values
    trim = int(np.floor(beta * len(updates)))
    expected = sorted_values[trim : len(updates) - trim].mean(dim=0)

    torch.testing.assert_close(actual, expected, rtol=1e-5, atol=1e-6)
