from __future__ import annotations

import os
import time
from collections.abc import Sequence

import numpy as np
import pytest
import torch

native = pytest.importorskip("zerotrust_fl_cpp")

from zerotrust_fl.aggregators.native_cpp import CppByzantineAggregator


def _numpy_krum(updates: Sequence[np.ndarray], f: int, k: int) -> np.ndarray:
    stacked = np.stack(updates).astype(np.float64, copy=False)
    n = stacked.shape[0]
    if n < 2 * f + 3:
        raise ValueError("Krum requires n >= 2*f + 3")
    neighbor_count = n - f - 2
    if not 1 <= k <= neighbor_count:
        raise ValueError("invalid k")

    flat = stacked.reshape(n, -1)
    diff = flat[:, None, :] - flat[None, :, :]
    distances = np.einsum("ijk,ijk->ij", diff, diff, optimize=True)
    scores = np.empty(n, dtype=np.float64)
    for index in range(n):
        row = np.delete(distances[index], index)
        scores[index] = np.partition(row, neighbor_count - 1)[:neighbor_count].sum()

    selected = np.argsort(scores, kind="stable")[:k]
    return stacked[selected].mean(axis=0).astype(np.float32)


def _numpy_trimmed_mean(updates: Sequence[np.ndarray], beta: float) -> np.ndarray:
    stacked = np.sort(np.stack(updates).astype(np.float64), axis=0)
    trim = int(np.floor(beta * len(stacked)))
    retained = stacked[trim : len(stacked) - trim]
    return retained.mean(axis=0).astype(np.float32)


def _numpy_median(updates: Sequence[np.ndarray]) -> np.ndarray:
    return np.median(np.stack(updates).astype(np.float64), axis=0).astype(np.float32)


def _torch_updates(
    seed: int = 17,
    clients: int = 9,
    shape: tuple[int, ...] = (8, 16),
) -> list[torch.Tensor]:
    generator = torch.Generator().manual_seed(seed)
    return [
        torch.randn(shape, generator=generator, dtype=torch.float32)
        for _ in range(clients)
    ]


def test_native_module_metadata() -> None:
    assert native.__version__ == "0.2.0"
    assert isinstance(native.openmp_enabled, bool)


def test_krum_matches_numpy_reference() -> None:
    updates = _torch_updates()
    arrays = [update.numpy() for update in updates]

    expected = _numpy_krum(arrays, f=2, k=3)
    actual = native.krum_aggregate(arrays, 2, 3)

    assert actual.shape == updates[0].shape
    assert actual.dtype == np.float32
    np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=1e-6)


def test_trimmed_mean_matches_numpy_reference() -> None:
    updates = _torch_updates(clients=10)
    arrays = [update.numpy() for update in updates]

    expected = _numpy_trimmed_mean(arrays, beta=0.2)
    actual = native.trimmed_mean_aggregate(arrays, 0.2)

    np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=1e-6)


def test_coordinate_median_matches_numpy_reference_for_even_and_odd_clients() -> None:
    for clients in (9, 10):
        updates = _torch_updates(clients=clients)
        arrays = [update.numpy() for update in updates]

        expected = _numpy_median(arrays)
        actual = native.median_aggregate(arrays)

        np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=1e-6)


def test_pybind_rejects_shape_mismatch_and_non_finite_input() -> None:
    with pytest.raises(ValueError, match="same shape"):
        native.median_aggregate(
            [np.zeros((4,), dtype=np.float32), np.zeros((5,), dtype=np.float32)]
        )

    invalid = np.zeros((4,), dtype=np.float32)
    invalid[2] = np.nan
    with pytest.raises(ValueError, match="finite"):
        native.trimmed_mean_aggregate(
            [np.zeros((4,), dtype=np.float32), invalid],
            0.0,
        )


def test_krum_rejects_unsafe_fault_assumption() -> None:
    updates = [np.zeros((8,), dtype=np.float32) for _ in range(6)]
    with pytest.raises(ValueError, match=r"n >= 2\*f \+ 3"):
        native.krum_aggregate(updates, 2, 1)


def test_torch_wrapper_preserves_shape_device_and_dtype() -> None:
    updates = [
        tensor.to(dtype=torch.float64).T
        for tensor in _torch_updates(shape=(4, 7))
    ]
    aggregator = CppByzantineAggregator()

    result = aggregator.median(updates)

    assert result.shape == updates[0].shape
    assert result.device == updates[0].device
    assert result.dtype == updates[0].dtype

    expected = torch.from_numpy(
        _numpy_median([tensor.float().numpy() for tensor in updates])
    )
    torch.testing.assert_close(result.float(), expected, rtol=1e-5, atol=1e-6)


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("multi_krum", {"f": 2, "k": 3}),
        ("trimmed_mean", {"beta": 0.2}),
        ("median", {}),
    ],
)
def test_robust_aggregation_converges_with_twenty_percent_byzantine_clients(
    method: str,
    kwargs: dict[str, int | float],
) -> None:
    rng = np.random.default_rng(42)
    dimension = 128
    client_count = 10
    byzantine_count = 2
    rounds = 25
    step_size = 0.25

    target = rng.normal(size=dimension).astype(np.float32)
    model = np.zeros_like(target)
    initial_distance = float(np.linalg.norm(target - model))
    aggregator = CppByzantineAggregator(preserve_dtype=False)

    for _ in range(rounds):
        direction = target - model
        honest = [
            direction + rng.normal(0.0, 0.03, size=dimension).astype(np.float32)
            for _ in range(client_count - byzantine_count)
        ]
        sign_flip = (
            -8.0 * direction + rng.normal(0.0, 0.1, size=dimension).astype(np.float32)
        )
        gaussian_attack = rng.normal(0.0, 20.0, size=dimension).astype(np.float32)
        updates = [
            torch.from_numpy(update)
            for update in [*honest, sign_flip, gaussian_attack]
        ]

        aggregate = aggregator.aggregate(updates, method=method, **kwargs)
        model += step_size * aggregate.numpy()

    final_distance = float(np.linalg.norm(target - model))
    assert final_distance < 0.05 * initial_distance


def _pure_python_coordinate_median(updates: Sequence[np.ndarray]) -> np.ndarray:
    dimension = updates[0].size
    client_count = len(updates)
    middle = client_count // 2
    output = np.empty(dimension, dtype=np.float32)

    for coordinate in range(dimension):
        values = sorted(float(update[coordinate]) for update in updates)
        if client_count % 2:
            output[coordinate] = values[middle]
        else:
            output[coordinate] = 0.5 * (values[middle - 1] + values[middle])
    return output


@pytest.mark.performance
@pytest.mark.skipif(
    os.getenv("ZTFL_RUN_PERF") != "1",
    reason="set ZTFL_RUN_PERF=1 to run the 1M-parameter native micro-benchmark",
)
def test_cpp_median_microbenchmark_outperforms_pure_python() -> None:
    rng = np.random.default_rng(7)
    clients = 9
    parameters = 1_000_000
    updates = [
        rng.normal(size=parameters).astype(np.float32)
        for _ in range(clients)
    ]

    native.median_aggregate([update[:4096] for update in updates])

    start = time.perf_counter()
    cpp_result = native.median_aggregate(updates)
    cpp_seconds = time.perf_counter() - start

    start = time.perf_counter()
    python_result = _pure_python_coordinate_median(updates)
    python_seconds = time.perf_counter() - start

    np.testing.assert_allclose(cpp_result, python_result, rtol=0.0, atol=0.0)
    speedup = python_seconds / cpp_seconds
    print(
        f"native median: {cpp_seconds:.4f}s, pure Python: {python_seconds:.4f}s, "
        f"speedup: {speedup:.2f}x"
    )
    assert cpp_seconds < python_seconds
