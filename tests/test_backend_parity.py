from __future__ import annotations

import pytest
import torch
from zerotrust_fl.aggregators.native_cpp import CppByzantineAggregator
from zerotrust_fl.engine.coordinator import AggregationConfig, _torch_aggregate

pytest.importorskip("zerotrust_fl_cpp")


PARITY_RTOL = 2e-4
PARITY_ATOL = 2e-5


def _parity_corpus() -> list[torch.Tensor]:
    """Build a deterministic corpus with well-separated Byzantine outliers."""

    axis = torch.linspace(-1.0, 1.0, steps=257, dtype=torch.float32)
    centers = (-0.30, -0.20, -0.10, 0.00, 0.05, 0.10, 0.20, 25.0, -30.0)
    return [
        (axis * (0.001 * (index + 1)) + center).contiguous()
        for index, center in enumerate(centers)
    ]


@pytest.mark.parametrize(
    ("method", "f", "k", "beta"),
    [
        ("krum", 2, 1, 0.1),
        ("multi_krum", 2, 3, 0.1),
        ("trimmed_mean", 0, 1, 0.2),
        ("median", 0, 1, 0.1),
    ],
)
def test_torch_and_native_cpu_robust_aggregation_are_numerically_equivalent(
    method: str,
    f: int,
    k: int,
    beta: float,
) -> None:
    updates = _parity_corpus()
    config = AggregationConfig(
        method=method,  # type: ignore[arg-type]
        backend="torch",
        f=f,
        k=k,
        beta=beta,
    )

    torch_result = _torch_aggregate(updates, config)
    native_result = CppByzantineAggregator(
        preserve_device=False,
        preserve_dtype=False,
    ).aggregate(
        updates,
        method=method,  # type: ignore[arg-type]
        f=f,
        k=k,
        beta=beta,
    )

    assert torch_result.shape == native_result.shape == updates[0].shape
    assert torch_result.dtype == native_result.dtype == torch.float32
    assert bool(torch.isfinite(torch_result).all())
    assert bool(torch.isfinite(native_result).all())
    torch.testing.assert_close(
        native_result,
        torch_result,
        rtol=PARITY_RTOL,
        atol=PARITY_ATOL,
    )
