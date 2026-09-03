"""PyTorch integration for the native C++ Byzantine-robust aggregators."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

import numpy as np
import torch

try:
    import zerotrust_fl_cpp as _native
except ImportError as _native_import_error:
    _native = None
else:
    _native_import_error = None

AggregationMethod = Literal["krum", "multi_krum", "trimmed_mean", "median"]


def native_extension_available() -> bool:
    """Return whether the compiled ``zerotrust_fl_cpp`` module can be imported."""

    return _native is not None


class CppByzantineAggregator:
    """Thin PyTorch wrapper over the C++20 Byzantine aggregation extension.

    CPU, contiguous ``torch.float32`` tensors are exposed to NumPy without a
    data copy. Other dtypes, non-contiguous tensors, and accelerator tensors
    are converted to contiguous host-side float32 buffers before native code is
    invoked. Native computation releases the Python GIL.
    """

    def __init__(
        self,
        *,
        preserve_device: bool = True,
        preserve_dtype: bool = True,
        non_blocking_transfers: bool = True,
    ) -> None:
        if _native is None:
            raise RuntimeError(
                "zerotrust_fl_cpp is not installed; run `pip install -e .` from the repository root"
            ) from _native_import_error
        self.preserve_device = preserve_device
        self.preserve_dtype = preserve_dtype
        self.non_blocking_transfers = non_blocking_transfers

    @property
    def openmp_enabled(self) -> bool:
        """Whether the loaded native module was built with OpenMP support."""

        return bool(getattr(_native, "openmp_enabled", False))

    def krum(
        self,
        updates: Sequence[torch.Tensor],
        *,
        f: int,
        k: int = 1,
    ) -> torch.Tensor:
        """Aggregate using Krum (``k=1``) or Multi-Krum (``k>1``)."""

        arrays, reference = self._to_numpy_updates(updates)
        result = _native.krum_aggregate(arrays, int(f), int(k))
        return self._to_torch_result(result, reference)

    def trimmed_mean(
        self,
        updates: Sequence[torch.Tensor],
        *,
        beta: float,
    ) -> torch.Tensor:
        """Aggregate using a coordinate-wise adaptive trimmed mean."""

        arrays, reference = self._to_numpy_updates(updates)
        result = _native.trimmed_mean_aggregate(arrays, float(beta))
        return self._to_torch_result(result, reference)

    def median(self, updates: Sequence[torch.Tensor]) -> torch.Tensor:
        """Aggregate using the coordinate-wise median."""

        arrays, reference = self._to_numpy_updates(updates)
        result = _native.median_aggregate(arrays)
        return self._to_torch_result(result, reference)

    def aggregate(
        self,
        updates: Sequence[torch.Tensor],
        *,
        method: AggregationMethod,
        f: int = 0,
        k: int = 1,
        beta: float = 0.1,
    ) -> torch.Tensor:
        """Dispatch to one of the native robust aggregation algorithms."""

        if method == "krum":
            return self.krum(updates, f=f, k=1)
        if method == "multi_krum":
            return self.krum(updates, f=f, k=k)
        if method == "trimmed_mean":
            return self.trimmed_mean(updates, beta=beta)
        if method == "median":
            return self.median(updates)
        raise ValueError(f"unsupported aggregation method: {method!r}")

    def _to_numpy_updates(
        self,
        updates: Sequence[torch.Tensor],
    ) -> tuple[list[np.ndarray], torch.Tensor]:
        if not updates:
            raise ValueError("at least one model update is required")

        reference = updates[0]
        if not isinstance(reference, torch.Tensor):
            raise TypeError("model updates must be torch.Tensor instances")
        if not reference.is_floating_point():
            raise TypeError("model updates must use a floating-point dtype")

        expected_shape = reference.shape
        host_tensors: list[torch.Tensor] = []
        arrays: list[np.ndarray] = []

        for index, update in enumerate(updates):
            if not isinstance(update, torch.Tensor):
                raise TypeError(f"update {index} is not a torch.Tensor")
            if not update.is_floating_point():
                raise TypeError(f"update {index} must use a floating-point dtype")
            if update.shape != expected_shape:
                raise ValueError("all model updates must have the same shape")

            detached = update.detach()
            if detached.device.type == "cpu":
                host = detached.to(dtype=torch.float32).contiguous()
            else:
                host = detached.to(
                    device="cpu",
                    dtype=torch.float32,
                    non_blocking=self.non_blocking_transfers,
                ).contiguous()

            host_tensors.append(host)
            arrays.append(host.numpy())

        if len(host_tensors) != len(arrays):
            raise RuntimeError("failed to prepare native aggregation buffers")
        return arrays, reference

    def _to_torch_result(
        self,
        result: np.ndarray,
        reference: torch.Tensor,
    ) -> torch.Tensor:
        output = torch.from_numpy(np.asarray(result, dtype=np.float32))
        if self.preserve_dtype and output.dtype != reference.dtype:
            output = output.to(dtype=reference.dtype)
        if self.preserve_device and reference.device.type != "cpu":
            output = output.to(
                device=reference.device,
                non_blocking=self.non_blocking_transfers,
            )
        return output
