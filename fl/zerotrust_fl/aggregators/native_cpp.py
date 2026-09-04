"""PyTorch integration for native Byzantine-robust aggregation backends."""

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
CudaAggregationMethod = Literal["krum", "multi_krum", "trimmed_mean"]


def native_extension_available() -> bool:
    """Return whether the compiled ``zerotrust_fl_cpp`` module can be imported."""

    return _native is not None


def cuda_extension_available() -> bool:
    """Return whether native CUDA kernels were compiled and a CUDA device is visible."""

    return bool(
        _native is not None
        and getattr(_native, "cuda_enabled", False)
        and torch.cuda.is_available()
    )


class CppByzantineAggregator:
    """Thin PyTorch wrapper over the C++20 CPU aggregation extension.

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

    @property
    def simd_backend(self) -> str:
        """Return the active CPU distance backend: ``avx512``, ``neon``, or ``scalar``."""

        return str(getattr(_native, "simd_backend", "scalar"))

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
                    non_blocking=False,
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


class CudaByzantineAggregator:
    """Device-resident CUDA backend for Krum/Multi-Krum and trimmed mean.

    The model-update payload is never copied to host memory. Each input must be
    a contiguous CUDA ``torch.float32`` tensor on the same device. The wrapper
    builds only a tiny device-side pointer table; native CUDA kernels dereference
    the original PyTorch allocations directly on the current CUDA stream.

    If tensors arrive through ``torch.multiprocessing`` CUDA sharing, PyTorch
    maps them with CUDA IPC. Their mapped ``data_ptr()`` values are consumed by
    the same kernels, preserving zero-copy access to the shared device storage.
    """

    def __init__(self, *, validate_finite: bool = True) -> None:
        if _native is None:
            raise RuntimeError(
                "zerotrust_fl_cpp is not installed; run `pip install -e .` from the repository root"
            ) from _native_import_error
        if not bool(getattr(_native, "cuda_enabled", False)):
            raise RuntimeError(
                "zerotrust_fl_cpp was built without CUDA; rebuild with ZTFL_ENABLE_CUDA=ON"
            )
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA aggregation requires an available CUDA device")
        self.validate_finite = validate_finite

    @property
    def runtime_version(self) -> int:
        """Return the CUDA Runtime version encoded as an integer (for example 12040)."""

        return int(_native.cuda_runtime_version())

    def krum(
        self,
        updates: Sequence[torch.Tensor],
        *,
        f: int,
        k: int = 1,
    ) -> torch.Tensor:
        """Run Krum/Multi-Krum while keeping update tensors resident on the GPU."""

        prepared = self._prepare_updates(updates)
        client_count = len(prepared.updates)
        if f < 0:
            raise ValueError("Byzantine count f must be non-negative")
        if client_count < 2 * f + 3:
            raise ValueError("Krum requires n >= 2*f + 3")
        neighbor_count = client_count - f - 2
        if k <= 0 or k > neighbor_count:
            raise ValueError("Multi-Krum candidate count k must satisfy 1 <= k <= n-f-2")

        with torch.cuda.device(prepared.reference.device):
            distances = torch.zeros(
                (client_count, client_count),
                dtype=torch.float64,
                device=prepared.reference.device,
            )
            distances.record_stream(prepared.stream)
            _native._cuda_pairwise_distances(
                prepared.pointer_table.data_ptr(),
                distances.data_ptr(),
                client_count,
                prepared.dimension,
                prepared.stream.cuda_stream,
            )
            distances.diagonal().fill_(float("inf"))

            nearest = torch.topk(
                distances,
                k=neighbor_count,
                dim=1,
                largest=False,
                sorted=False,
            ).values
            scores = nearest.sum(dim=1)
            selected = torch.topk(
                scores,
                k=k,
                largest=False,
                sorted=True,
            ).indices.contiguous()
            selected.record_stream(prepared.stream)

            output = torch.empty_like(prepared.reference)
            output.record_stream(prepared.stream)
            _native._cuda_average_selected(
                prepared.pointer_table.data_ptr(),
                selected.data_ptr(),
                output.data_ptr(),
                k,
                prepared.dimension,
                prepared.stream.cuda_stream,
            )
            return output

    def trimmed_mean(
        self,
        updates: Sequence[torch.Tensor],
        *,
        beta: float,
    ) -> torch.Tensor:
        """Run the coordinate-wise trimmed mean in a CUDA bitonic-sort kernel."""

        prepared = self._prepare_updates(updates)
        client_count = len(prepared.updates)
        if not 0.0 <= beta < 0.5:
            raise ValueError("trim ratio beta must satisfy 0 <= beta < 0.5")
        trim_count = int(np.floor(beta * client_count))
        if 2 * trim_count >= client_count:
            raise ValueError("trim ratio removes every model update")
        if client_count > int(getattr(_native, "cuda_trimmed_mean_max_clients", 1024)):
            raise ValueError("CUDA trimmed mean supports at most 1024 clients")

        with torch.cuda.device(prepared.reference.device):
            output = torch.empty_like(prepared.reference)
            output.record_stream(prepared.stream)
            _native._cuda_trimmed_mean(
                prepared.pointer_table.data_ptr(),
                output.data_ptr(),
                client_count,
                prepared.dimension,
                float(beta),
                prepared.stream.cuda_stream,
            )
            return output

    def aggregate(
        self,
        updates: Sequence[torch.Tensor],
        *,
        method: CudaAggregationMethod,
        f: int = 0,
        k: int = 1,
        beta: float = 0.1,
    ) -> torch.Tensor:
        """Dispatch to a device-resident CUDA robust aggregation algorithm."""

        if method == "krum":
            return self.krum(updates, f=f, k=1)
        if method == "multi_krum":
            return self.krum(updates, f=f, k=k)
        if method == "trimmed_mean":
            return self.trimmed_mean(updates, beta=beta)
        raise ValueError(f"unsupported CUDA aggregation method: {method!r}")

    def _prepare_updates(self, updates: Sequence[torch.Tensor]) -> _CudaPreparedUpdates:
        if not updates:
            raise ValueError("at least one model update is required")

        reference = updates[0]
        if not isinstance(reference, torch.Tensor):
            raise TypeError("model updates must be torch.Tensor instances")
        if reference.device.type != "cuda":
            raise TypeError("CUDA aggregation requires CUDA tensors")
        if reference.dtype != torch.float32:
            raise TypeError("zero-copy CUDA aggregation requires torch.float32 tensors")
        if not reference.is_contiguous():
            raise ValueError("zero-copy CUDA aggregation requires contiguous tensors")
        if reference.numel() == 0:
            raise ValueError("model updates must not be empty")

        expected_shape = reference.shape
        expected_device = reference.device
        stream = torch.cuda.current_stream(expected_device)
        pointers: list[int] = []

        for index, update in enumerate(updates):
            if not isinstance(update, torch.Tensor):
                raise TypeError(f"update {index} is not a torch.Tensor")
            if update.device != expected_device:
                raise ValueError("all CUDA model updates must be on the same device")
            if update.dtype != torch.float32:
                raise TypeError("zero-copy CUDA aggregation requires torch.float32 tensors")
            if update.shape != expected_shape:
                raise ValueError("all model updates must have the same shape")
            if not update.is_contiguous():
                raise ValueError("zero-copy CUDA aggregation requires contiguous tensors")
            if self.validate_finite and not bool(torch.isfinite(update).all().item()):
                raise ValueError("model updates must contain only finite values")
            update.record_stream(stream)
            pointers.append(update.data_ptr())

        pointer_table = torch.tensor(
            pointers,
            dtype=torch.int64,
            device=expected_device,
        )
        pointer_table.record_stream(stream)
        return _CudaPreparedUpdates(
            updates=tuple(updates),
            reference=reference,
            pointer_table=pointer_table,
            dimension=reference.numel(),
            stream=stream,
        )


class _CudaPreparedUpdates:
    def __init__(
        self,
        *,
        updates: tuple[torch.Tensor, ...],
        reference: torch.Tensor,
        pointer_table: torch.Tensor,
        dimension: int,
        stream: object,
    ) -> None:
        self.updates = updates
        self.reference = reference
        self.pointer_table = pointer_table
        self.dimension = dimension
        self.stream = stream
