"""Byzantine-robust federated aggregation interfaces."""

from .native_cpp import (
    CppByzantineAggregator,
    CudaByzantineAggregator,
    cuda_extension_available,
    native_extension_available,
)

__all__ = [
    "CppByzantineAggregator",
    "CudaByzantineAggregator",
    "cuda_extension_available",
    "native_extension_available",
]
