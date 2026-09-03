"""Byzantine-robust federated aggregation interfaces."""

from .native_cpp import CppByzantineAggregator, native_extension_available

__all__ = ["CppByzantineAggregator", "native_extension_available"]
