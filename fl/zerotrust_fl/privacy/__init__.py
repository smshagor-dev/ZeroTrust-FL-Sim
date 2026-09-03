"""Privacy-preserving primitives for federated model updates."""

from zerotrust_fl.privacy.ckks import (
    CKKSConfig,
    CKKSKeyMaterial,
    CKKSPublicBundle,
    CKKSDecryptor,
    CKKSServerAggregator,
    CKKSClientEncryptor,
    native_ckks_available,
)
from zerotrust_fl.privacy.rdp import (
    LocalDPConfig,
    ProtectedUpdate,
    RDPAccountant,
    protect_model_update,
)

__all__ = [
    "CKKSClientEncryptor",
    "CKKSConfig",
    "CKKSDecryptor",
    "CKKSKeyMaterial",
    "CKKSPublicBundle",
    "CKKSServerAggregator",
    "LocalDPConfig",
    "ProtectedUpdate",
    "RDPAccountant",
    "native_ckks_available",
    "protect_model_update",
]
