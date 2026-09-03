"""CKKS encrypted model-update aggregation backed by the native C++ extension."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
import torch

try:
    import zerotrust_fl_cpp as _native
except ImportError:  # pragma: no cover - exercised when native build is unavailable
    _native = None


@dataclass(frozen=True, slots=True)
class CKKSConfig:
    poly_modulus_degree: int = 8192
    coeff_modulus_bits: tuple[int, ...] = (60, 40, 40, 60)
    scale_bits: int = 40

    def __post_init__(self) -> None:
        degree = self.poly_modulus_degree
        if degree < 2048 or degree & (degree - 1):
            raise ValueError("poly_modulus_degree must be a power of two >= 2048")
        if len(self.coeff_modulus_bits) < 2:
            raise ValueError("at least two coefficient-modulus primes are required")
        if self.scale_bits <= 0 or self.scale_bits >= 60:
            raise ValueError("scale_bits must be in (0, 60)")


@dataclass(frozen=True, slots=True)
class CKKSPublicBundle:
    parameters: bytes
    public_key: bytes
    slot_count: int
    scale_bits: int


@dataclass(frozen=True, slots=True)
class CKKSKeyMaterial:
    parameters: bytes
    public_key: bytes
    secret_key: bytes
    slot_count: int
    scale_bits: int

    @classmethod
    def generate(cls, config: CKKSConfig | None = None) -> "CKKSKeyMaterial":
        _require_native_ckks()
        cfg = config or CKKSConfig()
        raw = _native.ckks_generate_key_material(
            cfg.poly_modulus_degree,
            list(cfg.coeff_modulus_bits),
            cfg.scale_bits,
        )
        return cls(
            parameters=bytes(raw["parameters"]),
            public_key=bytes(raw["public_key"]),
            secret_key=bytes(raw["secret_key"]),
            slot_count=int(raw["slot_count"]),
            scale_bits=int(raw["scale_bits"]),
        )

    def public_bundle(self) -> CKKSPublicBundle:
        return CKKSPublicBundle(
            parameters=self.parameters,
            public_key=self.public_key,
            slot_count=self.slot_count,
            scale_bits=self.scale_bits,
        )


@dataclass(frozen=True, slots=True)
class EncryptedUpdate:
    chunks: tuple[bytes, ...]
    original_size: int
    weight: float


class CKKSClientEncryptor:
    """Client-side encryptor containing public material only."""

    def __init__(self, bundle: CKKSPublicBundle) -> None:
        _require_native_ckks()
        self.bundle = bundle

    def encrypt(self, update: torch.Tensor | np.ndarray | Iterable[float], *, weight: float = 1.0) -> EncryptedUpdate:
        if not np.isfinite(weight) or weight <= 0:
            raise ValueError("weight must be finite and positive")
        values = _as_numpy_vector(update)
        weighted = np.ascontiguousarray(values * float(weight), dtype=np.float64)
        chunks = _native.ckks_encrypt(
            weighted,
            self.bundle.parameters,
            self.bundle.public_key,
            self.bundle.scale_bits,
        )
        return EncryptedUpdate(
            chunks=tuple(bytes(chunk) for chunk in chunks),
            original_size=int(weighted.size),
            weight=float(weight),
        )


class CKKSServerAggregator:
    """Server-side additive aggregator that never receives the CKKS secret key."""

    def __init__(self, parameters: bytes) -> None:
        _require_native_ckks()
        if not parameters:
            raise ValueError("serialized CKKS parameters are required")
        self.parameters = bytes(parameters)

    def aggregate(self, updates: Iterable[EncryptedUpdate]) -> EncryptedUpdate:
        materialized = tuple(updates)
        if not materialized:
            raise ValueError("at least one encrypted update is required")
        original_size = materialized[0].original_size
        if any(update.original_size != original_size for update in materialized):
            raise ValueError("all encrypted updates must have the same original size")
        chunks = _native.ckks_add(
            [list(update.chunks) for update in materialized],
            self.parameters,
        )
        return EncryptedUpdate(
            chunks=tuple(bytes(chunk) for chunk in chunks),
            original_size=original_size,
            weight=float(sum(update.weight for update in materialized)),
        )


class CKKSDecryptor:
    """Key-authority side decryptor; keep this object outside the aggregation server."""

    def __init__(self, key_material: CKKSKeyMaterial) -> None:
        _require_native_ckks()
        self.key_material = key_material

    def decrypt_sum(self, encrypted: EncryptedUpdate) -> np.ndarray:
        values = _native.ckks_decrypt(
            list(encrypted.chunks),
            self.key_material.parameters,
            self.key_material.secret_key,
            encrypted.original_size,
        )
        return np.asarray(values, dtype=np.float64)

    def decrypt_weighted_mean(self, encrypted: EncryptedUpdate) -> np.ndarray:
        if encrypted.weight <= 0:
            raise ValueError("aggregate weight must be positive")
        return self.decrypt_sum(encrypted) / encrypted.weight


def native_ckks_available() -> bool:
    return bool(_native is not None and getattr(_native, "ckks_enabled", False))


def _require_native_ckks() -> None:
    if not native_ckks_available():
        raise RuntimeError(
            "CKKS support is unavailable; rebuild zerotrust_fl_cpp with ZTFL_ENABLE_CKKS=ON"
        )


def _as_numpy_vector(values: torch.Tensor | np.ndarray | Iterable[float]) -> np.ndarray:
    if isinstance(values, torch.Tensor):
        array = values.detach().to(device="cpu", dtype=torch.float64).numpy()
    elif isinstance(values, np.ndarray):
        array = values.astype(np.float64, copy=False)
    else:
        array = np.asarray(tuple(values), dtype=np.float64)
    vector = np.ascontiguousarray(array.reshape(-1), dtype=np.float64)
    if vector.size == 0:
        raise ValueError("model update must not be empty")
    if not np.isfinite(vector).all():
        raise ValueError("model update contains non-finite values")
    return vector
