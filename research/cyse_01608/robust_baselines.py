"""Additional *plaintext* Byzantine aggregation baselines for CYSE-01608.

- RFA geometric median approximated by smoothed Weiszfeld (known prior art).
- Server-enforced norm projection after receiving client update bytes.
- This module is deliberately NOT a CKKS-encrypted Byzantine filter.
- Enforcement on post-local-DP releases is postprocessing but requires the
  server to see the plaintext/noisy vector and authentic client identity.
"""
from __future__ import annotations

import math
import numpy as np

EXTENSION_AGGREGATORS = (
    "rfa",
    "server_clipped_mean",
    "server_clipped_rfa",
    "server_clipped_multi_krum",
)
TRUSTED_ROOT_AGGREGATORS = ("fltrust",)


def _validate(updates: np.ndarray) -> np.ndarray:
    data = np.asarray(updates, dtype=np.float64)
    if data.ndim != 2 or data.shape[0] < 2 or data.shape[1] < 1:
        raise ValueError("expected [at least two clients, nonempty vector]")
    if not np.isfinite(data).all():
        raise ValueError("untrusted updates must contain only finite numbers")
    return data


def project_l2(updates: np.ndarray, cap: float) -> np.ndarray:
    """Enforce a SERVER-SIDE L2 cap on every update, including Byzantine clients.

    Only protects the *magnitude* of observed plaintext update vectors.
    It does not verify that an attacker followed client-side Gaussian DP,
    and it is not usable on semantically opaque CKKS ciphertext vectors.
    """
    if not math.isfinite(cap) or cap <= 0:
        raise ValueError("cap must be positive and finite")
    data = _validate(updates)
    # Normalize each row before computing Euclidean norm to avoid squaring
    # arbitrary large attacker-controlled finite floats.
    maxima = np.max(np.abs(data), axis=1, keepdims=True)
    safe_max = np.where(maxima == 0, 1., maxima)
    units = data / safe_max
    unit_norms = np.linalg.norm(units, axis=1, keepdims=True)
    norms = maxima * unit_norms
    # When the mathematical norm overflows float64, unit directions are still
    # known. Divide the unit row by its norm, then scale to cap.
    protected = np.empty_like(data)
    clipped = (norms > cap) | ~np.isfinite(norms)
    np.copyto(protected, data)
    idx = clipped[:, 0]
    if np.any(idx):
        protected[idx] = cap * (units[idx] / unit_norms[idx])
    # Tolerate only round-off, not arbitrary cap violations.
    if np.any(np.linalg.norm(protected, axis=1) > cap*(1+1e-12)):
        raise AssertionError("server clipping failed to enforce update norm cap")
    return protected


def geometric_median(
    updates: np.ndarray, *, max_iterations: int = 80,
    tolerance: float = 1e-9, smoothing: float = 1e-7,
) -> np.ndarray:
    """RFA-style, unweighted smoothed Weiszfeld geometric median approximation.

    The returned vector is a convex combination of the received points.
    It is a known robust-estimation baseline, not a new contribution.
    """
    data = _validate(updates)
    if max_iterations < 1:
        raise ValueError("max_iterations must be positive")
    if (not math.isfinite(tolerance) or tolerance <= 0 or
            not math.isfinite(smoothing) or smoothing <= 0):
        raise ValueError("smoothing and tolerance must be finite and positive")
    current = data.mean(axis=0)
    for _ in range(max_iterations):
        # Center first and normalize distances for numerical robustness.
        dist = np.linalg.norm(data - current, axis=1)
        if not np.isfinite(dist).all():
            raise ValueError("distances overflowed; apply server clipping first")
        inv_dist = 1.0 / np.maximum(dist, smoothing)
        new = np.average(data, axis=0, weights=inv_dist)
        if np.linalg.norm(new - current) <= tolerance*(1+np.linalg.norm(current)):
            return new
        current = new
    return current


def fltrust_aggregate(updates: np.ndarray, trusted_update: np.ndarray) -> np.ndarray:
    """FLTrust baseline: ReLU cosine weighting and trusted-root norm matching.

    Cao et al., NDSS 2021. NOT a new algorithm. Assumes a genuinely clean,
    server-owned root dataset and plaintext/noisy client updates. Does not
    verify client-side DP or operate on opaque CKKS vectors.
    """
    vectors = _validate(updates)
    root = np.asarray(trusted_update, dtype=np.float64)
    if root.shape != (vectors.shape[1],) or not np.isfinite(root).all():
        raise ValueError("invalid server trusted-root update")
    root_norm = np.linalg.norm(root)
    if root_norm <= 0 or not np.isfinite(root_norm):
        raise ValueError("trusted root update has zero or nonfinite norm")
    # Avoid cosine overflow even for attacker-controlled finite magnitudes.
    root_unit = root / root_norm
    maxima = np.max(np.abs(vectors), axis=1, keepdims=True)
    safe = np.where(maxima == 0, 1.0, maxima)
    scaled = vectors / safe
    norms = np.linalg.norm(scaled, axis=1)
    valid = (maxima[:, 0] > 0) & (norms > 0) & np.isfinite(norms)
    unit = np.zeros_like(vectors)
    unit[valid] = scaled[valid] / norms[valid, None]
    trust = np.maximum(0.0, unit @ root_unit)
    total = trust.sum()
    if not np.isfinite(total):
        raise ValueError("invalid FLTrust weights")
    if total <= 1e-15:
        # Fail closed: no client direction agrees with the clean root.
        return np.zeros_like(root)
    return root_norm * ((unit.T @ trust) / total)


def aggregate_extended(
    updates: np.ndarray, method: str, *, cap: float,
    multi_krum_callback=None, trusted_update=None,
) -> np.ndarray:
    """Select an explicit transparent baseline. No hidden fallback."""
    if method not in EXTENSION_AGGREGATORS + TRUSTED_ROOT_AGGREGATORS:
        raise ValueError("unknown robust extension method")
    vectors = _validate(updates)
    if method == "fltrust":
        if trusted_update is None:
            raise ValueError("FLTrust requires a disjoint server-owned trusted-root update")
        return fltrust_aggregate(vectors, trusted_update)
    if method.startswith("server_clipped_"):
        vectors = project_l2(vectors, cap)
    if method in ("rfa", "server_clipped_rfa"):
        return geometric_median(vectors)
    if method == "server_clipped_mean":
        return vectors.mean(axis=0)
    if method == "server_clipped_multi_krum":
        if multi_krum_callback is None:
            raise ValueError("Multi-Krum callback must be explicitly provided")
        return multi_krum_callback(vectors)
    raise AssertionError("unreachable aggregator state")
