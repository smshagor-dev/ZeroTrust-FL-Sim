"""Client-side model-update clipping, Gaussian local DP, and RDP accounting."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

import torch

Adjacency = Literal["add_remove", "replace"]

_DEFAULT_ORDERS = (
    1.25,
    1.5,
    1.75,
    2.0,
    3.0,
    4.0,
    5.0,
    8.0,
    10.0,
    16.0,
    32.0,
    64.0,
)


@dataclass(frozen=True, slots=True)
class LocalDPConfig:
    """Configuration for release-level Local Differential Privacy.

    The model update is clipped to ``clip_norm`` before Gaussian noise is
    applied. Under replacement adjacency, the L2 sensitivity of a vector
    clipped to a radius C is bounded by 2C. Under add/remove adjacency the
    configured sensitivity is C.
    """

    enabled: bool = False
    clip_norm: float = 1.0
    noise_multiplier: float = 1.0
    delta: float = 1e-5
    adjacency: Adjacency = "replace"
    orders: tuple[float, ...] = _DEFAULT_ORDERS

    def __post_init__(self) -> None:
        if self.clip_norm <= 0:
            raise ValueError("clip_norm must be positive")
        if self.noise_multiplier <= 0:
            raise ValueError("noise_multiplier must be positive")
        if not 0.0 < self.delta < 1.0:
            raise ValueError("delta must be in (0, 1)")
        if self.adjacency not in {"add_remove", "replace"}:
            raise ValueError("adjacency must be 'add_remove' or 'replace'")
        if not self.orders or any(alpha <= 1.0 for alpha in self.orders):
            raise ValueError("every RDP order must be > 1")

    @property
    def sensitivity(self) -> float:
        return self.clip_norm * (2.0 if self.adjacency == "replace" else 1.0)

    @property
    def noise_std(self) -> float:
        return self.noise_multiplier * self.sensitivity


@dataclass(frozen=True, slots=True)
class ProtectedUpdate:
    update: torch.Tensor
    original_norm: float
    clipped_norm: float
    clipping_factor: float
    noise_std: float
    epsilon_per_release: float
    optimal_order: float


class RDPAccountant:
    """RDP accountant for the full-participation Gaussian mechanism (q=1)."""

    def __init__(self, config: LocalDPConfig, *, releases: int = 0) -> None:
        if releases < 0:
            raise ValueError("releases cannot be negative")
        self.config = config
        self.releases = int(releases)

    def step(self, count: int = 1) -> None:
        if count <= 0:
            raise ValueError("count must be positive")
        self.releases += int(count)

    def rdp(self, alpha: float) -> float:
        if alpha <= 1.0:
            raise ValueError("alpha must be > 1")
        if not self.config.enabled or self.releases == 0:
            return 0.0
        sigma = self.config.noise_multiplier
        return self.releases * alpha / (2.0 * sigma * sigma)

    def epsilon(self, delta: float | None = None) -> tuple[float, float]:
        """Convert composed RDP to an (epsilon, delta)-DP upper bound."""

        target_delta = self.config.delta if delta is None else float(delta)
        if not 0.0 < target_delta < 1.0:
            raise ValueError("delta must be in (0, 1)")
        if not self.config.enabled or self.releases == 0:
            return 0.0, self.config.orders[0]

        best_epsilon = math.inf
        best_order = self.config.orders[0]
        for alpha in self.config.orders:
            epsilon = self.rdp(alpha) + math.log(1.0 / target_delta) / (alpha - 1.0)
            if epsilon < best_epsilon:
                best_epsilon = epsilon
                best_order = alpha
        return float(best_epsilon), float(best_order)


def protect_model_update(
    update: torch.Tensor,
    config: LocalDPConfig,
    *,
    seed: int,
) -> ProtectedUpdate:
    """Clip a model update and add deterministic-seed Gaussian noise.

    The seed exists to make simulator experiments reproducible. Production
    deployments must replace deterministic experiment seeds with a
    cryptographically appropriate random source.
    """

    if update.numel() == 0:
        raise ValueError("model update must not be empty")
    if not torch.isfinite(update).all():
        raise ValueError("model update contains non-finite values")

    working = update.detach().to(device="cpu", dtype=torch.float32).contiguous()
    original_norm = float(torch.linalg.vector_norm(working))

    if not config.enabled:
        return ProtectedUpdate(
            update=working,
            original_norm=original_norm,
            clipped_norm=original_norm,
            clipping_factor=1.0,
            noise_std=0.0,
            epsilon_per_release=0.0,
            optimal_order=config.orders[0],
        )

    clipping_factor = min(1.0, config.clip_norm / max(original_norm, 1e-12))
    clipped = working * clipping_factor
    clipped_norm = float(torch.linalg.vector_norm(clipped))

    generator = torch.Generator(device="cpu")
    generator.manual_seed(int(seed))
    noise = torch.randn(
        clipped.shape,
        generator=generator,
        dtype=clipped.dtype,
        device="cpu",
    ) * config.noise_std
    protected = clipped + noise

    accountant = RDPAccountant(config, releases=1)
    epsilon, optimal_order = accountant.epsilon()
    return ProtectedUpdate(
        update=protected.contiguous(),
        original_norm=original_norm,
        clipped_norm=clipped_norm,
        clipping_factor=float(clipping_factor),
        noise_std=float(config.noise_std),
        epsilon_per_release=epsilon,
        optimal_order=optimal_order,
    )
