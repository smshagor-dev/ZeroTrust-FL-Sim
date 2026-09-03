"""Adversarial label and model-update poisoning primitives."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal

import torch

AttackKind = Literal[
    "none",
    "label_flip",
    "gaussian",
    "sign_flip",
    "adaptive",
    "collusion",
]


@dataclass(frozen=True, slots=True)
class AttackConfig:
    """Configuration for a simulated malicious worker."""

    kind: AttackKind = "none"
    probability: float = 1.0
    source_class: int | None = None
    target_class: int | None = None
    label_mapping: dict[int, int] = field(default_factory=dict)
    noise_mean: float = 0.0
    noise_std: float = 5.0
    sign_scale: float = 1.0
    adaptive_scale: float = 4.0
    adaptive_max_norm_ratio: float = 1.0
    collusion_scale: float = 8.0
    collusion_seed: int = 20_271
    seed: int = 42

    def __post_init__(self) -> None:
        if self.kind not in {
            "none",
            "label_flip",
            "gaussian",
            "sign_flip",
            "adaptive",
            "collusion",
        }:
            raise ValueError(f"unsupported attack kind: {self.kind!r}")
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError("attack probability must be in [0, 1]")
        if self.noise_std < 0:
            raise ValueError("noise_std cannot be negative")
        if self.sign_scale < 0:
            raise ValueError("sign_scale cannot be negative")
        if self.adaptive_scale < 0:
            raise ValueError("adaptive_scale cannot be negative")
        if self.adaptive_max_norm_ratio <= 0:
            raise ValueError("adaptive_max_norm_ratio must be positive")
        if self.collusion_scale < 0:
            raise ValueError("collusion_scale cannot be negative")
        if self.source_class is not None and self.target_class is None and not self.label_mapping:
            raise ValueError("target_class is required when source_class is configured")


class PoisoningAttack:
    """Apply deterministic label- or update-level attacks for one worker."""

    def __init__(self, config: AttackConfig) -> None:
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.kind != "none"

    @property
    def attacks_labels(self) -> bool:
        return self.config.kind == "label_flip"

    @property
    def attacks_updates(self) -> bool:
        return self.config.kind in {"gaussian", "sign_flip", "adaptive", "collusion"}

    def transform_labels(
        self,
        labels: torch.Tensor,
        *,
        round_id: int = 0,
        batch_id: int = 0,
    ) -> torch.Tensor:
        """Return labels after a configured targeted or mapped label flip."""

        if self.config.kind != "label_flip" or self.config.probability == 0:
            return labels

        if not isinstance(labels, torch.Tensor):
            raise TypeError("labels must be a torch.Tensor")

        output = labels.clone()
        generator = _generator_for(
            labels.device,
            self.config.seed,
            round_id,
            batch_id,
            stream=11,
        )
        selected = torch.rand(
            labels.shape,
            generator=generator,
            device=labels.device,
        ) < self.config.probability

        if self.config.label_mapping:
            original = labels.clone()
            for source, target in self.config.label_mapping.items():
                mask = selected & original.eq(int(source))
                output[mask] = int(target)
            return output

        if self.config.source_class is not None:
            mask = selected & labels.eq(int(self.config.source_class))
            output[mask] = int(self.config.target_class)
            return output

        if self.config.target_class is not None:
            output[selected] = int(self.config.target_class)
            return output

        unique = torch.unique(labels)
        if unique.numel() != 2:
            raise ValueError(
                "multiclass label flipping requires label_mapping or source_class/target_class"
            )
        first, second = unique[0], unique[1]
        original = labels.clone()
        output[selected & original.eq(first)] = second
        output[selected & original.eq(second)] = first
        return output

    def transform_update(
        self,
        update: torch.Tensor,
        *,
        round_id: int = 0,
    ) -> torch.Tensor:
        """Return a poisoned model delta without mutating the input."""

        if not isinstance(update, torch.Tensor):
            raise TypeError("update must be a torch.Tensor")
        if not update.is_floating_point():
            raise TypeError("model updates must use a floating-point dtype")

        kind = self.config.kind
        if kind in {"none", "label_flip"} or self.config.probability == 0:
            return update.clone()

        if self.config.probability < 1.0:
            generator = _generator_for(
                update.device,
                self.config.seed,
                round_id,
                0,
                stream=23,
            )
            if torch.rand((), generator=generator, device=update.device).item() >= self.config.probability:
                return update.clone()

        if kind == "gaussian":
            generator = _generator_for(
                update.device,
                self.config.seed,
                round_id,
                0,
                stream=31,
            )
            noise = torch.normal(
                mean=self.config.noise_mean,
                std=self.config.noise_std,
                size=tuple(update.shape),
                generator=generator,
                device=update.device,
                dtype=update.dtype,
            )
            return update + noise

        if kind == "sign_flip":
            return update.mul(-self.config.sign_scale)

        if kind == "adaptive":
            return _adaptive_poison(
                update,
                scale=self.config.adaptive_scale,
                max_norm_ratio=self.config.adaptive_max_norm_ratio,
            )

        if kind == "collusion":
            return _coordinated_collusion(
                update,
                round_id=round_id,
                scale=self.config.collusion_scale,
                shared_seed=self.config.collusion_seed,
            )

        raise RuntimeError(f"unhandled attack kind: {kind!r}")


def label_flip(
    labels: torch.Tensor,
    *,
    source_class: int,
    target_class: int,
    probability: float = 1.0,
    seed: int = 42,
) -> torch.Tensor:
    """Convenience wrapper for a targeted label-flipping attack."""

    return PoisoningAttack(
        AttackConfig(
            kind="label_flip",
            source_class=source_class,
            target_class=target_class,
            probability=probability,
            seed=seed,
        )
    ).transform_labels(labels)


def gaussian_noise(
    update: torch.Tensor,
    *,
    mean: float = 0.0,
    std: float = 5.0,
    seed: int = 42,
) -> torch.Tensor:
    """Convenience wrapper for additive Gaussian model poisoning."""

    return PoisoningAttack(
        AttackConfig(
            kind="gaussian",
            noise_mean=mean,
            noise_std=std,
            seed=seed,
        )
    ).transform_update(update)


def sign_flip(update: torch.Tensor, *, gamma: float = 1.0) -> torch.Tensor:
    """Invert and scale a model update."""

    return PoisoningAttack(
        AttackConfig(kind="sign_flip", sign_scale=gamma)
    ).transform_update(update)


def adaptive_poison(
    update: torch.Tensor,
    *,
    scale: float = 4.0,
    max_norm_ratio: float = 1.0,
) -> torch.Tensor:
    """Push opposite to the honest update while respecting a norm envelope."""

    return _adaptive_poison(update, scale=scale, max_norm_ratio=max_norm_ratio)


def coordinated_collusion(
    update: torch.Tensor,
    *,
    round_id: int = 0,
    scale: float = 8.0,
    shared_seed: int = 20_271,
) -> torch.Tensor:
    """Create a round-synchronized malicious direction shared by colluding clients."""

    return _coordinated_collusion(
        update,
        round_id=round_id,
        scale=scale,
        shared_seed=shared_seed,
    )


def _adaptive_poison(
    update: torch.Tensor,
    *,
    scale: float,
    max_norm_ratio: float,
) -> torch.Tensor:
    original_norm = torch.linalg.vector_norm(update)
    if not torch.isfinite(original_norm):
        raise ValueError("update norm must be finite")
    if original_norm.item() == 0.0:
        return update.clone()

    candidate = update.mul(-scale)
    candidate_norm = torch.linalg.vector_norm(candidate)
    max_norm = original_norm * max_norm_ratio
    if candidate_norm > max_norm:
        candidate = candidate * (max_norm / candidate_norm)
    return candidate


def _coordinated_collusion(
    update: torch.Tensor,
    *,
    round_id: int,
    scale: float,
    shared_seed: int,
) -> torch.Tensor:
    original_norm = torch.linalg.vector_norm(update)
    if not torch.isfinite(original_norm):
        raise ValueError("update norm must be finite")
    if original_norm.item() == 0.0 or scale == 0.0:
        return torch.zeros_like(update)

    generator = _generator_for(
        update.device,
        shared_seed,
        round_id,
        0,
        stream=47,
    )
    signs = torch.randint(
        0,
        2,
        tuple(update.shape),
        generator=generator,
        device=update.device,
        dtype=torch.int64,
    ).to(dtype=update.dtype)
    signs = signs.mul_(2.0).sub_(1.0)
    direction = signs / math.sqrt(float(update.numel()))
    return direction.mul(original_norm * scale)


def _generator_for(
    device: torch.device,
    seed: int,
    round_id: int,
    batch_id: int,
    *,
    stream: int,
) -> torch.Generator:
    generator_device = device if device.type == "cuda" else torch.device("cpu")
    generator = torch.Generator(device=generator_device)
    mixed = (
        int(seed)
        + 1_000_003 * int(round_id)
        + 9_176 * int(batch_id)
        + 65_537 * int(stream)
    ) % (2**63 - 1)
    generator.manual_seed(mixed)
    return generator
