"""Small importable model factories used by the simulation runner."""

from __future__ import annotations

import torch
from torch import nn


class MLPClassifier(nn.Module):
    def __init__(
        self,
        input_shape: tuple[int, ...] | list[int],
        num_classes: int,
        hidden_dim: int = 128,
    ) -> None:
        super().__init__()
        feature_count = 1
        for dimension in input_shape:
            feature_count *= int(dimension)
        self.network = nn.Sequential(
            nn.Flatten(),
            nn.Linear(feature_count, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.network(inputs)


class SmallConvClassifier(nn.Module):
    def __init__(
        self,
        input_channels: int,
        num_classes: int,
        image_size: int = 32,
    ) -> None:
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(input_channels, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
        )
        spatial = image_size // 4
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * spatial * spatial, 128),
            nn.ReLU(),
            nn.Linear(128, num_classes),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.features(inputs))


def mlp_classifier(
    *,
    input_shape: tuple[int, ...] | list[int],
    num_classes: int,
    hidden_dim: int = 128,
) -> nn.Module:
    return MLPClassifier(
        input_shape=input_shape,
        num_classes=num_classes,
        hidden_dim=hidden_dim,
    )


def small_conv_classifier(
    *,
    input_channels: int,
    num_classes: int,
    image_size: int = 32,
) -> nn.Module:
    return SmallConvClassifier(
        input_channels=input_channels,
        num_classes=num_classes,
        image_size=image_size,
    )
