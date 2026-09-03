"""Deterministic IID and Dirichlet non-IID dataset partitioning."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np
import torch
from torch.utils.data import Dataset


@dataclass(frozen=True, slots=True)
class PartitionStats:
    """Summary statistics for one client partition."""

    client_id: int
    sample_count: int
    class_counts: dict[int, int]


def extract_targets(dataset_or_targets: Dataset | Sequence[int] | np.ndarray | torch.Tensor) -> np.ndarray:
    """Return dataset labels as a contiguous one-dimensional ``int64`` array.

    Datasets exposing ``targets`` or ``labels`` are supported directly. A plain
    sequence, NumPy array, or tensor can also be supplied.
    """

    source = dataset_or_targets
    if isinstance(source, Dataset):
        if hasattr(source, "targets"):
            source = getattr(source, "targets")
        elif hasattr(source, "labels"):
            source = getattr(source, "labels")
        else:
            labels: list[int] = []
            for index in range(len(source)):
                item = source[index]
                if not isinstance(item, (tuple, list)) or len(item) < 2:
                    raise TypeError(
                        "dataset must expose targets/labels or return (features, label) samples"
                    )
                label = item[1]
                if isinstance(label, torch.Tensor):
                    if label.numel() != 1:
                        raise ValueError("dataset labels must be scalar values")
                    label = label.item()
                labels.append(int(label))
            source = labels

    if isinstance(source, torch.Tensor):
        targets = source.detach().cpu().numpy()
    else:
        targets = np.asarray(source)

    if targets.ndim != 1:
        targets = targets.reshape(-1)
    if targets.size == 0:
        raise ValueError("cannot partition an empty label set")
    if not np.issubdtype(targets.dtype, np.integer):
        if not np.all(np.isfinite(targets)) or not np.all(targets == np.floor(targets)):
            raise TypeError("class labels must be integer-valued")
    return np.ascontiguousarray(targets, dtype=np.int64)


def iid_partition(
    dataset_or_targets: Dataset | Sequence[int] | np.ndarray | torch.Tensor,
    num_clients: int,
    *,
    seed: int = 42,
) -> dict[int, np.ndarray]:
    """Split sample indices uniformly at random across clients."""

    targets = extract_targets(dataset_or_targets)
    _validate_client_count(len(targets), num_clients)

    rng = np.random.default_rng(seed)
    shuffled = rng.permutation(len(targets))
    splits = np.array_split(shuffled, num_clients)
    return {
        client_id: np.sort(np.ascontiguousarray(indices, dtype=np.int64))
        for client_id, indices in enumerate(splits)
    }


def dirichlet_partition(
    dataset_or_targets: Dataset | Sequence[int] | np.ndarray | torch.Tensor,
    num_clients: int,
    *,
    alpha: float = 0.5,
    seed: int = 42,
    min_samples_per_client: int = 1,
    max_retries: int = 1024,
) -> dict[int, np.ndarray]:
    """Partition indices by class using a symmetric Dirichlet distribution.

    Smaller ``alpha`` values produce stronger class skew. Every source sample is
    assigned exactly once. Sampling is retried until each client receives at
    least ``min_samples_per_client`` samples.
    """

    targets = extract_targets(dataset_or_targets)
    _validate_client_count(len(targets), num_clients)

    if not np.isfinite(alpha) or alpha <= 0:
        raise ValueError("alpha must be a finite value greater than zero")
    if min_samples_per_client < 0:
        raise ValueError("min_samples_per_client cannot be negative")
    if min_samples_per_client * num_clients > len(targets):
        raise ValueError("minimum sample requirement exceeds dataset size")
    if max_retries <= 0:
        raise ValueError("max_retries must be positive")

    classes = np.unique(targets)
    master_rng = np.random.default_rng(seed)

    for _ in range(max_retries):
        client_indices: list[list[np.ndarray]] = [[] for _ in range(num_clients)]
        client_sizes = np.zeros(num_clients, dtype=np.int64)

        # A fresh child seed makes retries deterministic while avoiding the same
        # failed draw on each attempt.
        attempt_rng = np.random.default_rng(master_rng.integers(0, 2**63 - 1))

        for class_id in classes:
            class_indices = np.flatnonzero(targets == class_id)
            attempt_rng.shuffle(class_indices)

            proportions = attempt_rng.dirichlet(
                np.full(num_clients, alpha, dtype=np.float64)
            )

            # Mild balancing prevents one already-large client from consuming
            # nearly all samples while retaining the requested Dirichlet skew.
            average_target = len(targets) / num_clients
            under_target = client_sizes < average_target
            if np.any(under_target):
                proportions *= under_target
                total = proportions.sum()
                if total > 0:
                    proportions /= total
                else:
                    proportions = np.full(num_clients, 1.0 / num_clients)

            counts = attempt_rng.multinomial(len(class_indices), proportions)
            offsets = np.concatenate(([0], np.cumsum(counts)))
            for client_id in range(num_clients):
                chunk = class_indices[offsets[client_id] : offsets[client_id + 1]]
                if chunk.size:
                    client_indices[client_id].append(chunk)
                    client_sizes[client_id] += chunk.size

        if np.min(client_sizes) < min_samples_per_client:
            continue

        partitions: dict[int, np.ndarray] = {}
        for client_id, chunks in enumerate(client_indices):
            if chunks:
                merged = np.concatenate(chunks).astype(np.int64, copy=False)
                attempt_rng.shuffle(merged)
            else:
                merged = np.empty(0, dtype=np.int64)
            partitions[client_id] = np.ascontiguousarray(merged)

        _validate_partition_coverage(partitions, len(targets))
        return partitions

    raise RuntimeError(
        "could not satisfy Dirichlet minimum sample constraint; "
        "increase alpha, reduce clients, or lower min_samples_per_client"
    )


def partition_dataset(
    dataset_or_targets: Dataset | Sequence[int] | np.ndarray | torch.Tensor,
    num_clients: int,
    *,
    strategy: str = "dirichlet",
    alpha: float = 0.5,
    seed: int = 42,
    min_samples_per_client: int = 1,
) -> dict[int, np.ndarray]:
    """Dispatch to IID or Dirichlet partitioning."""

    normalized = strategy.strip().lower().replace("-", "_")
    if normalized == "iid":
        return iid_partition(dataset_or_targets, num_clients, seed=seed)
    if normalized in {"dirichlet", "non_iid", "noniid"}:
        return dirichlet_partition(
            dataset_or_targets,
            num_clients,
            alpha=alpha,
            seed=seed,
            min_samples_per_client=min_samples_per_client,
        )
    raise ValueError(f"unsupported partition strategy: {strategy!r}")


def partition_stats(
    targets: Sequence[int] | np.ndarray | torch.Tensor,
    partitions: Mapping[int, Sequence[int] | np.ndarray],
) -> list[PartitionStats]:
    """Return per-client class histograms for diagnostics."""

    labels = extract_targets(targets)
    stats: list[PartitionStats] = []
    for client_id, indices in sorted(partitions.items()):
        index_array = np.asarray(indices, dtype=np.int64)
        selected = labels[index_array]
        class_ids, counts = np.unique(selected, return_counts=True)
        stats.append(
            PartitionStats(
                client_id=int(client_id),
                sample_count=int(index_array.size),
                class_counts={
                    int(class_id): int(count)
                    for class_id, count in zip(class_ids, counts, strict=True)
                },
            )
        )
    return stats


def _validate_client_count(sample_count: int, num_clients: int) -> None:
    if num_clients <= 0:
        raise ValueError("num_clients must be positive")
    if num_clients > sample_count:
        raise ValueError("num_clients cannot exceed the number of samples")


def _validate_partition_coverage(
    partitions: Mapping[int, np.ndarray],
    sample_count: int,
) -> None:
    merged = np.concatenate(list(partitions.values()))
    if merged.size != sample_count:
        raise RuntimeError("partitioning did not assign every sample exactly once")
    if np.unique(merged).size != sample_count:
        raise RuntimeError("partitioning assigned at least one sample more than once")
    if merged.min(initial=0) < 0 or merged.max(initial=-1) >= sample_count:
        raise RuntimeError("partition contains an out-of-range sample index")
