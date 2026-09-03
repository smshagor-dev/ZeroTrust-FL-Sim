from __future__ import annotations

import gc
import time

import numpy as np
import psutil
import torch
from torch.utils.data import TensorDataset

from zerotrust_fl.attacks.poisoning import (
    AttackConfig,
    PoisoningAttack,
    adaptive_poison,
    gaussian_noise,
    sign_flip,
)
from zerotrust_fl.data.partitioner import (
    dirichlet_partition,
    iid_partition,
    partition_stats,
)
from zerotrust_fl.engine.coordinator import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    SimulationConfig,
)
from zerotrust_fl.engine.worker import ModelSpec, WorkerConfig, WorkerSpec


def _dataset(samples: int = 320) -> TensorDataset:
    generator = torch.Generator().manual_seed(7)
    features = torch.randn(samples, 4, generator=generator)
    labels = (features[:, 0] + 0.4 * features[:, 1] > 0).long()
    return TensorDataset(features, labels)


def test_iid_partition_is_complete_disjoint_and_balanced() -> None:
    dataset = _dataset(120)
    partitions = iid_partition(dataset, 6, seed=10)
    merged = np.concatenate(list(partitions.values()))
    assert merged.size == len(dataset)
    assert np.unique(merged).size == len(dataset)
    sizes = [len(indices) for indices in partitions.values()]
    assert max(sizes) - min(sizes) <= 1


def test_dirichlet_partition_produces_non_iid_class_skew() -> None:
    labels = np.repeat(np.arange(4, dtype=np.int64), 200)
    partitions = dirichlet_partition(
        labels,
        8,
        alpha=0.15,
        seed=123,
        min_samples_per_client=20,
    )
    stats = partition_stats(labels, partitions)
    class_zero_ratios = [
        stat.class_counts.get(0, 0) / stat.sample_count
        for stat in stats
    ]
    merged = np.concatenate(list(partitions.values()))
    assert merged.size == labels.size
    assert np.unique(merged).size == labels.size
    assert min(stat.sample_count for stat in stats) >= 20
    assert max(class_zero_ratios) - min(class_zero_ratios) > 0.20


def test_attack_suite_modifies_labels_and_updates_deterministically() -> None:
    labels = torch.tensor([0, 1, 0, 2, 0, 1])
    label_attack = PoisoningAttack(
        AttackConfig(
            kind="label_flip",
            source_class=0,
            target_class=2,
            probability=1.0,
            seed=9,
        )
    )
    flipped = label_attack.transform_labels(labels, round_id=1, batch_id=0)
    assert torch.equal(flipped, torch.tensor([2, 1, 2, 2, 2, 1]))
    assert torch.equal(labels, torch.tensor([0, 1, 0, 2, 0, 1]))

    update = torch.tensor([1.0, -2.0, 3.0, -4.0])
    assert torch.equal(sign_flip(update, gamma=3.0), -3.0 * update)

    adaptive = adaptive_poison(update, scale=8.0, max_norm_ratio=1.0)
    assert torch.allclose(adaptive, -update)
    assert torch.allclose(adaptive.norm(), update.norm())

    noise_a = gaussian_noise(update, mean=0.0, std=2.0, seed=77)
    noise_b = gaussian_noise(update, mean=0.0, std=2.0, seed=77)
    assert torch.equal(noise_a, noise_b)
    assert not torch.equal(noise_a, update)


def test_async_multiprocess_training_runs_multiple_rounds_without_deadlock() -> None:
    dataset = _dataset(320)
    partitions = iid_partition(dataset, 4, seed=21)
    workers: list[WorkerSpec] = []
    for client_id in range(4):
        malicious = client_id == 0
        workers.append(
            WorkerSpec(
                config=WorkerConfig(
                    node_id=f"test-worker-{client_id}",
                    batch_size=16,
                    local_epochs_min=1,
                    local_epochs_max=2,
                    learning_rate=0.05,
                    learning_rate_jitter=0.05,
                    optimizer="sgd",
                    compute_delay_seconds=(0.0, 0.02 * client_id),
                    network_delay_seconds=(0.0, 0.01),
                    torch_num_threads=1,
                    seed=100 + client_id,
                    malicious=malicious,
                    attack=AttackConfig(
                        kind="sign_flip" if malicious else "none",
                        sign_scale=1.0,
                        seed=100 + client_id,
                    ),
                ),
                sample_indices=tuple(int(index) for index in partitions[client_id]),
            )
        )

    coordinator = AsyncFederatedCoordinator(
        dataset=dataset,
        model_spec=ModelSpec(
            factory_path="zerotrust_fl.engine.models:mlp_classifier",
            kwargs={"input_shape": [4], "num_classes": 2, "hidden_dim": 8},
        ),
        workers=workers,
        simulation=SimulationConfig(
            rounds=3,
            clients_per_round=4,
            min_results=4,
            round_timeout_seconds=20.0,
            start_method="spawn",
            seed=22,
        ),
        aggregation=AggregationConfig(method="mean", backend="torch"),
    )

    process = psutil.Process()
    before_rss = process.memory_info().rss
    started = time.perf_counter()
    summary = coordinator.run()
    elapsed = time.perf_counter() - started
    gc.collect()
    after_rss = process.memory_info().rss

    assert len(summary.rounds) == 3
    assert all(len(metrics.completed_clients) == 4 for metrics in summary.rounds)
    assert all(not metrics.failed_clients for metrics in summary.rounds)
    assert all(not metrics.straggler_clients for metrics in summary.rounds)
    assert all(metrics.malicious_results == 1 for metrics in summary.rounds)
    assert coordinator.processes_alive == 0
    assert elapsed < 20.0
    assert after_rss - before_rss < 256 * 1024 * 1024
