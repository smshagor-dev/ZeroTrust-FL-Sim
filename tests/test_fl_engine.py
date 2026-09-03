from __future__ import annotations

import math

import numpy as np
import pytest
import torch
from torch.utils.data import TensorDataset

from zerotrust_fl.attacks import (
    AttackConfig,
    PoisoningAttack,
    adaptive_poison,
    gaussian_noise,
    label_flip,
    sign_flip,
)
from zerotrust_fl.client.grpc_worker import deserialize_update, serialize_update
from zerotrust_fl.data import dirichlet_partition, iid_partition
from zerotrust_fl.engine import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    ModelSpec,
    SimulationConfig,
    WorkerConfig,
    WorkerSpec,
)


def test_iid_partition_has_exact_non_overlapping_coverage() -> None:
    labels = np.repeat(np.arange(4), 25)
    partitions = iid_partition(labels, 5, seed=7)

    merged = np.concatenate(list(partitions.values()))
    assert merged.size == labels.size
    assert np.unique(merged).size == labels.size
    assert sorted(len(indices) for indices in partitions.values()) == [20] * 5


def test_dirichlet_partition_creates_class_skew_and_exact_coverage() -> None:
    labels = np.repeat(np.arange(5), 200)
    partitions = dirichlet_partition(
        labels,
        10,
        alpha=0.08,
        seed=19,
        min_samples_per_client=10,
    )

    merged = np.concatenate(list(partitions.values()))
    assert merged.size == labels.size
    assert np.unique(merged).size == labels.size

    dominant_fractions = []
    for indices in partitions.values():
        client_labels = labels[indices]
        _, counts = np.unique(client_labels, return_counts=True)
        dominant_fractions.append(float(counts.max() / counts.sum()))

    assert float(np.mean(dominant_fractions)) > 0.45


def test_label_flip_changes_only_targeted_class() -> None:
    labels = torch.tensor([0, 1, 0, 2, 0, 3])
    poisoned = label_flip(
        labels,
        source_class=0,
        target_class=4,
        probability=1.0,
        seed=3,
    )
    assert poisoned.tolist() == [4, 1, 4, 2, 4, 3]
    assert labels.tolist() == [0, 1, 0, 2, 0, 3]


def test_weight_poisoning_operators_are_deterministic_and_bounded() -> None:
    update = torch.tensor([1.0, -2.0, 3.0, -4.0])

    assert torch.equal(sign_flip(update, gamma=2.5), update * -2.5)

    noisy_a = gaussian_noise(update, std=1.5, seed=11)
    noisy_b = gaussian_noise(update, std=1.5, seed=11)
    assert torch.equal(noisy_a, noisy_b)
    assert not torch.equal(noisy_a, update)

    adaptive = adaptive_poison(
        update,
        scale=10.0,
        max_norm_ratio=0.75,
    )
    assert torch.dot(adaptive, update) < 0
    assert torch.linalg.vector_norm(adaptive) <= (
        torch.linalg.vector_norm(update) * 0.75 + 1e-6
    )


def test_grpc_update_serialization_is_non_pickle_float32() -> None:
    update = torch.linspace(-1.0, 1.0, steps=32, dtype=torch.float64)
    payload = serialize_update(update)
    restored = deserialize_update(payload)

    assert restored.dtype == np.float32
    np.testing.assert_allclose(restored, update.numpy(), rtol=1e-6, atol=1e-6)


def test_attack_probability_can_disable_update_attack() -> None:
    update = torch.randn(16)
    attack = PoisoningAttack(
        AttackConfig(
            kind="sign_flip",
            sign_scale=4.0,
            probability=0.0,
            seed=5,
        )
    )
    assert torch.equal(attack.transform_update(update, round_id=1), update)


def test_async_multi_process_training_completes_without_deadlock() -> None:
    generator = torch.Generator().manual_seed(123)
    features = torch.randn(160, 4, generator=generator)
    true_weights = torch.tensor(
        [
            [1.2, -0.4, 0.1],
            [-0.5, 1.1, 0.2],
            [0.3, -0.2, 0.9],
            [0.8, 0.4, -0.6],
        ]
    )
    labels = (features @ true_weights).argmax(dim=1)
    dataset = TensorDataset(features, labels)

    partitions = iid_partition(labels, 4, seed=29)
    workers: list[WorkerSpec] = []
    for client_id in range(4):
        malicious = client_id == 3
        workers.append(
            WorkerSpec(
                config=WorkerConfig(
                    node_id=f"test-worker-{client_id}",
                    batch_size=16,
                    local_epochs_min=1,
                    local_epochs_max=2,
                    learning_rate=0.05,
                    optimizer="sgd",
                    optimizer_kwargs={"momentum": 0.0},
                    compute_delay_seconds=(0.0, 0.01 * client_id),
                    network_delay_seconds=(0.0, 0.005 * client_id),
                    torch_num_threads=1,
                    seed=100 + client_id,
                    malicious=malicious,
                    attack=(
                        AttackConfig(
                            kind="sign_flip",
                            sign_scale=3.0,
                            seed=900 + client_id,
                        )
                        if malicious
                        else AttackConfig()
                    ),
                ),
                sample_indices=tuple(int(i) for i in partitions[client_id]),
            )
        )

    coordinator = AsyncFederatedCoordinator(
        dataset=dataset,
        evaluation_dataset=dataset,
        model_spec=ModelSpec(
            "zerotrust_fl.engine.models:mlp_classifier",
            {
                "input_shape": [4],
                "num_classes": 3,
                "hidden_dim": 12,
            },
        ),
        workers=workers,
        simulation=SimulationConfig(
            rounds=3,
            clients_per_round=4,
            min_results=4,
            round_timeout_seconds=20.0,
            start_method="spawn",
            seed=77,
            evaluation_batch_size=64,
        ),
        aggregation=AggregationConfig(
            method="median",
            backend="torch",
        ),
    )

    summary = coordinator.run()

    assert len(summary.rounds) == 3
    assert coordinator.processes_alive == 0
    assert all(len(round_metrics.completed_clients) == 4 for round_metrics in summary.rounds)
    assert all(not round_metrics.straggler_clients for round_metrics in summary.rounds)
    assert all(math.isfinite(round_metrics.mean_client_loss) for round_metrics in summary.rounds)
    assert all(
        round_metrics.evaluation_accuracy is not None
        and 0.0 <= round_metrics.evaluation_accuracy <= 1.0
        for round_metrics in summary.rounds
    )
    assert summary.attack_mitigation_success_rate is not None


def test_async_quorum_marks_slow_worker_as_straggler() -> None:
    generator = torch.Generator().manual_seed(321)
    features = torch.randn(96, 3, generator=generator)
    labels = (features[:, 0] + 0.4 * features[:, 1] > 0).long()
    dataset = TensorDataset(features, labels)
    partitions = iid_partition(labels, 4, seed=9)

    workers = []
    for client_id in range(4):
        delay = (0.9, 0.9) if client_id == 3 else (0.0, 0.0)
        workers.append(
            WorkerSpec(
                config=WorkerConfig(
                    node_id=f"quorum-worker-{client_id}",
                    batch_size=12,
                    local_epochs_min=1,
                    local_epochs_max=1,
                    learning_rate=0.05,
                    compute_delay_seconds=delay,
                    torch_num_threads=1,
                    seed=500 + client_id,
                ),
                sample_indices=tuple(int(i) for i in partitions[client_id]),
            )
        )

    coordinator = AsyncFederatedCoordinator(
        dataset=dataset,
        model_spec=ModelSpec(
            "zerotrust_fl.engine.models:mlp_classifier",
            {"input_shape": [3], "num_classes": 2, "hidden_dim": 8},
        ),
        workers=workers,
        simulation=SimulationConfig(
            rounds=1,
            clients_per_round=4,
            min_results=3,
            round_timeout_seconds=5.0,
            start_method="spawn",
            seed=13,
        ),
        aggregation=AggregationConfig(method="median", backend="torch"),
    )

    summary = coordinator.run()
    metrics = summary.rounds[0]
    assert len(metrics.completed_clients) == 3
    assert len(metrics.straggler_clients) == 1
    assert coordinator.processes_alive == 0


def test_invalid_krum_population_is_rejected_before_process_start() -> None:
    dataset = TensorDataset(
        torch.randn(9, 2),
        torch.tensor([0, 1, 0, 1, 0, 1, 0, 1, 0]),
    )
    workers = [
        WorkerSpec(
            config=WorkerConfig(node_id=f"w{i}"),
            sample_indices=tuple(range(i * 3, (i + 1) * 3)),
        )
        for i in range(3)
    ]

    with pytest.raises(ValueError, match="Krum requires"):
        AsyncFederatedCoordinator(
            dataset=dataset,
            model_spec=ModelSpec(
                "zerotrust_fl.engine.models:mlp_classifier",
                {"input_shape": [2], "num_classes": 2, "hidden_dim": 4},
            ),
            workers=workers,
            simulation=SimulationConfig(
                rounds=1,
                clients_per_round=3,
            ),
            aggregation=AggregationConfig(
                method="krum",
                backend="torch",
                f=1,
            ),
        )
