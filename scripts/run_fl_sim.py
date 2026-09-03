"""Run an asynchronous multi-process federated-learning attack simulation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from torchvision import datasets, transforms

from zerotrust_fl.attacks.poisoning import AttackConfig
from zerotrust_fl.data.partitioner import partition_dataset, partition_stats
from zerotrust_fl.engine.coordinator import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    SimulationConfig,
)
from zerotrust_fl.engine.worker import ModelSpec, WorkerConfig, WorkerSpec


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=["fashion-mnist", "cifar10"], default="fashion-mnist")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--clients", type=int, default=10)
    parser.add_argument("--clients-per-round", type=int, default=None)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--partition", choices=["iid", "dirichlet"], default="dirichlet")
    parser.add_argument("--alpha", type=float, default=0.3)
    parser.add_argument("--local-epochs-min", type=int, default=1)
    parser.add_argument("--local-epochs-max", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.02)
    parser.add_argument("--learning-rate-jitter", type=float, default=0.1)
    parser.add_argument("--optimizer", choices=["sgd", "adam"], default="sgd")
    parser.add_argument(
        "--aggregation",
        choices=["mean", "krum", "multi_krum", "trimmed_mean", "median"],
        default="median",
    )
    parser.add_argument("--aggregation-backend", choices=["auto", "native", "torch"], default="auto")
    parser.add_argument("--byzantine-f", type=int, default=None)
    parser.add_argument("--multi-krum-k", type=int, default=2)
    parser.add_argument("--trim-beta", type=float, default=0.2)
    parser.add_argument("--compromised-ratio", type=float, default=0.2)
    parser.add_argument(
        "--attack",
        choices=["label_flip", "gaussian", "sign_flip", "adaptive"],
        default="sign_flip",
    )
    parser.add_argument("--noise-std", type=float, default=10.0)
    parser.add_argument("--sign-scale", type=float, default=5.0)
    parser.add_argument("--adaptive-scale", type=float, default=4.0)
    parser.add_argument("--adaptive-max-norm-ratio", type=float, default=1.0)
    parser.add_argument("--compute-delay-max", type=float, default=0.05)
    parser.add_argument("--network-delay-max", type=float, default=0.05)
    parser.add_argument("--round-timeout", type=float, default=120.0)
    parser.add_argument("--min-results", type=int, default=None)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="")
    return parser.parse_args()


def load_dataset(name: str, data_dir: str):
    if name == "fashion-mnist":
        transform = transforms.ToTensor()
        train = datasets.FashionMNIST(data_dir, train=True, download=True, transform=transform)
        test = datasets.FashionMNIST(data_dir, train=False, download=True, transform=transform)
        model_spec = ModelSpec(
            factory_path="zerotrust_fl.engine.models:mlp_classifier",
            kwargs={"input_shape": [1, 28, 28], "num_classes": 10, "hidden_dim": 128},
        )
        return train, test, model_spec

    transform = transforms.Compose(
        [
            transforms.ToTensor(),
            transforms.Normalize(
                (0.4914, 0.4822, 0.4465),
                (0.2470, 0.2435, 0.2616),
            ),
        ]
    )
    train = datasets.CIFAR10(data_dir, train=True, download=True, transform=transform)
    test = datasets.CIFAR10(data_dir, train=False, download=True, transform=transform)
    model_spec = ModelSpec(
        factory_path="zerotrust_fl.engine.models:small_conv_classifier",
        kwargs={"input_channels": 3, "num_classes": 10, "image_size": 32},
    )
    return train, test, model_spec


def main() -> None:
    args = parse_args()
    if args.clients <= 0:
        raise ValueError("clients must be positive")
    if not 0.0 <= args.compromised_ratio < 1.0:
        raise ValueError("compromised-ratio must be in [0, 1)")
    if min(args.compute_delay_max, args.network_delay_max) < 0:
        raise ValueError("delay maxima cannot be negative")

    torch.manual_seed(args.seed)
    train_dataset, test_dataset, model_spec = load_dataset(args.dataset, args.data_dir)
    partitions = partition_dataset(
        train_dataset,
        args.clients,
        strategy=args.partition,
        alpha=args.alpha,
        seed=args.seed,
        min_samples_per_client=max(2, args.batch_size // 4),
    )

    rng = np.random.default_rng(args.seed)
    compromised_count = int(round(args.clients * args.compromised_ratio))
    compromised_ids = set(
        int(value)
        for value in rng.choice(args.clients, size=compromised_count, replace=False).tolist()
    ) if compromised_count else set()

    workers: list[WorkerSpec] = []
    for client_id in range(args.clients):
        malicious = client_id in compromised_ids
        attack = AttackConfig(
            kind=args.attack if malicious else "none",
            source_class=0,
            target_class=1,
            noise_std=args.noise_std,
            sign_scale=args.sign_scale,
            adaptive_scale=args.adaptive_scale,
            adaptive_max_norm_ratio=args.adaptive_max_norm_ratio,
            seed=args.seed + client_id,
        )
        workers.append(
            WorkerSpec(
                config=WorkerConfig(
                    node_id=f"edge-worker-{client_id:03d}",
                    batch_size=args.batch_size,
                    local_epochs_min=args.local_epochs_min,
                    local_epochs_max=args.local_epochs_max,
                    learning_rate=args.learning_rate,
                    learning_rate_jitter=args.learning_rate_jitter,
                    optimizer=args.optimizer,
                    device=args.device,
                    compute_delay_seconds=(0.0, args.compute_delay_max),
                    network_delay_seconds=(0.0, args.network_delay_max),
                    seed=args.seed + client_id,
                    malicious=malicious,
                    attack=attack,
                ),
                sample_indices=tuple(int(index) for index in partitions[client_id]),
            )
        )

    selected_count = args.clients_per_round or args.clients
    byzantine_f = args.byzantine_f
    if byzantine_f is None:
        byzantine_f = min(compromised_count, max(0, (selected_count - 3) // 2))

    coordinator = AsyncFederatedCoordinator(
        dataset=train_dataset,
        model_spec=model_spec,
        workers=workers,
        simulation=SimulationConfig(
            rounds=args.rounds,
            clients_per_round=args.clients_per_round,
            min_results=args.min_results,
            round_timeout_seconds=args.round_timeout,
            start_method="spawn",
            seed=args.seed,
            evaluation_device=args.device,
        ),
        aggregation=AggregationConfig(
            method=args.aggregation,
            backend=args.aggregation_backend,
            f=byzantine_f,
            k=args.multi_krum_k,
            beta=args.trim_beta,
        ),
        evaluation_dataset=test_dataset,
    )

    print("partition statistics:")
    for stat in partition_stats(train_dataset, partitions):
        print(json.dumps({
            "client": stat.client_id,
            "samples": stat.sample_count,
            "classes": stat.class_counts,
        }))

    summary = coordinator.run()
    records: list[dict[str, object]] = []
    for metrics in summary.rounds:
        record = {
            "round": metrics.round_id,
            "selected": len(metrics.selected_clients),
            "completed": len(metrics.completed_clients),
            "failed": list(metrics.failed_clients),
            "stragglers": list(metrics.straggler_clients),
            "malicious_results": metrics.malicious_results,
            "aggregation_backend": metrics.aggregation_backend,
            "aggregation_method": metrics.aggregation_method,
            "mean_client_loss": metrics.mean_client_loss,
            "evaluation_loss": metrics.evaluation_loss,
            "evaluation_accuracy": metrics.evaluation_accuracy,
            "mitigation_score": metrics.mitigation_score,
            "attack_mitigated": metrics.attack_mitigated,
            "round_duration_ms": metrics.round_duration_ms,
        }
        records.append(record)
        print(json.dumps(record))

    print(json.dumps({
        "attack_mitigation_success_rate": summary.attack_mitigation_success_rate,
        "final_accuracy": summary.final_accuracy,
        "final_loss": summary.final_loss,
    }))

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(records, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
