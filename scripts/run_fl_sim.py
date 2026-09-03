"""Run a local asynchronous federated learning simulation."""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import TensorDataset
from zerotrust_fl.attacks import AttackConfig
from zerotrust_fl.data import partition_dataset, partition_stats
from zerotrust_fl.engine import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    ModelSpec,
    SimulationConfig,
    WorkerConfig,
    WorkerSpec,
)
from zerotrust_fl.privacy import LocalDPConfig, RDPAccountant


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Asynchronous multi-process ZeroTrust-FL simulation"
    )
    parser.add_argument(
        "--dataset",
        choices=["synthetic", "fashion-mnist", "cifar10"],
        default="synthetic",
    )
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--clients", type=int, default=10)
    parser.add_argument("--clients-per-round", type=int, default=None)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--alpha", type=float, default=0.3)
    parser.add_argument(
        "--partition",
        choices=["iid", "dirichlet"],
        default="dirichlet",
    )
    parser.add_argument("--malicious-fraction", type=float, default=0.2)
    parser.add_argument(
        "--attack",
        choices=["none", "label_flip", "gaussian", "sign_flip", "adaptive"],
        default="sign_flip",
    )
    parser.add_argument(
        "--aggregator",
        choices=["mean", "krum", "multi_krum", "trimmed_mean", "median"],
        default="multi_krum",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "native", "torch"],
        default="auto",
    )
    parser.add_argument("--byzantine-f", type=int, default=None)
    parser.add_argument("--multi-krum-k", type=int, default=3)
    parser.add_argument("--trim-beta", type=float, default=0.2)
    parser.add_argument("--local-epochs-min", type=int, default=1)
    parser.add_argument("--local-epochs-max", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.03)
    parser.add_argument("--optimizer", choices=["sgd", "adam"], default="sgd")
    parser.add_argument("--round-timeout", type=float, default=120.0)
    parser.add_argument(
        "--min-results",
        type=int,
        default=None,
        help="minimum successful worker quorum; defaults to all selected clients",
    )
    parser.add_argument("--max-compute-delay", type=float, default=0.15)
    parser.add_argument("--max-network-delay", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--synthetic-samples", type=int, default=4000)
    parser.add_argument("--synthetic-features", type=int, default=20)
    parser.add_argument("--synthetic-classes", type=int, default=4)
    parser.add_argument("--device", default="cpu")
    parser.add_argument(
        "--dp",
        action="store_true",
        help="enable release-level Local Differential Privacy on client model updates",
    )
    parser.add_argument("--dp-clip-norm", type=float, default=1.0)
    parser.add_argument("--dp-noise-multiplier", type=float, default=1.0)
    parser.add_argument("--dp-delta", type=float, default=1e-5)
    parser.add_argument(
        "--dp-adjacency",
        choices=["replace", "add_remove"],
        default="replace",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.clients <= 0:
        raise SystemExit("--clients must be positive")
    if not 0.0 <= args.malicious_fraction < 1.0:
        raise SystemExit("--malicious-fraction must be in [0, 1)")

    local_dp = LocalDPConfig(
        enabled=args.dp,
        clip_norm=args.dp_clip_norm,
        noise_multiplier=args.dp_noise_multiplier,
        delta=args.dp_delta,
        adjacency=args.dp_adjacency,
    )

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    train_dataset, test_dataset, model_spec = load_dataset_and_model(args)
    partitions = partition_dataset(
        train_dataset,
        args.clients,
        strategy=args.partition,
        alpha=args.alpha,
        seed=args.seed,
        min_samples_per_client=max(1, min(8, len(train_dataset) // args.clients)),
    )

    malicious_count = math.floor(args.clients * args.malicious_fraction)
    rng = np.random.default_rng(args.seed)
    malicious_ids = (
        {
            int(value)
            for value in rng.choice(
                args.clients,
                size=malicious_count,
                replace=False,
            ).tolist()
        }
        if malicious_count
        else set()
    )

    workers: list[WorkerSpec] = []
    for client_id in range(args.clients):
        malicious = client_id in malicious_ids
        attack = make_attack_config(args, client_id) if malicious else AttackConfig()
        worker_config = WorkerConfig(
            node_id=f"edge-worker-{client_id:02d}",
            batch_size=args.batch_size,
            local_epochs_min=args.local_epochs_min,
            local_epochs_max=args.local_epochs_max,
            learning_rate=args.learning_rate,
            learning_rate_jitter=0.1,
            optimizer=args.optimizer,
            optimizer_kwargs={"momentum": 0.9} if args.optimizer == "sgd" else {},
            device=args.device,
            compute_delay_seconds=(0.0, args.max_compute_delay),
            network_delay_seconds=(0.0, args.max_network_delay),
            torch_num_threads=1,
            seed=args.seed + client_id * 1009,
            malicious=malicious,
            attack=attack,
            local_dp=local_dp,
        )
        workers.append(
            WorkerSpec(
                config=worker_config,
                sample_indices=tuple(int(index) for index in partitions[client_id]),
            )
        )

    clients_per_round = args.clients_per_round or args.clients
    min_results = args.min_results or clients_per_round
    byzantine_f = (
        args.byzantine_f
        if args.byzantine_f is not None
        else min(malicious_count, max(0, (min_results - 3) // 2))
    )
    k = min(
        args.multi_krum_k,
        max(1, min_results - byzantine_f - 2),
    )

    simulation = SimulationConfig(
        rounds=args.rounds,
        clients_per_round=clients_per_round,
        min_results=min_results,
        round_timeout_seconds=args.round_timeout,
        start_method="spawn",
        seed=args.seed,
        evaluation_device=args.device,
    )
    aggregation = AggregationConfig(
        method=args.aggregator,
        backend=args.backend,
        f=byzantine_f,
        k=k,
        beta=args.trim_beta,
    )

    targets = _dataset_targets(train_dataset)
    print("Partition summary:")
    for stat in partition_stats(targets, partitions):
        print(
            json.dumps(
                {
                    "client": stat.client_id,
                    "samples": stat.sample_count,
                    "classes": stat.class_counts,
                    "malicious": stat.client_id in malicious_ids,
                },
                sort_keys=True,
            )
        )

    if local_dp.enabled:
        accountant = RDPAccountant(local_dp, releases=args.rounds)
        epsilon, optimal_order = accountant.epsilon()
        print("\nLocal DP worst-case budget:")
        print(
            json.dumps(
                {
                    "adjacency": local_dp.adjacency,
                    "clip_norm": local_dp.clip_norm,
                    "sensitivity": local_dp.sensitivity,
                    "noise_multiplier": local_dp.noise_multiplier,
                    "noise_std": local_dp.noise_std,
                    "delta": local_dp.delta,
                    "assumed_releases": args.rounds,
                    "epsilon": epsilon,
                    "optimal_rdp_order": optimal_order,
                    "note": "worst-case per-client bound assuming participation in every round",
                },
                sort_keys=True,
            )
        )

    coordinator = AsyncFederatedCoordinator(
        dataset=train_dataset,
        model_spec=model_spec,
        workers=workers,
        simulation=simulation,
        aggregation=aggregation,
        evaluation_dataset=test_dataset,
    )
    summary = coordinator.run()

    print("\nRound metrics:")
    for metrics in summary.rounds:
        print(json.dumps(asdict(metrics), sort_keys=True))

    print(
        json.dumps(
            {
                "final_accuracy": summary.final_accuracy,
                "final_loss": summary.final_loss,
                "attack_mitigation_success_rate": summary.attack_mitigation_success_rate,
            },
            sort_keys=True,
        )
    )


def make_attack_config(args: argparse.Namespace, client_id: int) -> AttackConfig:
    common = {"seed": args.seed + client_id * 7919}
    if args.attack == "label_flip":
        return AttackConfig(
            kind="label_flip",
            source_class=0,
            target_class=1,
            probability=1.0,
            **common,
        )
    if args.attack == "gaussian":
        return AttackConfig(
            kind="gaussian",
            noise_mean=0.0,
            noise_std=3.0,
            **common,
        )
    if args.attack == "sign_flip":
        return AttackConfig(
            kind="sign_flip",
            sign_scale=5.0,
            **common,
        )
    if args.attack == "adaptive":
        return AttackConfig(
            kind="adaptive",
            adaptive_scale=8.0,
            adaptive_max_norm_ratio=1.0,
            **common,
        )
    return AttackConfig(kind="none", **common)


def load_dataset_and_model(
    args: argparse.Namespace,
) -> tuple[torch.utils.data.Dataset, torch.utils.data.Dataset, ModelSpec]:
    if args.dataset == "synthetic":
        train, test = _synthetic_dataset(
            samples=args.synthetic_samples,
            features=args.synthetic_features,
            classes=args.synthetic_classes,
            seed=args.seed,
        )
        return (
            train,
            test,
            ModelSpec(
                "zerotrust_fl.engine.models:mlp_classifier",
                {
                    "input_shape": [args.synthetic_features],
                    "num_classes": args.synthetic_classes,
                    "hidden_dim": 64,
                },
            ),
        )

    try:
        from torchvision import datasets, transforms
    except ImportError as exc:
        raise SystemExit(
            "torchvision is required for Fashion-MNIST/CIFAR-10; "
            "install requirements.txt first"
        ) from exc

    data_root = str(Path(args.data_dir))
    if args.dataset == "fashion-mnist":
        transform = transforms.ToTensor()
        train = datasets.FashionMNIST(
            data_root,
            train=True,
            download=True,
            transform=transform,
        )
        test = datasets.FashionMNIST(
            data_root,
            train=False,
            download=True,
            transform=transform,
        )
        model_spec = ModelSpec(
            "zerotrust_fl.engine.models:mlp_classifier",
            {
                "input_shape": [1, 28, 28],
                "num_classes": 10,
                "hidden_dim": 128,
            },
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
    train = datasets.CIFAR10(
        data_root,
        train=True,
        download=True,
        transform=transform,
    )
    test = datasets.CIFAR10(
        data_root,
        train=False,
        download=True,
        transform=transform,
    )
    model_spec = ModelSpec(
        "zerotrust_fl.engine.models:small_conv_classifier",
        {
            "input_channels": 3,
            "num_classes": 10,
            "image_size": 32,
        },
    )
    return train, test, model_spec


def _synthetic_dataset(
    *,
    samples: int,
    features: int,
    classes: int,
    seed: int,
) -> tuple[TensorDataset, TensorDataset]:
    if samples < classes * 10:
        raise ValueError("synthetic sample count is too small")
    generator = torch.Generator().manual_seed(seed)
    weights = torch.randn(features, classes, generator=generator)

    def make(count: int) -> TensorDataset:
        inputs = torch.randn(count, features, generator=generator)
        logits = inputs @ weights + 0.2 * torch.randn(
            count,
            classes,
            generator=generator,
        )
        labels = logits.argmax(dim=1)
        return TensorDataset(inputs, labels)

    return make(samples), make(max(classes * 20, samples // 4))


def _dataset_targets(dataset: torch.utils.data.Dataset) -> np.ndarray:
    if hasattr(dataset, "targets"):
        return np.asarray(dataset.targets, dtype=np.int64)
    if hasattr(dataset, "tensors"):
        tensors = dataset.tensors
        if len(tensors) >= 2:
            return tensors[1].detach().cpu().numpy().astype(np.int64, copy=False)
    labels = []
    for index in range(len(dataset)):
        label = dataset[index][1]
        labels.append(int(label.item() if isinstance(label, torch.Tensor) else label))
    return np.asarray(labels, dtype=np.int64)


if __name__ == "__main__":
    main()
