"""Run a long-lived synthetic FL worker against the Go mTLS coordinator."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import grpc
import torch
from torch import nn

from zerotrust_fl.attacks import AttackConfig, PoisoningAttack
from zerotrust_fl.client import GrpcWorkerClient, GrpcWorkerConfig, UpdateMetrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default=os.getenv("ZTFL_COORDINATOR_ADDRESS", "coordinator:50051"))
    parser.add_argument("--server-name", default=os.getenv("ZTFL_SERVER_NAME", "coordinator"))
    parser.add_argument("--node-id", default=os.getenv("ZTFL_NODE_ID", "edge-worker-01"))
    parser.add_argument("--cert-dir", default=os.getenv("ZTFL_CERT_DIR", "/certs"))
    parser.add_argument(
        "--attack",
        choices=["none", "label_flip", "gaussian", "sign_flip", "adaptive"],
        default=os.getenv("ZTFL_ATTACK", "none"),
    )
    parser.add_argument("--interval", type=float, default=float(os.getenv("ZTFL_UPDATE_INTERVAL", "5")))
    parser.add_argument("--samples", type=int, default=int(os.getenv("ZTFL_LOCAL_SAMPLES", "128")))
    parser.add_argument("--features", type=int, default=int(os.getenv("ZTFL_LOCAL_FEATURES", "16")))
    parser.add_argument("--seed", type=int, default=int(os.getenv("ZTFL_WORKER_SEED", "42")))
    parser.add_argument("--health-file", default=os.getenv("ZTFL_HEALTH_FILE", "/tmp/ztfl-worker.ready"))
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cert_dir = Path(args.cert_dir)
    config = GrpcWorkerConfig(
        address=args.address,
        node_id=args.node_id,
        certificate_common_name=args.node_id,
        ca_certificate=str(cert_dir / "ca.crt"),
        client_certificate=str(cert_dir / f"{args.node_id}.crt"),
        client_private_key=str(cert_dir / f"{args.node_id}.key"),
        jwt_token_file=str(cert_dir / f"{args.node_id}.jwt"),
        server_name_override=args.server_name,
        timeout_seconds=10.0,
    )

    attack = PoisoningAttack(
        AttackConfig(
            kind=args.attack,
            source_class=0,
            target_class=1,
            noise_std=8.0,
            sign_scale=4.0,
            adaptive_scale=4.0,
            adaptive_max_norm_ratio=1.0,
            seed=args.seed,
        )
    )

    with GrpcWorkerClient(config) as client:
        _register_with_retry(client)
        Path(args.health_file).write_text("ready\n", encoding="utf-8")
        cycle = 0
        while True:
            model = client.get_global_model()
            update, metrics = _train_synthetic_update(
                attack=attack,
                malicious=args.attack != "none",
                samples=args.samples,
                features=args.features,
                seed=args.seed + cycle * 10_007,
                round_id=int(model.round_id),
            )
            response = client.submit_update(
                update,
                round_id=int(model.round_id),
                base_model_version=str(model.model_version),
                metrics=metrics,
            )
            if not response.accepted:
                raise RuntimeError(f"coordinator rejected update: {response.reason}")
            client.heartbeat(str(model.model_version))
            print(
                f"node={args.node_id} attack={args.attack} update={response.update_id} "
                f"loss={metrics.loss:.6f}",
                flush=True,
            )
            cycle += 1
            if args.once:
                return
            time.sleep(max(0.1, args.interval))


def _register_with_retry(client: GrpcWorkerClient, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client.wait_ready(timeout=3.0)
            client.register()
            return
        except (grpc.RpcError, grpc.FutureTimeoutError, RuntimeError) as exc:
            last_error = exc
            time.sleep(1.0)
    raise RuntimeError("could not register worker before startup deadline") from last_error


def _train_synthetic_update(
    *,
    attack: PoisoningAttack,
    malicious: bool,
    samples: int,
    features: int,
    seed: int,
    round_id: int,
) -> tuple[torch.Tensor, UpdateMetrics]:
    generator = torch.Generator().manual_seed(seed)
    inputs = torch.randn(samples, features, generator=generator)
    target_weights = torch.randn(features, generator=generator)
    labels = (inputs @ target_weights > 0).long()

    torch.manual_seed(12345)
    model = nn.Linear(features, 2)
    baseline = torch.nn.utils.parameters_to_vector(model.parameters()).detach().clone()
    optimizer = torch.optim.SGD(model.parameters(), lr=0.05)
    criterion = nn.CrossEntropyLoss()

    started = time.perf_counter()
    optimizer.zero_grad(set_to_none=True)
    training_labels = labels
    if malicious and attack.attacks_labels:
        training_labels = attack.transform_labels(labels, round_id=round_id, batch_id=0)
    logits = model(inputs)
    loss = criterion(logits, training_labels)
    loss.backward()
    gradient_norm = _gradient_norm(model)
    optimizer.step()

    update = (
        torch.nn.utils.parameters_to_vector(model.parameters()).detach() - baseline
    ).to(dtype=torch.float32, device="cpu").contiguous()
    if malicious and attack.attacks_updates:
        update = attack.transform_update(update, round_id=round_id).cpu().contiguous()

    metrics = UpdateMetrics(
        dynamic_epochs=1,
        loss=float(loss.detach()),
        gradient_norms=(gradient_norm,),
        sample_count=samples,
        training_duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
    )
    return update, metrics


def _gradient_norm(model: nn.Module) -> float:
    squared = torch.zeros((), dtype=torch.float64)
    for parameter in model.parameters():
        if parameter.grad is not None:
            squared += parameter.grad.detach().double().pow(2).sum()
    return float(torch.sqrt(squared))


if __name__ == "__main__":
    main()
