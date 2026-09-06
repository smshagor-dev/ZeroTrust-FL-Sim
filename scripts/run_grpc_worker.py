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
from zerotrust_fl.client import (
    GrpcWorkerClient,
    GrpcWorkerConfig,
    UpdateMetrics,
    deserialize_update,
)
from zerotrust_fl.observability import TelemetryRuntime
from zerotrust_fl.privacy import LocalDPConfig, RDPAccountant, protect_model_update


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--address",
        default=os.getenv("ZTFL_COORDINATOR_ADDRESS", "coordinator:50051"),
    )
    parser.add_argument(
        "--server-name", default=os.getenv("ZTFL_SERVER_NAME", "coordinator")
    )
    parser.add_argument(
        "--node-id", default=os.getenv("ZTFL_NODE_ID", "edge-worker-01")
    )
    parser.add_argument(
        "--model-id", default=os.getenv("ZTFL_MODEL_ID", "global-model")
    )
    parser.add_argument("--cert-dir", default=os.getenv("ZTFL_CERT_DIR", "/certs"))
    parser.add_argument(
        "--attack",
        choices=[
            "none",
            "label_flip",
            "gaussian",
            "sign_flip",
            "adaptive",
            "collusion",
        ],
        default=os.getenv("ZTFL_ATTACK", "none"),
    )
    parser.add_argument(
        "--collusion-scale",
        type=float,
        default=float(os.getenv("ZTFL_COLLUSION_SCALE", "8")),
    )
    parser.add_argument(
        "--collusion-seed",
        type=int,
        default=int(os.getenv("ZTFL_COLLUSION_SEED", "20271")),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("ZTFL_UPDATE_INTERVAL", "5")),
    )
    parser.add_argument(
        "--samples", type=int, default=int(os.getenv("ZTFL_LOCAL_SAMPLES", "128"))
    )
    parser.add_argument(
        "--features", type=int, default=int(os.getenv("ZTFL_LOCAL_FEATURES", "16"))
    )
    parser.add_argument(
        "--seed", type=int, default=int(os.getenv("ZTFL_WORKER_SEED", "42"))
    )
    parser.add_argument(
        "--health-file",
        default=os.getenv("ZTFL_HEALTH_FILE", "/tmp/ztfl-worker.ready"),
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--dp",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("ZTFL_DP_ENABLED", False),
        help="apply release-level Local Differential Privacy before SubmitLocalUpdate",
    )
    parser.add_argument(
        "--dp-clip-norm",
        type=float,
        default=float(os.getenv("ZTFL_DP_CLIP_NORM", "1.0")),
    )
    parser.add_argument(
        "--dp-noise-multiplier",
        type=float,
        default=float(os.getenv("ZTFL_DP_NOISE_MULTIPLIER", "1.0")),
    )
    parser.add_argument(
        "--dp-delta",
        type=float,
        default=float(os.getenv("ZTFL_DP_DELTA", "1e-5")),
    )
    parser.add_argument(
        "--dp-adjacency",
        choices=["replace", "add_remove"],
        default=os.getenv("ZTFL_DP_ADJACENCY", "replace"),
    )
    parser.add_argument(
        "--dp-reproducible",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("ZTFL_DP_REPRODUCIBLE", False),
        help="use deterministic DP noise for research reproduction only",
    )
    parser.add_argument(
        "--enforce-dp-on-malicious",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("ZTFL_ENFORCE_DP_ON_MALICIOUS", False),
        help="model a trusted runtime that enforces DP on Byzantine workers",
    )
    parser.add_argument(
        "--telemetry",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("ZTFL_TELEMETRY_ENABLED", False),
    )
    parser.add_argument(
        "--metrics-host",
        default=os.getenv("ZTFL_METRICS_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=int(os.getenv("ZTFL_METRICS_PORT", "9465")),
    )
    parser.add_argument(
        "--otel-endpoint",
        default=os.getenv("ZTFL_OTEL_ENDPOINT", ""),
    )
    parser.add_argument(
        "--otel-insecure",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("ZTFL_OTEL_INSECURE", False),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    telemetry = None
    if args.telemetry:
        telemetry = TelemetryRuntime(
            service_name="zerotrust-fl-worker",
            instance_id=args.node_id,
            metrics_host=args.metrics_host,
            metrics_port=args.metrics_port,
            otlp_endpoint=args.otel_endpoint,
            otlp_insecure=args.otel_insecure,
        )
        telemetry.instrument_grpc_client()
        telemetry.record_attack(args.attack)
        telemetry.record_process_memory()

    cert_dir = Path(args.cert_dir)
    config = GrpcWorkerConfig(
        address=args.address,
        node_id=args.node_id,
        certificate_common_name=args.node_id,
        ca_certificate=str(cert_dir / "ca.crt"),
        client_certificate=str(cert_dir / f"{args.node_id}.crt"),
        client_private_key=str(cert_dir / f"{args.node_id}.key"),
        model_id=args.model_id,
        jwt_token_file=str(cert_dir / f"{args.node_id}.jwt"),
        server_name_override=args.server_name,
        timeout_seconds=10.0,
        max_message_bytes=8 << 20,
    )
    local_dp = LocalDPConfig(
        enabled=bool(args.dp),
        clip_norm=args.dp_clip_norm,
        noise_multiplier=args.dp_noise_multiplier,
        delta=args.dp_delta,
        adjacency=args.dp_adjacency,
    )
    accountant = RDPAccountant(local_dp)

    attack = PoisoningAttack(
        AttackConfig(
            kind=args.attack,
            source_class=0,
            target_class=1,
            noise_std=8.0,
            sign_scale=4.0,
            adaptive_scale=4.0,
            adaptive_max_norm_ratio=1.0,
            collusion_scale=args.collusion_scale,
            collusion_seed=args.collusion_seed,
            seed=args.seed,
        )
    )

    try:
        with GrpcWorkerClient(config) as client:
            _register_with_retry(client, telemetry=telemetry)
            Path(args.health_file).write_text("ready\n", encoding="utf-8")
            cycle = 0
            while True:
                attributes = {
                    "fl.worker.node_id": args.node_id,
                    "fl.worker.cycle": cycle,
                    "fl.attack.kind": args.attack,
                }
                if telemetry is None:
                    _run_cycle(
                        args=args,
                        client=client,
                        attack=attack,
                        local_dp=local_dp,
                        accountant=accountant,
                        cycle=cycle,
                        telemetry=None,
                    )
                else:
                    with telemetry.span("fl.worker.cycle", attributes):
                        _run_cycle(
                            args=args,
                            client=client,
                            attack=attack,
                            local_dp=local_dp,
                            accountant=accountant,
                            cycle=cycle,
                            telemetry=telemetry,
                        )
                cycle += 1
                if args.once:
                    return
                time.sleep(max(0.1, args.interval))
    finally:
        if telemetry is not None:
            telemetry.shutdown()


def _run_cycle(
    *,
    args: argparse.Namespace,
    client: GrpcWorkerClient,
    attack: PoisoningAttack,
    local_dp: LocalDPConfig,
    accountant: RDPAccountant,
    cycle: int,
    telemetry: TelemetryRuntime | None,
) -> None:
    if telemetry is None:
        global_model = client.get_global_model()
    else:
        with telemetry.measure_rpc("GetGlobalModel"):
            global_model = client.get_global_model()

    update, metrics = _train_synthetic_update(
        attack=attack,
        malicious=args.attack != "none",
        samples=args.samples,
        features=args.features,
        seed=args.seed + cycle * 10_007,
        round_id=int(global_model.round_id),
        global_weights_payload=bytes(global_model.weights_payload),
    )
    if telemetry is not None:
        telemetry.record_epoch(float(metrics.training_duration_ms) / 1000.0)

    malicious = args.attack != "none"
    dp_applied = local_dp.enabled and (
        not malicious or bool(args.enforce_dp_on_malicious)
    )
    dp_config = LocalDPConfig(
        enabled=dp_applied,
        clip_norm=local_dp.clip_norm,
        noise_multiplier=local_dp.noise_multiplier,
        delta=local_dp.delta,
        adjacency=local_dp.adjacency,
        orders=local_dp.orders,
    )
    deterministic_seed = (
        args.seed + cycle * 104_729 + 17_171 if args.dp_reproducible else None
    )
    protected = protect_model_update(update, dp_config, seed=deterministic_seed)

    try:
        if telemetry is None:
            response = client.submit_update(
                protected.update,
                round_id=int(global_model.round_id),
                base_model_version=str(global_model.model_version),
                metrics=metrics,
            )
        else:
            with telemetry.measure_rpc("SubmitLocalUpdate"):
                response = client.submit_update(
                    protected.update,
                    round_id=int(global_model.round_id),
                    base_model_version=str(global_model.model_version),
                    metrics=metrics,
                )
    except grpc.RpcError as exc:
        if telemetry is not None:
            telemetry.record_update(accepted=False)
        if exc.code() in {grpc.StatusCode.FAILED_PRECONDITION, grpc.StatusCode.ALREADY_EXISTS}:
            print(
                f"node={args.node_id} round={global_model.round_id} "
                f"submission_skipped={exc.code().name}",
                flush=True,
            )
            return
        raise
    except Exception:
        if telemetry is not None:
            telemetry.record_update(accepted=False)
        raise

    if telemetry is not None:
        telemetry.record_update(accepted=bool(response.accepted))
    if not response.accepted:
        raise RuntimeError(f"coordinator rejected update: {response.reason}")

    if telemetry is None:
        client.heartbeat(str(global_model.model_version))
    else:
        with telemetry.measure_rpc("Heartbeat"):
            client.heartbeat(str(global_model.model_version))
        telemetry.record_process_memory()

    privacy_text = "dp=off"
    if dp_applied:
        accountant.step()
        epsilon, order = accountant.epsilon()
        privacy_text = (
            f"dp=on eps={epsilon:.6f} delta={local_dp.delta:g} "
            f"order={order:g} noise_std={local_dp.noise_std:.6f}"
        )
    elif malicious and local_dp.enabled:
        privacy_text = "dp=bypassed-by-byzantine"

    print(
        f"node={args.node_id} attack={args.attack} update={response.update_id} "
        f"loss={metrics.loss:.6f} {privacy_text}",
        flush=True,
    )


def _register_with_retry(
    client: GrpcWorkerClient,
    timeout_seconds: float = 30.0,
    *,
    telemetry: TelemetryRuntime | None = None,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if telemetry is None:
                client.wait_ready(timeout=3.0)
                client.register()
            else:
                with telemetry.measure_rpc("WaitReady"):
                    client.wait_ready(timeout=3.0)
                with telemetry.measure_rpc("RegisterNode"):
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
    global_weights_payload: bytes,
) -> tuple[torch.Tensor, UpdateMetrics]:
    generator = torch.Generator().manual_seed(seed)
    inputs = torch.randn(samples, features, generator=generator)
    target_weights = torch.randn(features, generator=generator)
    labels = (inputs @ target_weights > 0).long()

    model = nn.Linear(features, 2)
    parameter_count = sum(parameter.numel() for parameter in model.parameters())
    if global_weights_payload:
        global_array = deserialize_update(global_weights_payload).reshape(-1)
        if int(global_array.size) != parameter_count:
            raise ValueError(
                "global model vector length does not match the synthetic worker model: "
                f"{global_array.size} != {parameter_count}"
            )
        global_vector = torch.from_numpy(global_array.copy())
    else:
        global_vector = torch.zeros(parameter_count, dtype=torch.float32)

    torch.nn.utils.vector_to_parameters(global_vector, model.parameters())
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
