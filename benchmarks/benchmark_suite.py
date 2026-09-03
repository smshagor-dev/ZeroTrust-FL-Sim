"""Performance benchmarks for native aggregation, gRPC transport, and poisoned FL convergence."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import tempfile
import time
from concurrent import futures
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

import grpc
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import torch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from torch.utils.data import TensorDataset

from zerotrust_fl.aggregators.native_cpp import CppByzantineAggregator, native_extension_available
from zerotrust_fl.attacks import AttackConfig
from zerotrust_fl.data import partition_dataset
from zerotrust_fl.engine import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    ModelSpec,
    SimulationConfig,
    WorkerConfig,
    WorkerSpec,
)

PROFILE_FULL = "full"
PROFILE_QUICK = "quick"


@dataclass(frozen=True, slots=True)
class AggregationRecord:
    algorithm: str
    parameters: int
    clients: int
    native_ms: float
    numpy_ms: float
    speedup: float


@dataclass(frozen=True, slots=True)
class NetworkRecord:
    transport: str
    payload_bytes: int
    requests: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    throughput_per_second: float


@dataclass(frozen=True, slots=True)
class ConvergenceRecord:
    malicious_fraction: float
    round_id: int
    loss: float
    accuracy: float
    mitigation_score: float | None
    attack_mitigated: bool | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=[PROFILE_FULL, PROFILE_QUICK], default=PROFILE_FULL)
    parser.add_argument(
        "--sections",
        nargs="+",
        choices=["aggregation", "network", "convergence"],
        default=["aggregation", "network", "convergence"],
    )
    parser.add_argument("--output-dir", default="benchmarks/results")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "profile": args.profile,
        "sections": args.sections,
        "seed": args.seed,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python": os.sys.version,
        "torch": torch.__version__,
        "native_extension": native_extension_available(),
    }
    (output_dir / "benchmark_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    if "aggregation" in args.sections:
        records = benchmark_aggregators(args.profile, args.seed)
        _write_records(output_dir / "aggregation.csv", records)
        plot_aggregation(records, output_dir / "aggregation_speedup.png")

    if "network" in args.sections:
        records = benchmark_grpc_transport(args.profile)
        _write_records(output_dir / "network.csv", records)
        plot_network(records, output_dir / "mtls_overhead.png")

    if "convergence" in args.sections:
        records = benchmark_convergence(args.profile, args.seed)
        _write_records(output_dir / "convergence.csv", records)
        plot_convergence(records, output_dir / "poisoning_convergence.png")

    print(f"benchmark results written to {output_dir.resolve()}")


def benchmark_aggregators(profile: str, seed: int) -> list[AggregationRecord]:
    if not native_extension_available():
        raise RuntimeError("zerotrust_fl_cpp is required for aggregation benchmarks; build with `pip install -e .`")

    sizes = (1_000, 100_000, 10_000_000) if profile == PROFILE_FULL else (1_000, 100_000)
    repeats = 5 if profile == PROFILE_FULL else 2
    clients = 7
    f = 1
    k = 3
    beta = 0.2
    rng = np.random.default_rng(seed)
    native = CppByzantineAggregator(preserve_device=False, preserve_dtype=False)

    algorithms: tuple[
        tuple[str, Callable[[list[torch.Tensor]], torch.Tensor], Callable[[list[np.ndarray]], np.ndarray]], ...
    ] = (
        ("krum", lambda tensors: native.krum(tensors, f=f, k=1), lambda arrays: _numpy_krum(arrays, f=f, k=1)),
        ("multi_krum", lambda tensors: native.krum(tensors, f=f, k=k), lambda arrays: _numpy_krum(arrays, f=f, k=k)),
        ("adaptive_trimmed_mean", lambda tensors: native.trimmed_mean(tensors, beta=beta), lambda arrays: _numpy_trimmed_mean(arrays, beta=beta)),
    )

    records: list[AggregationRecord] = []
    for parameters in sizes:
        arrays = [
            np.ascontiguousarray(rng.normal(0.0, 1.0, size=parameters), dtype=np.float32)
            for _ in range(clients)
        ]
        tensors = [torch.from_numpy(array) for array in arrays]

        for name, native_fn, numpy_fn in algorithms:
            native_result = native_fn(tensors)
            numpy_result = numpy_fn(arrays)
            np.testing.assert_allclose(native_result.numpy(), numpy_result, rtol=2e-4, atol=2e-5)

            native_ms = _median_duration_ms(lambda: native_fn(tensors), repeats)
            numpy_ms = _median_duration_ms(lambda: numpy_fn(arrays), repeats)
            record = AggregationRecord(
                algorithm=name,
                parameters=parameters,
                clients=clients,
                native_ms=native_ms,
                numpy_ms=numpy_ms,
                speedup=numpy_ms / native_ms if native_ms > 0 else math.inf,
            )
            records.append(record)
            print(json.dumps(asdict(record), sort_keys=True))
    return records


def _numpy_krum(updates: list[np.ndarray], *, f: int, k: int) -> np.ndarray:
    n = len(updates)
    if n < 2 * f + 3:
        raise ValueError("unsafe Krum configuration")
    neighbour_count = n - f - 2
    scores = np.zeros(n, dtype=np.float64)
    for i in range(n):
        distances = []
        left = updates[i]
        for j in range(n):
            if i == j:
                continue
            diff = left - updates[j]
            distances.append(float(np.dot(diff, diff)))
        scores[i] = np.partition(np.asarray(distances), neighbour_count - 1)[:neighbour_count].sum()
    selected = np.argsort(scores, kind="stable")[:k]
    return np.mean(np.stack([updates[int(index)] for index in selected]), axis=0, dtype=np.float64).astype(np.float32)


def _numpy_trimmed_mean(updates: list[np.ndarray], *, beta: float) -> np.ndarray:
    stacked = np.stack(updates, axis=0)
    trim = int(math.floor(len(updates) * beta))
    if 2 * trim >= len(updates):
        raise ValueError("trim removes every update")
    ordered = np.sort(stacked, axis=0)
    return ordered[trim : len(updates) - trim].mean(axis=0, dtype=np.float64).astype(np.float32)


def benchmark_grpc_transport(profile: str) -> list[NetworkRecord]:
    requests = 1_000 if profile == PROFILE_FULL else 100
    payload_bytes = 16 * 1024 if profile == PROFILE_FULL else 4 * 1024
    payload = b"z" * payload_bytes

    with tempfile.TemporaryDirectory(prefix="ztfl-grpc-bench-") as temp_dir:
        certs = _generate_benchmark_certificates(Path(temp_dir))
        records = [
            _measure_grpc_echo(payload, requests, secure=False, certs=certs),
            _measure_grpc_echo(payload, requests, secure=True, certs=certs),
        ]
    for record in records:
        print(json.dumps(asdict(record), sort_keys=True))
    return records


def _measure_grpc_echo(
    payload: bytes,
    requests: int,
    *,
    secure: bool,
    certs: dict[str, bytes],
) -> NetworkRecord:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    handler = grpc.unary_unary_rpc_method_handler(
        lambda request, _context: request,
        request_deserializer=lambda value: value,
        response_serializer=lambda value: value,
    )
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("bench.Echo", {"Ping": handler}),))

    if secure:
        credentials = grpc.ssl_server_credentials(
            ((certs["server_key"], certs["server_cert"]),),
            root_certificates=certs["ca_cert"],
            require_client_auth=True,
        )
        port = server.add_secure_port("127.0.0.1:0", credentials)
    else:
        port = server.add_insecure_port("127.0.0.1:0")
    server.start()

    try:
        if secure:
            channel_credentials = grpc.ssl_channel_credentials(
                root_certificates=certs["ca_cert"],
                private_key=certs["client_key"],
                certificate_chain=certs["client_cert"],
            )
            channel = grpc.secure_channel(
                f"127.0.0.1:{port}",
                channel_credentials,
                options=(("grpc.ssl_target_name_override", "localhost"),),
            )
        else:
            channel = grpc.insecure_channel(f"127.0.0.1:{port}")

        grpc.channel_ready_future(channel).result(timeout=5)
        call = channel.unary_unary(
            "/bench.Echo/Ping",
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )
        for _ in range(10):
            if call(payload, timeout=5) != payload:
                raise RuntimeError("gRPC echo warmup returned a corrupt payload")

        durations: list[float] = []
        started = time.perf_counter()
        for _ in range(requests):
            request_started = time.perf_counter()
            if call(payload, timeout=5) != payload:
                raise RuntimeError("gRPC echo returned a corrupt payload")
            durations.append((time.perf_counter() - request_started) * 1000.0)
        elapsed = time.perf_counter() - started
        channel.close()
    finally:
        server.stop(grace=0).wait(timeout=5)

    sorted_durations = sorted(durations)
    return NetworkRecord(
        transport="mtls" if secure else "plaintext",
        payload_bytes=len(payload),
        requests=requests,
        mean_ms=float(statistics.fmean(durations)),
        p50_ms=float(np.percentile(sorted_durations, 50)),
        p95_ms=float(np.percentile(sorted_durations, 95)),
        throughput_per_second=float(requests / elapsed),
    )


def _generate_benchmark_certificates(directory: Path) -> dict[str, bytes]:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZTFL Benchmark CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def issue(name: str, *, server: bool) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    server_cert, server_key = issue("localhost", server=True)
    client_cert, client_key = issue("benchmark-client", server=False)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    (directory / "ca.crt").write_bytes(ca_pem)
    return {
        "ca_cert": ca_pem,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
    }


def benchmark_convergence(profile: str, seed: int) -> list[ConvergenceRecord]:
    rounds = 50 if profile == PROFILE_FULL else 3
    clients = 20 if profile == PROFILE_FULL else 5
    samples = 8_000 if profile == PROFILE_FULL else 500
    malicious_fractions = (0.0, 0.10, 0.25, 0.40)
    train, test = _synthetic_classification(samples=samples, features=12, seed=seed)
    model_spec = ModelSpec(
        factory_path="zerotrust_fl.engine.models:mlp_classifier",
        kwargs={"input_shape": [12], "num_classes": 2, "hidden_dim": 16},
    )
    records: list[ConvergenceRecord] = []

    for fraction in malicious_fractions:
        partitions = partition_dataset(
            train,
            clients,
            strategy="dirichlet",
            alpha=0.5,
            seed=seed + int(fraction * 1_000),
            min_samples_per_client=8,
        )
        malicious_count = min(clients - 1, int(round(clients * fraction)))
        malicious_ids = set(range(malicious_count))
        workers = []
        for client_id in range(clients):
            malicious = client_id in malicious_ids
            workers.append(
                WorkerSpec(
                    config=WorkerConfig(
                        node_id=f"bench-{int(fraction * 100):02d}-{client_id:02d}",
                        batch_size=64,
                        local_epochs_min=1,
                        local_epochs_max=1,
                        learning_rate=0.05,
                        optimizer="sgd",
                        torch_num_threads=1,
                        seed=seed + 101 * client_id,
                        malicious=malicious,
                        attack=AttackConfig(
                            kind="sign_flip" if malicious else "none",
                            sign_scale=4.0,
                            seed=seed + 101 * client_id,
                        ),
                    ),
                    sample_indices=tuple(int(index) for index in partitions[client_id]),
                )
            )

        coordinator = AsyncFederatedCoordinator(
            dataset=train,
            model_spec=model_spec,
            workers=workers,
            simulation=SimulationConfig(
                rounds=rounds,
                clients_per_round=clients,
                min_results=clients,
                round_timeout_seconds=120.0,
                start_method="spawn",
                seed=seed,
            ),
            aggregation=AggregationConfig(method="median", backend="auto"),
            evaluation_dataset=test,
        )
        summary = coordinator.run()
        for metrics in summary.rounds:
            if metrics.evaluation_loss is None or metrics.evaluation_accuracy is None:
                raise RuntimeError("convergence benchmark requires evaluation metrics")
            record = ConvergenceRecord(
                malicious_fraction=fraction,
                round_id=metrics.round_id,
                loss=metrics.evaluation_loss,
                accuracy=metrics.evaluation_accuracy,
                mitigation_score=metrics.mitigation_score,
                attack_mitigated=metrics.attack_mitigated,
            )
            records.append(record)
            print(json.dumps(asdict(record), sort_keys=True))
    return records


def _synthetic_classification(*, samples: int, features: int, seed: int) -> tuple[TensorDataset, TensorDataset]:
    generator = torch.Generator().manual_seed(seed)
    weights = torch.randn(features, generator=generator)
    inputs = torch.randn(samples, features, generator=generator)
    logits = inputs @ weights + 0.15 * torch.randn(samples, generator=generator)
    labels = (logits > 0).long()
    split = int(samples * 0.8)
    return (
        TensorDataset(inputs[:split].contiguous(), labels[:split].contiguous()),
        TensorDataset(inputs[split:].contiguous(), labels[split:].contiguous()),
    )


def plot_aggregation(records: Iterable[AggregationRecord], output: Path) -> None:
    records = list(records)
    fig, ax = plt.subplots(figsize=(10, 6))
    for algorithm in sorted({record.algorithm for record in records}):
        selected = sorted((r for r in records if r.algorithm == algorithm), key=lambda r: r.parameters)
        ax.plot([r.parameters for r in selected], [r.speedup for r in selected], marker="o", label=algorithm)
    ax.set_xscale("log")
    ax.set_xlabel("Model parameters")
    ax.set_ylabel("Native speedup vs NumPy")
    ax.set_title("C++20 Byzantine Aggregator Speedup")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output, dpi=300)
    plt.close(fig)


def plot_network(records: Iterable[NetworkRecord], output: Path) -> None:
    records = list(records)
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = [r.transport for r in records]
    ax.bar(labels, [r.mean_ms for r in records])
    ax.set_ylabel("Mean request latency (ms)")
    ax.set_title("gRPC Transport Latency: Plaintext vs mTLS")
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, dpi=300)
    plt.close(fig)


def plot_convergence(records: Iterable[ConvergenceRecord], output: Path) -> None:
    records = list(records)
    fig, ax = plt.subplots(figsize=(10, 6))
    for fraction in sorted({record.malicious_fraction for record in records}):
        selected = sorted((r for r in records if r.malicious_fraction == fraction), key=lambda r: r.round_id)
        ax.plot(
            [r.round_id for r in selected],
            [r.accuracy for r in selected],
            marker="o",
            label=f"{int(fraction * 100)}% malicious",
        )
    ax.set_xlabel("Federated round")
    ax.set_ylabel("Test accuracy")
    ax.set_ylim(0.0, 1.0)
    ax.set_title("Robust Median Convergence Under Sign-Flipping Poisoning")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output, dpi=300)
    plt.close(fig)


def _median_duration_ms(operation: Callable[[], object], repeats: int) -> float:
    durations = []
    for _ in range(repeats):
        started = time.perf_counter()
        operation()
        durations.append((time.perf_counter() - started) * 1000.0)
    return float(statistics.median(durations))


def _write_records(path: Path, records: Iterable[object]) -> None:
    rows = [asdict(record) for record in records]
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
