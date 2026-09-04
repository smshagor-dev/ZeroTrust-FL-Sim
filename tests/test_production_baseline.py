from __future__ import annotations

import inspect
from pathlib import Path

import numpy as np
import torch
from zerotrust_fl.aggregators.native_cpp import CudaByzantineAggregator
from zerotrust_fl.client import grpc_worker
from zerotrust_fl.data import partition_dataset
from zerotrust_fl.engine.coordinator import _weighted_fedavg
from zerotrust_fl.engine.worker import WorkerResult
from zerotrust_fl.protocols import fl_service_pb2

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _worker_result(node_id: str, update: torch.Tensor, sample_count: int) -> WorkerResult:
    return WorkerResult(
        node_id=node_id,
        round_id=1,
        update=update,
        sample_count=sample_count,
        loss=0.1,
        gradient_norms=(0.1,),
        dynamic_epochs=1,
        training_duration_ms=1,
        simulated_latency_ms=0,
        malicious=False,
        attack_kind="none",
    )


def test_grpc_security_metadata_uses_unique_128_bit_nonces() -> None:
    first = grpc_worker._security_metadata(fl_service_pb2)
    second = grpc_worker._security_metadata(fl_service_pb2)

    assert first.issued_at_unix > 0
    assert len(first.nonce) == 16
    assert len(second.nonce) == 16
    assert first.nonce != second.nonce


def test_cuda_aggregation_validates_finite_values_by_default() -> None:
    parameter = inspect.signature(CudaByzantineAggregator).parameters["validate_finite"]
    assert parameter.default is True


def test_dirichlet_raw_strategy_is_explicit_and_deterministic() -> None:
    labels = np.repeat(np.arange(6), 100)
    first = partition_dataset(
        labels,
        8,
        strategy="dirichlet_raw",
        alpha=0.4,
        seed=77,
        min_samples_per_client=2,
    )
    second = partition_dataset(
        labels,
        8,
        strategy="dirichlet_raw",
        alpha=0.4,
        seed=77,
        min_samples_per_client=2,
    )

    assert all(np.array_equal(first[index], second[index]) for index in first)
    merged = np.concatenate(list(first.values()))
    assert merged.size == labels.size
    assert np.unique(merged).size == labels.size


def test_mean_aggregation_uses_sample_weighted_fedavg() -> None:
    result = _weighted_fedavg(
        [
            _worker_result("small", torch.tensor([1.0, 1.0]), 1),
            _worker_result("large", torch.tensor([3.0, 3.0]), 3),
        ]
    )
    torch.testing.assert_close(result, torch.tensor([2.5, 2.5]))


def test_compose_defaults_to_grpc_interoperable_development_identity() -> None:
    compose = (REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ZTFL_CERTIFICATE_ALGORITHM:-ecdsa-p256" in compose
    assert "ZTFL_CERTIFICATE_ALGORITHM:-ed25519" not in compose
