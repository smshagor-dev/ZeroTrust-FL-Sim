from __future__ import annotations

import inspect

import numpy as np
import torch
from zerotrust_fl.aggregators.native_cpp import CudaByzantineAggregator
from zerotrust_fl.client.grpc_worker import _security_metadata
from zerotrust_fl.data import partition_dataset
from zerotrust_fl.engine.coordinator import _weighted_fedavg
from zerotrust_fl.engine.worker import WorkerResult
from zerotrust_fl.protocols import fl_service_pb2


def _result(update: torch.Tensor, sample_count: int) -> WorkerResult:
    return WorkerResult(
        node_id=f"worker-{sample_count}",
        round_id=1,
        update=update,
        sample_count=sample_count,
        loss=0.1,
        gradient_norms=(1.0,),
        dynamic_epochs=1,
        training_duration_ms=1,
        simulated_latency_ms=0,
        malicious=False,
        attack_kind="none",
    )


def test_fedavg_is_sample_weighted() -> None:
    aggregate = _weighted_fedavg(
        [
            _result(torch.tensor([0.0, 2.0]), 1),
            _result(torch.tensor([4.0, 6.0]), 3),
        ]
    )
    torch.testing.assert_close(aggregate, torch.tensor([3.0, 5.0]))


def test_dirichlet_raw_is_explicit_and_exact() -> None:
    labels = np.repeat(np.arange(5), 100)
    raw = partition_dataset(
        labels,
        8,
        strategy="dirichlet_raw",
        alpha=0.3,
        seed=17,
        min_samples_per_client=1,
    )
    balanced = partition_dataset(
        labels,
        8,
        strategy="dirichlet_balanced",
        alpha=0.3,
        seed=17,
        min_samples_per_client=1,
    )

    raw_merged = np.concatenate(list(raw.values()))
    assert raw_merged.size == labels.size
    assert np.unique(raw_merged).size == labels.size
    assert any(not np.array_equal(raw[index], balanced[index]) for index in raw)


def test_security_metadata_uses_fresh_random_nonce() -> None:
    first = _security_metadata(fl_service_pb2)
    second = _security_metadata(fl_service_pb2)

    assert len(first.nonce) >= 16
    assert len(second.nonce) >= 16
    assert first.nonce != second.nonce
    assert first.issued_at_unix > 0


def test_cuda_finite_validation_is_fail_closed_by_default() -> None:
    parameter = inspect.signature(CudaByzantineAggregator).parameters["validate_finite"]
    assert parameter.default is True
