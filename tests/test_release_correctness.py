from __future__ import annotations

import importlib

import pytest
import torch
from torch import nn
from torch.nn.utils import parameters_to_vector
from torch.utils.data import TensorDataset

from zerotrust_fl.engine import (
    AggregationConfig,
    AsyncFederatedCoordinator,
    ModelSpec,
    SimulationConfig,
    WorkerConfig,
    WorkerSpec,
)


class _BufferedModel(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.linear = nn.Linear(2, 2)
        self.register_buffer("running_marker", torch.zeros(1))

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.linear(inputs)


def _dataset(sample_count: int) -> TensorDataset:
    features = torch.arange(sample_count * 2, dtype=torch.float32).reshape(sample_count, 2)
    labels = torch.arange(sample_count, dtype=torch.long) % 2
    return TensorDataset(features, labels)


def _workers(count: int) -> list[WorkerSpec]:
    return [
        WorkerSpec(
            config=WorkerConfig(node_id=f"release-worker-{index}"),
            sample_indices=(index,),
        )
        for index in range(count)
    ]


def _coordinator(
    *,
    worker_count: int,
    minimum: int,
    aggregation: AggregationConfig,
) -> AsyncFederatedCoordinator:
    return AsyncFederatedCoordinator(
        dataset=_dataset(worker_count),
        model_spec=ModelSpec(
            "zerotrust_fl.engine.models:mlp_classifier",
            {"input_shape": [2], "num_classes": 2, "hidden_dim": 4},
        ),
        workers=_workers(worker_count),
        simulation=SimulationConfig(
            rounds=1,
            clients_per_round=worker_count,
            min_results=minimum,
            round_timeout_seconds=5.0,
        ),
        aggregation=aggregation,
    )


def test_buffer_bearing_models_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    coordinator_module = importlib.import_module("zerotrust_fl.engine.coordinator")
    monkeypatch.setattr(coordinator_module, "build_model", lambda _spec: _BufferedModel())

    with pytest.raises(ValueError, match="registered buffers"):
        AsyncFederatedCoordinator(
            dataset=_dataset(1),
            model_spec=ModelSpec("unused:factory"),
            workers=_workers(1),
            simulation=SimulationConfig(rounds=1, clients_per_round=1, min_results=1),
        )


def test_parameter_delta_round_trip_is_exact() -> None:
    coordinator_module = importlib.import_module("zerotrust_fl.engine.coordinator")
    model = nn.Sequential(nn.Linear(2, 3), nn.ReLU(), nn.Linear(3, 2))
    before = parameters_to_vector(model.parameters()).detach().clone()
    delta = torch.linspace(-0.25, 0.25, steps=before.numel(), dtype=before.dtype)

    coordinator_module._apply_parameter_delta(model, delta)

    after = parameters_to_vector(model.parameters()).detach()
    torch.testing.assert_close(after, before + delta, rtol=0.0, atol=0.0)


def test_parameter_delta_rejects_broadcastable_wrong_length_without_mutation() -> None:
    coordinator_module = importlib.import_module("zerotrust_fl.engine.coordinator")
    model = nn.Linear(2, 2)
    before = parameters_to_vector(model.parameters()).detach().clone()

    with pytest.raises(ValueError, match="model expects"):
        coordinator_module._apply_parameter_delta(model, torch.tensor([1.0]))

    after = parameters_to_vector(model.parameters()).detach()
    torch.testing.assert_close(after, before, rtol=0.0, atol=0.0)


def test_parameter_delta_rejects_non_finite_values_without_mutation() -> None:
    coordinator_module = importlib.import_module("zerotrust_fl.engine.coordinator")
    model = nn.Linear(2, 2)
    before = parameters_to_vector(model.parameters()).detach().clone()
    delta = torch.zeros_like(before)
    delta[0] = float("nan")

    with pytest.raises(ValueError, match="non-finite"):
        coordinator_module._apply_parameter_delta(model, delta)

    after = parameters_to_vector(model.parameters()).detach()
    torch.testing.assert_close(after, before, rtol=0.0, atol=0.0)


def test_worker_global_parameter_loader_validates_rank_length_and_finiteness() -> None:
    worker_module = importlib.import_module("zerotrust_fl.engine.worker")
    model = nn.Linear(2, 2)
    expected = parameters_to_vector(model.parameters()).detach().clone()

    loaded = worker_module._load_global_parameters(
        model,
        expected,
        device=torch.device("cpu"),
    )
    torch.testing.assert_close(loaded, expected, rtol=0.0, atol=0.0)

    with pytest.raises(ValueError, match="one-dimensional"):
        worker_module._load_global_parameters(
            model,
            expected.reshape(2, -1),
            device=torch.device("cpu"),
        )

    with pytest.raises(ValueError, match="model expects"):
        worker_module._load_global_parameters(
            model,
            expected[:1],
            device=torch.device("cpu"),
        )

    invalid = expected.clone()
    invalid[0] = float("inf")
    with pytest.raises(ValueError, match="non-finite"):
        worker_module._load_global_parameters(
            model,
            invalid,
            device=torch.device("cpu"),
        )


@pytest.mark.parametrize(
    ("method", "worker_count", "minimum", "f", "k"),
    [
        ("krum", 5, 5, 1, 1),
        ("multi_krum", 5, 5, 1, 2),
        ("krum", 7, 7, 2, 1),
        ("multi_krum", 7, 7, 2, 3),
    ],
)
def test_valid_krum_population_matrix_is_accepted(
    method: str,
    worker_count: int,
    minimum: int,
    f: int,
    k: int,
) -> None:
    coordinator = _coordinator(
        worker_count=worker_count,
        minimum=minimum,
        aggregation=AggregationConfig(method=method, backend="torch", f=f, k=k),
    )
    assert coordinator.processes_alive == 0


@pytest.mark.parametrize(
    ("method", "worker_count", "minimum", "f", "k", "message"),
    [
        ("krum", 5, 4, 1, 1, "Krum requires"),
        ("multi_krum", 5, 4, 1, 1, "Krum requires"),
        ("krum", 7, 6, 2, 1, "Krum requires"),
        ("multi_krum", 5, 5, 1, 3, "Multi-Krum k"),
        ("multi_krum", 7, 7, 2, 4, "Multi-Krum k"),
    ],
)
def test_invalid_krum_population_matrix_fails_before_process_start(
    method: str,
    worker_count: int,
    minimum: int,
    f: int,
    k: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _coordinator(
            worker_count=worker_count,
            minimum=minimum,
            aggregation=AggregationConfig(method=method, backend="torch", f=f, k=k),
        )
