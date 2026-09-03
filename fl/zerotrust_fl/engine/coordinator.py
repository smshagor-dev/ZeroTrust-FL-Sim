"""Asynchronous multi-process federated learning simulation coordinator."""

from __future__ import annotations

import math
import multiprocessing as mp
import queue
import time
from dataclasses import dataclass
from typing import Literal

import numpy as np
import torch
from torch import nn
from torch.nn.utils import parameters_to_vector, vector_to_parameters
from torch.utils.data import DataLoader, Dataset

from zerotrust_fl.aggregators.native_cpp import (
    CppByzantineAggregator,
    native_extension_available,
)
from zerotrust_fl.engine.worker import (
    ModelSpec,
    StopCommand,
    TrainCommand,
    WorkerResult,
    WorkerSpec,
    build_model,
    worker_process_main,
)

AggregationMethod = Literal["mean", "krum", "multi_krum", "trimmed_mean", "median"]
AggregationBackend = Literal["auto", "native", "torch"]


@dataclass(frozen=True, slots=True)
class AggregationConfig:
    method: AggregationMethod = "median"
    backend: AggregationBackend = "auto"
    f: int = 0
    k: int = 1
    beta: float = 0.1

    def __post_init__(self) -> None:
        if self.method not in {"mean", "krum", "multi_krum", "trimmed_mean", "median"}:
            raise ValueError(f"unsupported aggregation method: {self.method!r}")
        if self.backend not in {"auto", "native", "torch"}:
            raise ValueError(f"unsupported aggregation backend: {self.backend!r}")
        if self.f < 0:
            raise ValueError("f cannot be negative")
        if self.k <= 0:
            raise ValueError("k must be positive")
        if not 0.0 <= self.beta < 0.5:
            raise ValueError("beta must be in [0, 0.5)")


@dataclass(frozen=True, slots=True)
class SimulationConfig:
    rounds: int = 5
    clients_per_round: int | None = None
    client_fraction: float = 1.0
    min_results: int | None = None
    round_timeout_seconds: float = 120.0
    start_method: str = "spawn"
    seed: int = 42
    evaluation_batch_size: int = 256
    evaluation_device: str = "cpu"

    def __post_init__(self) -> None:
        if self.rounds <= 0:
            raise ValueError("rounds must be positive")
        if self.clients_per_round is not None and self.clients_per_round <= 0:
            raise ValueError("clients_per_round must be positive")
        if not 0.0 < self.client_fraction <= 1.0:
            raise ValueError("client_fraction must be in (0, 1]")
        if self.min_results is not None and self.min_results <= 0:
            raise ValueError("min_results must be positive")
        if self.round_timeout_seconds <= 0:
            raise ValueError("round_timeout_seconds must be positive")
        if self.evaluation_batch_size <= 0:
            raise ValueError("evaluation_batch_size must be positive")


@dataclass(frozen=True, slots=True)
class RoundMetrics:
    round_id: int
    selected_clients: tuple[str, ...]
    completed_clients: tuple[str, ...]
    failed_clients: tuple[str, ...]
    straggler_clients: tuple[str, ...]
    malicious_results: int
    aggregation_backend: str
    aggregation_method: str
    mean_client_loss: float
    evaluation_loss: float | None
    evaluation_accuracy: float | None
    mitigation_score: float | None
    attack_mitigated: bool | None
    round_duration_ms: int


@dataclass(frozen=True, slots=True)
class SimulationSummary:
    rounds: tuple[RoundMetrics, ...]
    attack_mitigation_success_rate: float | None

    @property
    def final_accuracy(self) -> float | None:
        return self.rounds[-1].evaluation_accuracy if self.rounds else None

    @property
    def final_loss(self) -> float | None:
        return self.rounds[-1].evaluation_loss if self.rounds else None


class AsyncFederatedCoordinator:
    """Orchestrate persistent worker processes and asynchronous round completion."""

    def __init__(
        self,
        *,
        dataset: Dataset,
        model_spec: ModelSpec,
        workers: list[WorkerSpec] | tuple[WorkerSpec, ...],
        simulation: SimulationConfig | None = None,
        aggregation: AggregationConfig | None = None,
        evaluation_dataset: Dataset | None = None,
    ) -> None:
        if not workers:
            raise ValueError("at least one worker is required")

        self.dataset = dataset
        self.model_spec = model_spec
        self.worker_specs = tuple(workers)
        self.simulation = simulation or SimulationConfig()
        self.aggregation = aggregation or AggregationConfig()
        self.evaluation_dataset = evaluation_dataset

        node_ids = [spec.config.node_id for spec in self.worker_specs]
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("worker node IDs must be unique")
        if any(len(spec.sample_indices) == 0 for spec in self.worker_specs):
            raise ValueError("every worker must own at least one sample")

        self.model = build_model(model_spec).to("cpu")
        self._validate_round_counts()

        self._ctx: mp.context.BaseContext | None = None
        self._result_queue = None
        self._command_queues: dict[str, object] = {}
        self._processes: dict[str, mp.Process] = {}
        self._busy_round: dict[str, int] = {}
        self._started = False
        self._closed = False

    @property
    def processes_alive(self) -> int:
        return sum(1 for process in self._processes.values() if process.is_alive())

    def start(self) -> None:
        if self._closed:
            raise RuntimeError("coordinator has already been closed")
        if self._started:
            return

        self._ctx = mp.get_context(self.simulation.start_method)
        self._result_queue = self._ctx.Queue()

        for worker_spec in self.worker_specs:
            node_id = worker_spec.config.node_id
            command_queue = self._ctx.Queue(maxsize=1)
            process = self._ctx.Process(
                target=worker_process_main,
                name=f"ztfl-{node_id}",
                args=(
                    worker_spec.config,
                    self.model_spec,
                    self.dataset,
                    worker_spec.sample_indices,
                    command_queue,
                    self._result_queue,
                ),
            )
            process.daemon = False
            process.start()
            self._command_queues[node_id] = command_queue
            self._processes[node_id] = process

        self._started = True

    def close(self, *, grace_seconds: float = 5.0) -> None:
        if self._closed:
            return

        for command_queue in self._command_queues.values():
            try:
                command_queue.put_nowait(StopCommand())
            except queue.Full:
                pass

        deadline = time.monotonic() + max(0.0, grace_seconds)
        for process in self._processes.values():
            remaining = max(0.0, deadline - time.monotonic())
            process.join(timeout=remaining)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)

        for command_queue in self._command_queues.values():
            try:
                command_queue.close()
                command_queue.join_thread()
            except (AttributeError, OSError):
                pass
        if self._result_queue is not None:
            try:
                self._result_queue.close()
                self._result_queue.join_thread()
            except (AttributeError, OSError):
                pass

        self._busy_round.clear()
        self._closed = True

    def run(self) -> SimulationSummary:
        """Run configured FL rounds and always shut down worker processes."""

        self.start()
        history: list[RoundMetrics] = []
        try:
            for round_id in range(1, self.simulation.rounds + 1):
                history.append(self._run_round(round_id))
        finally:
            self.close()

        attacked = [
            metrics.attack_mitigated
            for metrics in history
            if metrics.attack_mitigated is not None
        ]
        success_rate = (
            float(sum(bool(value) for value in attacked) / len(attacked))
            if attacked
            else None
        )
        return SimulationSummary(
            rounds=tuple(history),
            attack_mitigation_success_rate=success_rate,
        )

    def _run_round(self, round_id: int) -> RoundMetrics:
        started = time.perf_counter()
        self._drain_completed_results()
        selected = self._select_clients(round_id)

        global_parameters = parameters_to_vector(self.model.parameters()).detach().cpu().float()
        for node_id in selected:
            self._command_queues[node_id].put(
                TrainCommand(
                    round_id=round_id,
                    global_parameters=global_parameters,
                )
            )
            self._busy_round[node_id] = round_id

        min_results = self._min_results_for(len(selected))
        results, failures = self._collect_round_results(
            round_id=round_id,
            selected=set(selected),
            min_results=min_results,
            timeout=self.simulation.round_timeout_seconds,
        )

        if len(results) < min_results:
            failed_names = ", ".join(failures) if failures else "none"
            raise TimeoutError(
                f"round {round_id} received {len(results)}/{min_results} required "
                f"successful results; failures={failed_names}"
            )

        updates = [result.update for result in results if result.update is not None]
        aggregated, backend_used = self._aggregate(updates)
        current = parameters_to_vector(self.model.parameters()).detach()
        vector_to_parameters(
            current + aggregated.to(dtype=current.dtype, device=current.device),
            self.model.parameters(),
        )

        evaluation_loss, evaluation_accuracy = self._evaluate()
        mitigation_score, attack_mitigated = _attack_mitigation_metrics(
            results,
            aggregated,
        )

        completed = tuple(result.node_id for result in results)
        failed = tuple(sorted(failures))
        stragglers = tuple(
            sorted(
                node_id
                for node_id in selected
                if node_id not in set(completed) | set(failed)
            )
        )
        mean_loss = float(np.mean([result.loss for result in results]))
        malicious_results = sum(result.malicious for result in results)

        return RoundMetrics(
            round_id=round_id,
            selected_clients=tuple(selected),
            completed_clients=completed,
            failed_clients=failed,
            straggler_clients=stragglers,
            malicious_results=int(malicious_results),
            aggregation_backend=backend_used,
            aggregation_method=self.aggregation.method,
            mean_client_loss=mean_loss,
            evaluation_loss=evaluation_loss,
            evaluation_accuracy=evaluation_accuracy,
            mitigation_score=mitigation_score,
            attack_mitigated=attack_mitigated,
            round_duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _collect_round_results(
        self,
        *,
        round_id: int,
        selected: set[str],
        min_results: int,
        timeout: float,
    ) -> tuple[list[WorkerResult], set[str]]:
        assert self._result_queue is not None
        deadline = time.monotonic() + timeout
        results: list[WorkerResult] = []
        failures: set[str] = set()
        observed: set[str] = set()

        while time.monotonic() < deadline and len(observed) < len(selected):
            remaining = max(0.001, deadline - time.monotonic())
            try:
                result: WorkerResult = self._result_queue.get(
                    timeout=min(0.25, remaining)
                )
            except queue.Empty:
                self._raise_if_required_workers_died(selected, observed)
                continue

            self._busy_round.pop(result.node_id, None)

            if result.round_id != round_id or result.node_id not in selected:
                continue
            if result.node_id in observed:
                continue

            observed.add(result.node_id)
            if result.succeeded:
                results.append(result)
            else:
                failures.add(result.node_id)

            if len(results) >= min_results:
                break
            if len(results) + (len(selected) - len(observed)) < min_results:
                break

        return results, failures

    def _drain_completed_results(self) -> None:
        if self._result_queue is None:
            return
        while True:
            try:
                result: WorkerResult = self._result_queue.get_nowait()
            except queue.Empty:
                return
            self._busy_round.pop(result.node_id, None)

    def _select_clients(self, round_id: int) -> list[str]:
        required = self._clients_per_round()
        available = self._wait_for_available(
            required,
            timeout=self.simulation.round_timeout_seconds,
        )

        rng = np.random.default_rng(self.simulation.seed + round_id * 65_537)
        chosen = rng.choice(np.asarray(available, dtype=object), size=required, replace=False)
        return [str(value) for value in chosen.tolist()]

    def _wait_for_available(
        self,
        required: int,
        *,
        timeout: float,
    ) -> list[str]:
        deadline = time.monotonic() + timeout
        while True:
            self._drain_completed_results()
            available = [
                spec.config.node_id
                for spec in self.worker_specs
                if spec.config.node_id not in self._busy_round
                and self._processes[spec.config.node_id].is_alive()
            ]
            if len(available) >= required:
                return available
            dead = [
                spec.config.node_id
                for spec in self.worker_specs
                if not self._processes[spec.config.node_id].is_alive()
            ]
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"only {len(available)} workers became available, but {required} "
                    f"are required; dead={dead}, busy={sorted(self._busy_round)}"
                )
            time.sleep(0.01)

    def _aggregate(
        self,
        updates: list[torch.Tensor],
    ) -> tuple[torch.Tensor, str]:
        if not updates:
            raise ValueError("cannot aggregate an empty update list")

        method = self.aggregation.method
        backend = self.aggregation.backend

        if method == "mean":
            return torch.stack(updates).mean(dim=0), "torch"

        use_native = backend == "native" or (
            backend == "auto" and native_extension_available()
        )
        if backend == "native" and not native_extension_available():
            raise RuntimeError(
                "native aggregation backend requested but zerotrust_fl_cpp is unavailable"
            )

        if use_native:
            native = CppByzantineAggregator(
                preserve_device=False,
                preserve_dtype=False,
            )
            result = native.aggregate(
                updates,
                method=method,
                f=self.aggregation.f,
                k=self.aggregation.k,
                beta=self.aggregation.beta,
            )
            return result.cpu().float(), "native"

        return _torch_aggregate(updates, self.aggregation), "torch"

    def _evaluate(self) -> tuple[float | None, float | None]:
        if self.evaluation_dataset is None:
            return None, None

        device = torch.device(self.simulation.evaluation_device)
        self.model.to(device)
        self.model.eval()
        criterion = nn.CrossEntropyLoss(reduction="sum")
        loader = DataLoader(
            self.evaluation_dataset,
            batch_size=self.simulation.evaluation_batch_size,
            shuffle=False,
            num_workers=0,
        )

        total_loss = 0.0
        total_correct = 0
        total_examples = 0
        with torch.no_grad():
            for batch in loader:
                if not isinstance(batch, (tuple, list)) or len(batch) < 2:
                    raise TypeError("evaluation dataset must return (inputs, labels)")
                inputs = batch[0].to(device)
                labels = batch[1].to(device=device, dtype=torch.long)
                logits = self.model(inputs)
                total_loss += float(criterion(logits, labels).cpu())
                total_correct += int(logits.argmax(dim=1).eq(labels).sum().cpu())
                total_examples += int(labels.shape[0])

        self.model.to("cpu")
        if total_examples == 0:
            return math.nan, math.nan
        return total_loss / total_examples, total_correct / total_examples

    def _clients_per_round(self) -> int:
        total = len(self.worker_specs)
        if self.simulation.clients_per_round is not None:
            return min(total, self.simulation.clients_per_round)
        return max(1, int(math.ceil(total * self.simulation.client_fraction)))

    def _min_results_for(self, selected_count: int) -> int:
        configured = self.simulation.min_results
        if configured is None:
            return selected_count
        if configured > selected_count:
            raise ValueError("min_results cannot exceed clients selected per round")
        return configured

    def _validate_round_counts(self) -> None:
        selected = self._clients_per_round()
        minimum = self._min_results_for(selected)

        if self.aggregation.method in {"krum", "multi_krum"}:
            if minimum < 2 * self.aggregation.f + 3:
                raise ValueError("Krum requires min_results >= 2*f + 3")
            neighbor_count = minimum - self.aggregation.f - 2
            k = 1 if self.aggregation.method == "krum" else self.aggregation.k
            if k > neighbor_count:
                raise ValueError(
                    "Multi-Krum k cannot exceed clients_per_round - f - 2"
                )

        if self.aggregation.method == "trimmed_mean":
            trim = int(math.floor(self.aggregation.beta * minimum))
            if 2 * trim >= minimum:
                raise ValueError("trimmed mean would remove every client update")

    def _raise_if_required_workers_died(
        self,
        selected: set[str],
        observed: set[str],
    ) -> None:
        dead = [
            node_id
            for node_id in selected - observed
            if not self._processes[node_id].is_alive()
        ]
        if dead:
            raise RuntimeError(
                "worker process exited before returning a result: " + ", ".join(dead)
            )


def _torch_aggregate(
    updates: list[torch.Tensor],
    config: AggregationConfig,
) -> torch.Tensor:
    stacked = torch.stack([update.detach().cpu().float() for update in updates])
    if not torch.isfinite(stacked).all():
        raise ValueError("aggregation input contains non-finite values")

    if config.method == "median":
        sorted_values, _ = torch.sort(stacked, dim=0)
        count = sorted_values.shape[0]
        middle = count // 2
        if count % 2:
            return sorted_values[middle]
        return (sorted_values[middle - 1] + sorted_values[middle]) * 0.5

    if config.method == "trimmed_mean":
        trim = int(math.floor(config.beta * stacked.shape[0]))
        if 2 * trim >= stacked.shape[0]:
            raise ValueError("trimmed mean would remove every update")
        sorted_values, _ = torch.sort(stacked, dim=0)
        selected = sorted_values[trim:-trim] if trim > 0 else sorted_values
        return selected.mean(dim=0)

    if config.method in {"krum", "multi_krum"}:
        count = stacked.shape[0]
        if count < 2 * config.f + 3:
            raise ValueError("Krum requires n >= 2*f + 3")
        flat = stacked.reshape(count, -1).double()
        distances = torch.cdist(flat, flat, p=2).pow(2)
        neighbor_count = count - config.f - 2
        scores = torch.empty(count, dtype=torch.float64)
        for index in range(count):
            row = torch.cat((distances[index, :index], distances[index, index + 1 :]))
            scores[index] = torch.topk(
                row,
                k=neighbor_count,
                largest=False,
                sorted=False,
            ).values.sum()
        k = 1 if config.method == "krum" else config.k
        selected_indices = torch.topk(
            scores,
            k=k,
            largest=False,
            sorted=True,
        ).indices
        return stacked[selected_indices].mean(dim=0)

    if config.method == "mean":
        return stacked.mean(dim=0)

    raise ValueError(f"unsupported aggregation method: {config.method!r}")


def _attack_mitigation_metrics(
    results: list[WorkerResult],
    robust_update: torch.Tensor,
) -> tuple[float | None, bool | None]:
    malicious = [result for result in results if result.malicious and result.update is not None]
    benign = [result for result in results if not result.malicious and result.update is not None]
    if not malicious or not benign:
        return None, None

    benign_mean = torch.stack([result.update for result in benign]).mean(dim=0)
    naive_mean = torch.stack(
        [result.update for result in results if result.update is not None]
    ).mean(dim=0)

    robust_error = float(torch.linalg.vector_norm(robust_update - benign_mean))
    naive_error = float(torch.linalg.vector_norm(naive_mean - benign_mean))
    if naive_error <= 1e-12:
        return (1.0 if robust_error <= 1e-12 else 0.0), robust_error <= 1e-12

    score = max(0.0, min(1.0, 1.0 - robust_error / naive_error))
    return score, robust_error < naive_error
