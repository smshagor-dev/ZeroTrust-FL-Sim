"""Persistent multiprocessing workers for local PyTorch training."""

from __future__ import annotations

import importlib
import random
import time
import traceback
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.nn.utils import parameters_to_vector, vector_to_parameters
from torch.utils.data import DataLoader, Dataset, Subset

from zerotrust_fl.attacks.poisoning import AttackConfig, PoisoningAttack
from zerotrust_fl.privacy.rdp import LocalDPConfig, protect_model_update


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """Serializable model factory reference for spawn-based multiprocessing."""

    factory_path: str
    kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    node_id: str
    batch_size: int = 64
    local_epochs_min: int = 1
    local_epochs_max: int = 1
    learning_rate: float = 0.01
    learning_rate_jitter: float = 0.0
    optimizer: str = "sgd"
    optimizer_kwargs: dict[str, Any] = field(default_factory=dict)
    device: str = "cpu"
    compute_delay_seconds: tuple[float, float] = (0.0, 0.0)
    network_delay_seconds: tuple[float, float] = (0.0, 0.0)
    max_grad_norm: float | None = None
    torch_num_threads: int = 1
    seed: int = 42
    malicious: bool = False
    attack: AttackConfig = field(default_factory=AttackConfig)
    local_dp: LocalDPConfig = field(default_factory=LocalDPConfig)

    def __post_init__(self) -> None:
        if not self.node_id.strip():
            raise ValueError("node_id is required")
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.local_epochs_min <= 0 or self.local_epochs_max < self.local_epochs_min:
            raise ValueError("local epoch range is invalid")
        if self.learning_rate <= 0:
            raise ValueError("learning_rate must be positive")
        if self.learning_rate_jitter < 0:
            raise ValueError("learning_rate_jitter cannot be negative")
        if self.optimizer.lower() not in {"sgd", "adam"}:
            raise ValueError("optimizer must be 'sgd' or 'adam'")
        _validate_delay_range(self.compute_delay_seconds, "compute_delay_seconds")
        _validate_delay_range(self.network_delay_seconds, "network_delay_seconds")
        if self.max_grad_norm is not None and self.max_grad_norm <= 0:
            raise ValueError("max_grad_norm must be positive")
        if self.torch_num_threads <= 0:
            raise ValueError("torch_num_threads must be positive")


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    """Coordinator-side description of one persistent worker process."""

    config: WorkerConfig
    sample_indices: tuple[int, ...]


@dataclass(slots=True)
class TrainCommand:
    round_id: int
    global_parameters: torch.Tensor


@dataclass(frozen=True, slots=True)
class StopCommand:
    pass


@dataclass(slots=True)
class WorkerResult:
    node_id: str
    round_id: int
    update: torch.Tensor | None
    sample_count: int
    loss: float
    gradient_norms: tuple[float, ...]
    dynamic_epochs: int
    training_duration_ms: int
    simulated_latency_ms: int
    malicious: bool
    attack_kind: str
    dp_original_norm: float | None = None
    dp_clipped_norm: float | None = None
    dp_noise_std: float | None = None
    dp_epsilon_per_release: float | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.update is not None


def worker_process_main(
    config: WorkerConfig,
    model_spec: ModelSpec,
    dataset: Dataset,
    sample_indices: tuple[int, ...],
    command_queue: Any,
    result_queue: Any,
) -> None:
    """Process entry point. A worker remains alive across training rounds."""

    torch.set_num_threads(config.torch_num_threads)
    _seed_everything(config.seed)

    device = torch.device(config.device)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError(f"worker {config.node_id}: CUDA device requested but unavailable")

    model = build_model(model_spec).to(device)
    subset = Subset(dataset, list(sample_indices))
    attack = PoisoningAttack(config.attack)

    while True:
        command = command_queue.get()
        if isinstance(command, StopCommand):
            return
        if not isinstance(command, TrainCommand):
            continue

        try:
            result = _execute_training_round(
                config=config,
                model=model,
                subset=subset,
                attack=attack,
                command=command,
                device=device,
            )
        except BaseException as exc:
            result = WorkerResult(
                node_id=config.node_id,
                round_id=command.round_id,
                update=None,
                sample_count=len(subset),
                loss=float("nan"),
                gradient_norms=(),
                dynamic_epochs=0,
                training_duration_ms=0,
                simulated_latency_ms=0,
                malicious=config.malicious,
                attack_kind=config.attack.kind if config.malicious else "none",
                error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=8)}",
            )
        result_queue.put(result)


def build_model(spec: ModelSpec) -> nn.Module:
    module_name, separator, attribute = spec.factory_path.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("model factory path must use 'module.submodule:function' format")
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute)
    model = factory(**spec.kwargs)
    if not isinstance(model, nn.Module):
        raise TypeError("model factory must return torch.nn.Module")
    return model


def _execute_training_round(
    *,
    config: WorkerConfig,
    model: nn.Module,
    subset: Dataset,
    attack: PoisoningAttack,
    command: TrainCommand,
    device: torch.device,
) -> WorkerResult:
    round_seed = config.seed + command.round_id * 100_003
    rng = np.random.default_rng(round_seed)
    torch.manual_seed(round_seed)

    global_parameters = command.global_parameters.detach().to(
        device=device,
        dtype=torch.float32,
    )
    expected_parameters = parameters_to_vector(model.parameters())
    if global_parameters.numel() != expected_parameters.numel():
        raise ValueError(
            f"global parameter vector has {global_parameters.numel()} values; "
            f"model expects {expected_parameters.numel()}"
        )
    vector_to_parameters(global_parameters, model.parameters())

    dynamic_epochs = int(
        rng.integers(config.local_epochs_min, config.local_epochs_max + 1)
    )
    jitter = rng.uniform(-config.learning_rate_jitter, config.learning_rate_jitter)
    local_lr = config.learning_rate * max(1e-6, 1.0 + jitter)

    generator = torch.Generator()
    generator.manual_seed(round_seed)
    loader = DataLoader(
        subset,
        batch_size=config.batch_size,
        shuffle=True,
        num_workers=0,
        generator=generator,
        drop_last=False,
    )
    optimizer = _make_optimizer(model, config, local_lr)
    criterion = nn.CrossEntropyLoss()

    pre_network = _sample_delay(rng, config.network_delay_seconds)
    compute_delay = _sample_delay(rng, config.compute_delay_seconds)
    if pre_network:
        time.sleep(pre_network)

    started = time.perf_counter()
    epoch_gradient_norms: list[float] = []
    total_loss = 0.0
    total_examples = 0
    batch_id = 0

    model.train()
    for _epoch in range(dynamic_epochs):
        epoch_norm_sum = 0.0
        epoch_batches = 0
        for batch in loader:
            if not isinstance(batch, (tuple, list)) or len(batch) < 2:
                raise TypeError("training dataset must return (inputs, labels)")

            inputs = batch[0].to(device)
            labels = batch[1].to(device=device, dtype=torch.long)
            if config.malicious and attack.attacks_labels:
                labels = attack.transform_labels(
                    labels,
                    round_id=command.round_id,
                    batch_id=batch_id,
                )

            optimizer.zero_grad(set_to_none=True)
            logits = model(inputs)
            loss = criterion(logits, labels)
            if not torch.isfinite(loss):
                raise FloatingPointError("local training produced non-finite loss")
            loss.backward()

            grad_norm = _gradient_norm(model)
            if config.max_grad_norm is not None:
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.max_grad_norm)
            optimizer.step()

            count = int(labels.shape[0])
            total_loss += float(loss.detach().cpu()) * count
            total_examples += count
            epoch_norm_sum += grad_norm
            epoch_batches += 1
            batch_id += 1

        epoch_gradient_norms.append(epoch_norm_sum / max(1, epoch_batches))

    if compute_delay:
        time.sleep(compute_delay)

    local_parameters = parameters_to_vector(model.parameters()).detach().to(
        device="cpu",
        dtype=torch.float32,
    )
    baseline = command.global_parameters.detach().to(device="cpu", dtype=torch.float32)
    update = local_parameters - baseline

    if config.malicious and attack.attacks_updates:
        update = attack.transform_update(update, round_id=command.round_id)

    if not torch.isfinite(update).all():
        raise FloatingPointError("worker produced a non-finite model update")

    protected = protect_model_update(
        update,
        config.local_dp,
        seed=round_seed + 47_117,
    )
    update = protected.update

    training_duration_ms = int((time.perf_counter() - started) * 1000)
    post_network = _sample_delay(rng, config.network_delay_seconds)
    if post_network:
        time.sleep(post_network)

    return WorkerResult(
        node_id=config.node_id,
        round_id=command.round_id,
        update=update.contiguous(),
        sample_count=len(subset),
        loss=total_loss / max(1, total_examples),
        gradient_norms=tuple(float(value) for value in epoch_gradient_norms),
        dynamic_epochs=dynamic_epochs,
        training_duration_ms=training_duration_ms,
        simulated_latency_ms=int((pre_network + compute_delay + post_network) * 1000),
        malicious=config.malicious,
        attack_kind=config.attack.kind if config.malicious else "none",
        dp_original_norm=protected.original_norm if config.local_dp.enabled else None,
        dp_clipped_norm=protected.clipped_norm if config.local_dp.enabled else None,
        dp_noise_std=protected.noise_std if config.local_dp.enabled else None,
        dp_epsilon_per_release=(
            protected.epsilon_per_release if config.local_dp.enabled else None
        ),
    )


def _make_optimizer(
    model: nn.Module,
    config: WorkerConfig,
    learning_rate: float,
) -> torch.optim.Optimizer:
    kwargs = dict(config.optimizer_kwargs)
    if config.optimizer.lower() == "sgd":
        return torch.optim.SGD(model.parameters(), lr=learning_rate, **kwargs)
    if config.optimizer.lower() == "adam":
        return torch.optim.Adam(model.parameters(), lr=learning_rate, **kwargs)
    raise RuntimeError(f"unsupported optimizer: {config.optimizer!r}")


def _gradient_norm(model: nn.Module) -> float:
    squared = torch.zeros((), dtype=torch.float64)
    for parameter in model.parameters():
        if parameter.grad is not None:
            grad = parameter.grad.detach()
            squared += grad.double().pow(2).sum().cpu()
    return float(torch.sqrt(squared))


def _sample_delay(
    rng: np.random.Generator,
    delay_range: tuple[float, float],
) -> float:
    low, high = delay_range
    if high == 0:
        return 0.0
    return float(rng.uniform(low, high))


def _validate_delay_range(value: tuple[float, float], name: str) -> None:
    if len(value) != 2:
        raise ValueError(f"{name} must be a two-value range")
    low, high = value
    if low < 0 or high < low:
        raise ValueError(f"{name} must satisfy 0 <= min <= max")


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed % (2**32 - 1))
    torch.manual_seed(seed)
