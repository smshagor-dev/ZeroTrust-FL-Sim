"""Observable wrapper around the local asynchronous FL coordinator."""

from __future__ import annotations

import time
from typing import Any

import psutil
import torch

from zerotrust_fl.engine import AsyncFederatedCoordinator
from zerotrust_fl.observability.telemetry import TelemetryRuntime


class ObservableAsyncFederatedCoordinator(AsyncFederatedCoordinator):
    """Publish round, aggregation, memory, churn, and mitigation telemetry live."""

    def __init__(self, *args: Any, telemetry: TelemetryRuntime, **kwargs: Any) -> None:
        self.telemetry = telemetry
        super().__init__(*args, **kwargs)

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        with self.telemetry.span("fl.simulation.round", {"fl.round.id": round_id}) as span:
            metrics = super()._run_round(round_id)
            span.set_attribute("fl.round.completed_clients", len(metrics.completed_clients))
            span.set_attribute("fl.round.failed_clients", len(metrics.failed_clients))
            span.set_attribute("fl.round.straggler_clients", len(metrics.straggler_clients))
            span.set_attribute("fl.round.malicious_results", metrics.malicious_results)
            if metrics.mitigation_score is not None:
                span.set_attribute("fl.poisoning.mitigation_score", metrics.mitigation_score)
        self.telemetry.record_round(metrics)
        return metrics

    def _aggregate(self, updates: list[torch.Tensor]) -> tuple[torch.Tensor, str]:
        process = psutil.Process()
        cpu_before = process.memory_info().rss
        gpu_before = 0
        if torch.cuda.is_available():
            gpu_before = int(torch.cuda.memory_allocated())
            torch.cuda.reset_peak_memory_stats()

        started = time.perf_counter()
        with self.telemetry.span(
            "fl.aggregation",
            {
                "fl.aggregation.method": self.aggregation.method,
                "fl.aggregation.update_count": len(updates),
            },
        ) as span:
            result, backend = super()._aggregate(updates)
            span.set_attribute("fl.aggregation.backend", backend)
        duration = time.perf_counter() - started

        cpu_after = process.memory_info().rss
        gpu_peak_delta = 0
        if torch.cuda.is_available():
            gpu_peak_delta = max(0, int(torch.cuda.max_memory_allocated()) - gpu_before)

        self.telemetry.record_aggregation(
            backend=backend,
            method=self.aggregation.method,
            duration_seconds=duration,
            cpu_memory_delta_bytes=max(0, cpu_after - cpu_before),
            gpu_peak_delta_bytes=gpu_peak_delta,
        )
        return result, backend
