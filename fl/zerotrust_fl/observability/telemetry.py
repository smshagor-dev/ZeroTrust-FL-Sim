"""Runtime tracing and Prometheus instrumentation.

Tracing is exported through OTLP/gRPC when an endpoint is configured. Metrics
use the official Prometheus Python client and expose a scrape endpoint.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator, Mapping
from typing import Any

import psutil
import torch
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)


class TelemetryRuntime:
    """Own tracing and metrics for one coordinator/simulator/worker process."""

    def __init__(
        self,
        *,
        service_name: str,
        instance_id: str,
        metrics_host: str = "0.0.0.0",
        metrics_port: int = 0,
        otlp_endpoint: str = "",
        otlp_insecure: bool = True,
    ) -> None:
        self.service_name = service_name
        self.instance_id = instance_id
        self.registry = CollectorRegistry(auto_describe=True)
        self._grpc_instrumented = False
        self._server = None
        self._server_thread = None
        self._attacked_rounds = 0
        self._mitigated_rounds = 0
        self._lock = threading.Lock()

        resource = Resource.create(
            {
                "service.name": service_name,
                "service.instance.id": instance_id,
                "service.namespace": "zerotrust-fl-sim",
            }
        )
        self.tracer_provider = TracerProvider(resource=resource)
        if otlp_endpoint:
            exporter = OTLPSpanExporter(
                endpoint=otlp_endpoint,
                insecure=otlp_insecure,
            )
            self.tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
        self.tracer = self.tracer_provider.get_tracer("zerotrust_fl.observability")

        common = ["service", "instance"]
        self.epoch_time = Histogram(
            "ztfl_epoch_duration_seconds",
            "Local training epoch/update duration in seconds.",
            common,
            registry=self.registry,
        )
        self.network_latency = Histogram(
            "ztfl_network_latency_seconds",
            "Client-observed gRPC round-trip latency in seconds.",
            [*common, "rpc"],
            registry=self.registry,
        )
        self.process_rss = Gauge(
            "ztfl_process_resident_memory_bytes",
            "Current process resident memory in bytes.",
            common,
            registry=self.registry,
        )
        self.gpu_memory = Gauge(
            "ztfl_gpu_memory_bytes",
            "Current CUDA memory allocated by this process in bytes.",
            common,
            registry=self.registry,
        )
        self.aggregation_time = Histogram(
            "ztfl_aggregation_duration_seconds",
            "Robust aggregation duration in seconds.",
            [*common, "backend", "method"],
            registry=self.registry,
        )
        self.aggregator_cpu_memory = Gauge(
            "ztfl_aggregator_cpu_memory_overhead_bytes",
            "Approximate aggregation RSS delta in bytes.",
            [*common, "backend", "method"],
            registry=self.registry,
        )
        self.aggregator_gpu_memory = Gauge(
            "ztfl_aggregator_gpu_memory_overhead_bytes",
            "Peak CUDA allocation above the pre-aggregation baseline in bytes.",
            [*common, "backend", "method"],
            registry=self.registry,
        )
        self.round_time = Histogram(
            "ztfl_round_duration_seconds",
            "End-to-end federated round duration in seconds.",
            common,
            registry=self.registry,
        )
        self.poisoning_mitigation_rate = Gauge(
            "ztfl_poisoning_mitigation_rate",
            "Running fraction of attacked rounds where robust aggregation beats naive mean.",
            common,
            registry=self.registry,
        )
        self.poisoning_mitigation_score = Gauge(
            "ztfl_poisoning_mitigation_score",
            "Latest robust-vs-naive poisoning mitigation score in [0,1].",
            common,
            registry=self.registry,
        )
        self.node_churn_rate = Gauge(
            "ztfl_node_churn_rate",
            "Latest fraction of selected clients that failed or became stragglers.",
            common,
            registry=self.registry,
        )
        self.updates = Counter(
            "ztfl_updates_total",
            "Submitted model updates by result.",
            [*common, "result"],
            registry=self.registry,
        )
        self.attack_active = Gauge(
            "ztfl_attack_active",
            "Whether this worker is currently configured to poison updates.",
            [*common, "attack"],
            registry=self.registry,
        )

        if metrics_port > 0:
            self._server, self._server_thread = start_http_server(
                metrics_port,
                addr=metrics_host,
                registry=self.registry,
            )

    @property
    def _common_labels(self) -> dict[str, str]:
        return {"service": self.service_name, "instance": self.instance_id}

    def instrument_grpc_client(self) -> None:
        """Enable OpenTelemetry client spans and W3C context propagation."""

        if self._grpc_instrumented:
            return
        GrpcInstrumentorClient().instrument(tracer_provider=self.tracer_provider)
        self._grpc_instrumented = True

    @contextlib.contextmanager
    def span(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> Iterator[Any]:
        with self.tracer.start_as_current_span(name, attributes=dict(attributes or {})) as span:
            yield span

    @contextlib.contextmanager
    def measure_rpc(self, rpc: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.network_latency.labels(**self._common_labels, rpc=rpc).observe(
                time.perf_counter() - started
            )

    def record_epoch(self, seconds: float) -> None:
        self.epoch_time.labels(**self._common_labels).observe(max(0.0, seconds))

    def record_update(self, *, accepted: bool) -> None:
        result = "accepted" if accepted else "rejected"
        self.updates.labels(**self._common_labels, result=result).inc()

    def record_attack(self, attack: str) -> None:
        self.attack_active.labels(**self._common_labels, attack=attack).set(
            0.0 if attack == "none" else 1.0
        )

    def record_process_memory(self) -> None:
        self.process_rss.labels(**self._common_labels).set(
            float(psutil.Process().memory_info().rss)
        )
        gpu_bytes = 0.0
        if torch.cuda.is_available():
            gpu_bytes = float(torch.cuda.memory_allocated())
        self.gpu_memory.labels(**self._common_labels).set(gpu_bytes)

    def record_aggregation(
        self,
        *,
        backend: str,
        method: str,
        duration_seconds: float,
        cpu_memory_delta_bytes: int,
        gpu_peak_delta_bytes: int,
    ) -> None:
        labels = {**self._common_labels, "backend": backend, "method": method}
        self.aggregation_time.labels(**labels).observe(max(0.0, duration_seconds))
        self.aggregator_cpu_memory.labels(**labels).set(
            max(0.0, float(cpu_memory_delta_bytes))
        )
        self.aggregator_gpu_memory.labels(**labels).set(
            max(0.0, float(gpu_peak_delta_bytes))
        )

    def record_round(self, metrics: Any) -> None:
        """Publish one simulator RoundMetrics object immediately after a round."""

        self.round_time.labels(**self._common_labels).observe(
            max(0.0, float(metrics.round_duration_ms) / 1000.0)
        )
        selected = len(metrics.selected_clients)
        churned = len(metrics.failed_clients) + len(metrics.straggler_clients)
        self.node_churn_rate.labels(**self._common_labels).set(
            float(churned / selected) if selected else 0.0
        )

        if metrics.mitigation_score is not None:
            self.poisoning_mitigation_score.labels(**self._common_labels).set(
                float(metrics.mitigation_score)
            )
        if metrics.attack_mitigated is not None:
            with self._lock:
                self._attacked_rounds += 1
                self._mitigated_rounds += int(bool(metrics.attack_mitigated))
                rate = self._mitigated_rounds / self._attacked_rounds
            self.poisoning_mitigation_rate.labels(**self._common_labels).set(rate)

        self.record_process_memory()

    def shutdown(self) -> None:
        if self._grpc_instrumented:
            GrpcInstrumentorClient().uninstrument()
            self._grpc_instrumented = False
        self.tracer_provider.shutdown()
        if self._server is not None:
            self._server.shutdown()
