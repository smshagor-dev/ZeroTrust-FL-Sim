"""Stream real federated-training state for the local dashboard.

The standard simulation runner remains the source of truth for datasets,
worker construction, privacy, attacks, and aggregation configuration. This
wrapper publishes only measurements observed from that running simulation.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import psutil
import torch

import run_fl_sim as base

_BaseAsyncCoordinator = base.AsyncFederatedCoordinator
_BaseObservableCoordinator = base.ObservableAsyncFederatedCoordinator

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "tmp" / "orchestrator"
STATE_FILE = RUNTIME / "dashboard-state.json"
COMMAND_FILE = RUNTIME / "dashboard-command.json"
_HISTORY: list[dict[str, Any]] = []
_LOGS: list[str] = []
_WORKER_RESULTS: dict[str, dict[str, Any]] = {}
_SYSTEM_SAMPLES: list[dict[str, Any]] = []
_STATE_LOCK = threading.Lock()
_WRITE_LOCK = threading.Lock()
_SAMPLER_STOP = threading.Event()
_ACTIVE_COORDINATOR: Any | None = None
_ACTIVE = False
_STARTED_AT = time.time()


def _dashboard_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--malicious-fraction", type=float, default=0.25)
    parser.add_argument("--attack", default="gaussian")
    parser.add_argument("--aggregator", default="median")
    parser.add_argument("--device", default="cpu")
    args, _ = parser.parse_known_args(sys.argv[1:])
    return args


_META = _dashboard_args()


def _log(message: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    with _STATE_LOCK:
        _LOGS.append(f"[{stamp}] {message}")
        del _LOGS[:-48]


def _set_coordinator(coordinator: Any | None) -> None:
    global _ACTIVE_COORDINATOR
    with _STATE_LOCK:
        _ACTIVE_COORDINATOR = coordinator


def _set_active(active: bool) -> None:
    global _ACTIVE
    with _STATE_LOCK:
        _ACTIVE = active


def _record_worker_results(
    results: list[Any],
    failures: set[str],
    round_id: int,
) -> None:
    now = time.time()
    with _STATE_LOCK:
        for result in results:
            loss = float(result.loss)
            _WORKER_RESULTS[result.node_id] = {
                "last_update_at": now,
                "latency_ms": int(result.simulated_latency_ms),
                "training_duration_ms": int(result.training_duration_ms),
                "loss": loss if math.isfinite(loss) else None,
                "last_round": int(result.round_id),
                "succeeded": bool(result.succeeded),
            }
        for node_id in failures:
            previous = _WORKER_RESULTS.setdefault(node_id, {})
            previous["last_update_at"] = now
            previous["last_round"] = round_id
            previous["succeeded"] = False


def _worker_snapshot(coordinator: Any | None) -> list[dict[str, Any]]:
    if coordinator is None:
        return []
    with _STATE_LOCK:
        latest = {
            node_id: dict(value)
            for node_id, value in _WORKER_RESULTS.items()
        }

    workers: list[dict[str, Any]] = []
    processes = getattr(coordinator, "_processes", {})
    for spec in getattr(coordinator, "worker_specs", ()):
        node_id = spec.config.node_id
        process = processes.get(node_id)
        recent = latest.get(node_id, {})
        workers.append(
            {
                "id": node_id,
                "role": "Malicious" if spec.config.malicious else "Benign",
                "status": (
                    "Online"
                    if process is not None and process.is_alive()
                    else "Offline"
                ),
                "last_update_at": recent.get("last_update_at"),
                "latency_ms": recent.get("latency_ms"),
                "data_size": len(spec.sample_indices),
                "training_duration_ms": recent.get("training_duration_ms"),
                "loss": recent.get("loss"),
                "last_round": recent.get("last_round"),
            }
        )
    return workers


def _sample_system() -> None:
    gpu_memory_percent: float | None = None
    if "cuda" in _META.device.lower() and torch.cuda.is_available():
        try:
            free_bytes, total_bytes = torch.cuda.mem_get_info()
            if total_bytes > 0:
                gpu_memory_percent = (
                    (total_bytes - free_bytes) / total_bytes * 100.0
                )
        except RuntimeError:
            gpu_memory_percent = None

    sample = {
        "timestamp": time.time(),
        "cpu_percent": float(psutil.cpu_percent(interval=None)),
        "memory_percent": float(psutil.virtual_memory().percent),
        "gpu_memory_percent": gpu_memory_percent,
    }
    with _STATE_LOCK:
        _SYSTEM_SAMPLES.append(sample)
        del _SYSTEM_SAMPLES[:-120]


def _state() -> dict[str, Any]:
    with _STATE_LOCK:
        active = _ACTIVE
        coordinator = _ACTIVE_COORDINATOR
        history = list(_HISTORY[-100:])
        logs = list(_LOGS[-48:])
        system_samples = list(_SYSTEM_SAMPLES[-120:])

    workers = _worker_snapshot(coordinator)
    malicious = sum(worker["role"] == "Malicious" for worker in workers)
    benign = sum(worker["role"] == "Benign" for worker in workers)
    if not workers:
        configured_malicious = max(
            0,
            min(
                _META.clients,
                round(_META.clients * _META.malicious_fraction),
            ),
        )
        benign = _META.clients - configured_malicious
        malicious = configured_malicious

    return {
        "active": active,
        "started_at": _STARTED_AT,
        "updated_at": time.time(),
        "current_round": history[-1]["round_id"] if history else 0,
        "total_rounds": _META.rounds,
        "attack": _META.attack,
        "aggregator": _META.aggregator,
        "device": _META.device,
        "benign_workers": benign,
        "malicious_workers": malicious,
        "rounds": history,
        "workers": workers,
        "system_samples": system_samples,
        "logs": logs,
    }


def _write_state() -> None:
    with _WRITE_LOCK:
        RUNTIME.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(_state(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, STATE_FILE)


def _system_sampler() -> None:
    psutil.cpu_percent(interval=None)
    while not _SAMPLER_STOP.is_set():
        _sample_system()
        _write_state()
        if _SAMPLER_STOP.wait(1.0):
            break


def _consume_stop_request() -> bool:
    if not COMMAND_FILE.exists():
        return False
    try:
        payload = json.loads(COMMAND_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    COMMAND_FILE.unlink(missing_ok=True)
    return payload.get("command") == "stop"


def _emit_round(metrics: Any) -> None:
    payload = asdict(metrics)
    payload["event"] = "round_complete"
    payload["byzantine_filtering"] = {
        "backend": metrics.aggregation_backend,
        "method": metrics.aggregation_method,
        "malicious_results": metrics.malicious_results,
        "mitigation_score": metrics.mitigation_score,
        "attack_mitigated": metrics.attack_mitigated,
    }
    with _STATE_LOCK:
        _HISTORY.append(payload)
        del _HISTORY[:-100]
    _log(
        "[CPP-AGGREGATOR] "
        f"Round {metrics.round_id}/{_META.rounds} "
        f"{metrics.aggregation_method} complete; "
        f"malicious={metrics.malicious_results}, "
        f"mitigation={metrics.mitigation_score}"
    )
    if metrics.attack_mitigated is not None:
        verdict = "mitigated" if metrics.attack_mitigated else "not mitigated"
        _log(
            f"[SECURITY] Byzantine attack {verdict} "
            f"in round {metrics.round_id}"
        )
    _write_state()
    print("LIVE_ROUND " + json.dumps(payload, sort_keys=True), flush=True)


class StreamingAsyncFederatedCoordinator(_BaseAsyncCoordinator):
    """Standard simulator coordinator with live dashboard instrumentation."""

    def start(self) -> None:
        super().start()
        _set_coordinator(self)
        _write_state()

    def _collect_round_results(self, **kwargs: Any):  # type: ignore[no-untyped-def]
        results, failures = super()._collect_round_results(**kwargs)
        _record_worker_results(results, failures, int(kwargs["round_id"]))
        _write_state()
        return results, failures

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        if _consume_stop_request():
            _log("[DASHBOARD] Stop requested by web dashboard")
            _set_active(False)
            _write_state()
            raise SystemExit(0)
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


class StreamingObservableAsyncFederatedCoordinator(_BaseObservableCoordinator):
    """Observable coordinator with live dashboard instrumentation."""

    def start(self) -> None:
        super().start()
        _set_coordinator(self)
        _write_state()

    def _collect_round_results(self, **kwargs: Any):  # type: ignore[no-untyped-def]
        results, failures = super()._collect_round_results(**kwargs)
        _record_worker_results(results, failures, int(kwargs["round_id"]))
        _write_state()
        return results, failures

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        if _consume_stop_request():
            _log("[DASHBOARD] Stop requested by web dashboard")
            _set_active(False)
            _write_state()
            raise SystemExit(0)
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


def main() -> None:
    COMMAND_FILE.unlink(missing_ok=True)
    _set_active(True)
    _log(
        f"[COORDINATOR] Training initialized: {_META.clients} clients, "
        f"attack={_META.attack}, aggregator={_META.aggregator}"
    )
    _write_state()
    sampler = threading.Thread(
        target=_system_sampler,
        name="ztfl-dashboard-system-sampler",
        daemon=True,
    )
    sampler.start()
    base.AsyncFederatedCoordinator = StreamingAsyncFederatedCoordinator
    base.ObservableAsyncFederatedCoordinator = (
        StreamingObservableAsyncFederatedCoordinator
    )
    try:
        base.main()
    finally:
        _set_active(False)
        _SAMPLER_STOP.set()
        sampler.join(timeout=2.0)
        _write_state()


if __name__ == "__main__":
    main()
