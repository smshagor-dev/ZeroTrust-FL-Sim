"""Stream federated-training round results for the root orchestrator and dashboard.

The standard simulation runner remains the source of truth for datasets,
worker construction, privacy, attacks, and aggregation configuration. This
wrapper adds immediate round output plus a small atomic JSON bridge consumed by
the optional local Next.js dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import run_fl_sim as base

_BaseAsyncCoordinator = base.AsyncFederatedCoordinator
_BaseObservableCoordinator = base.ObservableAsyncFederatedCoordinator

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "tmp" / "orchestrator"
STATE_FILE = RUNTIME / "dashboard-state.json"
COMMAND_FILE = RUNTIME / "dashboard-command.json"
_HISTORY: list[dict[str, Any]] = []
_LOGS: list[str] = []
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
    _LOGS.append(f"[{stamp}] {message}")
    del _LOGS[:-24]


def _state(active: bool) -> dict[str, Any]:
    malicious = max(0, min(_META.clients, round(_META.clients * _META.malicious_fraction)))
    return {
        "active": active,
        "started_at": _STARTED_AT,
        "updated_at": time.time(),
        "current_round": _HISTORY[-1]["round_id"] if _HISTORY else 0,
        "total_rounds": _META.rounds,
        "attack": _META.attack,
        "aggregator": _META.aggregator,
        "device": _META.device,
        "benign_workers": _META.clients - malicious,
        "malicious_workers": malicious,
        "rounds": _HISTORY[-100:],
        "logs": _LOGS[-24:],
    }


def _write_state(*, active: bool) -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(_writeable_state(active), indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, STATE_FILE)


def _writeable_state(active: bool) -> dict[str, Any]:
    return _state(active)


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
    _HISTORY.append(payload)
    _log(
        "[CPP-AGGREGATOR] "
        f"Round {metrics.round_id}/{_META.rounds} {metrics.aggregation_method} complete; "
        f"malicious={metrics.malicious_results}, mitigation={metrics.mitigation_score}"
    )
    if metrics.attack_mitigated is not None:
        verdict = "mitigated" if metrics.attack_mitigated else "not mitigated"
        _log(f"[SECURITY] Byzantine attack {verdict} in round {metrics.round_id}")
    _write_state(active=True)
    print("LIVE_ROUND " + json.dumps(payload, sort_keys=True), flush=True)


class StreamingAsyncFederatedCoordinator(_BaseAsyncCoordinator):
    """Standard simulator coordinator with immediate round and dashboard output."""

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        if _consume_stop_request():
            _log("[DASHBOARD] Stop requested by web dashboard")
            _write_state(active=False)
            raise SystemExit(0)
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


class StreamingObservableAsyncFederatedCoordinator(_BaseObservableCoordinator):
    """Observable coordinator with immediate round and dashboard output."""

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        if _consume_stop_request():
            _log("[DASHBOARD] Stop requested by web dashboard")
            _write_state(active=False)
            raise SystemExit(0)
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


def main() -> None:
    COMMAND_FILE.unlink(missing_ok=True)
    _log(
        f"[COORDINATOR] Training initialized: {_META.clients} clients, "
        f"attack={_META.attack}, aggregator={_META.aggregator}"
    )
    _write_state(active=True)
    base.AsyncFederatedCoordinator = StreamingAsyncFederatedCoordinator
    base.ObservableAsyncFederatedCoordinator = StreamingObservableAsyncFederatedCoordinator
    try:
        base.main()
    finally:
        _write_state(active=False)


if __name__ == "__main__":
    main()
