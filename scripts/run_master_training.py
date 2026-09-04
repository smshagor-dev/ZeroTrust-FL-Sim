"""Stream federated-training round results for the root orchestrator.

The standard simulation runner remains the source of truth for datasets,
worker construction, privacy, attacks, and aggregation configuration. This
wrapper only emits each completed round immediately instead of waiting for the
entire experiment to finish.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

import run_fl_sim as base

_BaseAsyncCoordinator = base.AsyncFederatedCoordinator
_BaseObservableCoordinator = base.ObservableAsyncFederatedCoordinator


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
    print("LIVE_ROUND " + json.dumps(payload, sort_keys=True), flush=True)


class StreamingAsyncFederatedCoordinator(_BaseAsyncCoordinator):
    """Standard simulator coordinator with immediate round output."""

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


class StreamingObservableAsyncFederatedCoordinator(_BaseObservableCoordinator):
    """Observable coordinator with immediate round output."""

    def _run_round(self, round_id: int):  # type: ignore[no-untyped-def]
        metrics = super()._run_round(round_id)
        _emit_round(metrics)
        return metrics


def main() -> None:
    # run_fl_sim.main resolves these module globals when creating coordinators.
    base.AsyncFederatedCoordinator = StreamingAsyncFederatedCoordinator
    base.ObservableAsyncFederatedCoordinator = (
        StreamingObservableAsyncFederatedCoordinator
    )
    base.main()


if __name__ == "__main__":
    main()
