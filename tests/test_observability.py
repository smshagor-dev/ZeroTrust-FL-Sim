from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import torch
import yaml
from prometheus_client import generate_latest
from zerotrust_fl.attacks import AttackConfig, PoisoningAttack
from zerotrust_fl.observability import TelemetryRuntime

ROOT = Path(__file__).resolve().parents[1]


def test_colluding_workers_share_round_direction() -> None:
    first = torch.linspace(-1.0, 1.0, 256)
    second = torch.linspace(0.25, 2.0, 256)
    first_attack = PoisoningAttack(
        AttackConfig(kind="collusion", collusion_scale=8.0, collusion_seed=20271, seed=1)
    )
    second_attack = PoisoningAttack(
        AttackConfig(kind="collusion", collusion_scale=8.0, collusion_seed=20271, seed=999)
    )

    first_poison = first_attack.transform_update(first, round_id=7)
    second_poison = second_attack.transform_update(second, round_id=7)
    next_round = first_attack.transform_update(first, round_id=8)

    torch.testing.assert_close(
        first_poison / torch.linalg.vector_norm(first_poison),
        second_poison / torch.linalg.vector_norm(second_poison),
    )
    assert not torch.equal(torch.sign(first_poison), torch.sign(next_round))


def test_prometheus_runtime_exports_requested_metrics() -> None:
    telemetry = TelemetryRuntime(
        service_name="test-simulator",
        instance_id="test-1",
        metrics_port=0,
    )
    try:
        telemetry.record_epoch(0.125)
        telemetry.record_aggregation(
            backend="native",
            method="median",
            duration_seconds=0.01,
            cpu_memory_delta_bytes=4096,
            gpu_peak_delta_bytes=8192,
        )
        telemetry.record_round(
            SimpleNamespace(
                round_duration_ms=250,
                selected_clients=("a", "b", "c", "d"),
                failed_clients=("a",),
                straggler_clients=("b",),
                mitigation_score=0.75,
                attack_mitigated=True,
            )
        )
        payload = generate_latest(telemetry.registry).decode("utf-8")
    finally:
        telemetry.shutdown()

    for metric in (
        "ztfl_epoch_duration_seconds",
        "ztfl_aggregation_duration_seconds",
        "ztfl_aggregator_cpu_memory_overhead_bytes",
        "ztfl_aggregator_gpu_memory_overhead_bytes",
        "ztfl_poisoning_mitigation_rate",
        "ztfl_node_churn_rate",
    ):
        assert metric in payload
    assert 'ztfl_node_churn_rate{instance="test-1",service="test-simulator"} 0.5' in payload


def test_chaos_mesh_profiles_encode_requested_faults() -> None:
    chaos_root = ROOT / "deploy" / "chaos" / "chaos-mesh"
    loss = yaml.safe_load((chaos_root / "network-loss-50.yaml").read_text())
    jitter = yaml.safe_load((chaos_root / "network-jitter.yaml").read_text())
    churn = yaml.safe_load((chaos_root / "node-churn.yaml").read_text())

    assert loss["kind"] == "NetworkChaos"
    assert loss["spec"]["action"] == "loss"
    assert loss["spec"]["loss"]["loss"] == "50"
    assert jitter["spec"]["action"] == "delay"
    assert jitter["spec"]["delay"]["jitter"] == "100ms"
    assert churn["kind"] == "PodChaos"
    assert churn["spec"]["action"] == "pod-failure"
    assert churn["spec"]["mode"] == "random-max-percent"
    assert churn["spec"]["value"] == "50"


def test_grafana_dashboard_contains_resilience_panels() -> None:
    path = ROOT / "observability" / "grafana" / "dashboards" / "dashboard.json"
    dashboard = json.loads(path.read_text(encoding="utf-8"))
    titles = {panel["title"] for panel in dashboard["panels"]}

    assert dashboard["uid"] == "zerotrust-fl-resilience"
    assert {
        "Epoch / Local Update Time p95",
        "Network / gRPC Latency p95",
        "Aggregator CPU Memory Overhead",
        "Aggregator GPU Memory Overhead",
        "Poisoning Mitigation Rate",
        "Node Churn Rate",
    } <= titles
