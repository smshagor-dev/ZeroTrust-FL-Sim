"""Smoke tests for the single-command local orchestrator."""

from __future__ import annotations

import importlib.util
import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main.py"
TRAINING_WRAPPER = ROOT / "scripts" / "run_master_training.py"
DASHBOARD_COMPONENT = ROOT / "frontend" / "components" / "dashboard.tsx"
DASHBOARD_API = ROOT / "frontend" / "app" / "api" / "dashboard" / "route.ts"


def _load_main_module():
    spec = importlib.util.spec_from_file_location("ztfl_master_main", MAIN)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_master_entrypoints_compile() -> None:
    py_compile.compile(str(MAIN), doraise=True)
    py_compile.compile(str(TRAINING_WRAPPER), doraise=True)


def test_master_help_is_available_without_starting_services() -> None:
    result = subprocess.run(
        [sys.executable, str(MAIN), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0
    assert "native C++ FL aggregation" in result.stdout


def test_default_training_command_uses_native_median(monkeypatch) -> None:
    master = _load_main_module()
    monkeypatch.setattr(sys, "argv", ["main.py"])
    args = master.parse_args()

    assert args.benign_workers == 3
    assert args.malicious_workers == 1
    assert args.aggregator == "median"

    command = master.trainer_cmd(args)
    assert command[command.index("--backend") + 1] == "native"
    assert command[command.index("--clients") + 1] == "4"
    assert command[command.index("--malicious-fraction") + 1] == "0.25"


def test_dashboard_sources_reject_synthetic_telemetry() -> None:
    component = DASHBOARD_COMPONENT.read_text(encoding="utf-8")
    api = DASHBOARD_API.read_text(encoding="utf-8")
    wrapper = TRAINING_WRAPPER.read_text(encoding="utf-8")
    combined_frontend = component + "\n" + api

    forbidden = (
        "const DEMO",
        "previewRounds",
        "preview-gaussian",
        "Math.sin(",
        "latencyMs: [12",
        "dataSize: 1024",
        "Configuration staged for the next run",
    )
    for marker in forbidden:
        assert marker not in combined_frontend

    assert 'dynamic = "force-dynamic"' in api
    assert '"Cache-Control": "no-store, max-age=0"' in api
    assert "system_samples" in wrapper
    assert "simulated_latency_ms" in wrapper
    assert '"data_size": len(spec.sample_indices)' in wrapper
    assert "psutil.cpu_percent" in wrapper
    assert "torch.cuda.mem_get_info" in wrapper
    assert "_WRITE_LOCK" in wrapper
