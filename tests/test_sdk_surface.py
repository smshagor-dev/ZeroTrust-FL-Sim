from __future__ import annotations

import argparse
import json

import pytest
import zerotrust_fl
from zerotrust_fl import cli
from zerotrust_fl.sdk import SDK_API_VERSION, Enrollment, WorkerConfig


def test_public_sdk_surface_is_explicit_and_versioned() -> None:
    assert zerotrust_fl.__version__ == "0.9.0"
    assert SDK_API_VERSION == "1"
    assert zerotrust_fl.__all__ == [
        "SDK_API_VERSION",
        "Enrollment",
        "HeartbeatStatus",
        "ModelSnapshot",
        "TensorManifest",
        "UpdateMetrics",
        "UpdateSubmission",
        "WorkerClient",
        "WorkerConfig",
        "__version__",
    ]
    assert Enrollment.__module__ == "zerotrust_fl.sdk"
    assert WorkerConfig.__name__ == "GrpcWorkerConfig"


def test_operator_validate_worker_fails_closed_on_missing_credentials(tmp_path, capsys) -> None:
    result = cli.main(
        [
            "validate",
            "--profile",
            "worker",
            "--node-id",
            "worker-01",
            "--cert-dir",
            str(tmp_path),
        ]
    )
    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert len(payload["problems"]) == 4


def test_operator_validate_production_coordinator_requires_durable_services(
    tmp_path, monkeypatch, capsys
) -> None:
    for name in ("server.crt", "server.key", "ca.crt", "jwt_signing_public.pem"):
        (tmp_path / name).write_text("test", encoding="utf-8")
    for name in (
        "ZTFL_POSTGRES_DSN",
        "ZTFL_S3_ENDPOINT",
        "ZTFL_S3_BUCKET",
        "ZTFL_S3_ACCESS_KEY_ID",
        "ZTFL_S3_SECRET_ACCESS_KEY",
        "ZTFL_EXPERIMENT_ID",
        "ZTFL_MODEL_ID",
        "ZTFL_STATE_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    result = cli.main(
        [
            "validate",
            "--profile",
            "coordinator",
            "--cert-dir",
            str(tmp_path),
            "--production",
        ]
    )
    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "production coordinator requires ZTFL_POSTGRES_DSN" in payload["problems"]


def test_operator_coordinator_dry_run_is_non_destructive(capsys) -> None:
    result = cli.main(
        ["coordinator-start", "--binary", "ztfl-coordinator", "--dry-run", "--", "--listen=:50051"]
    )
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"command": ["ztfl-coordinator", "--listen=:50051"], "ok": True}


def test_worker_config_validation_remains_strict() -> None:
    with pytest.raises(ValueError, match="address is required"):
        WorkerConfig(
            address="",
            node_id="node",
            certificate_common_name="node",
            ca_certificate="ca.crt",
            client_certificate="client.crt",
            client_private_key="client.key",
            jwt_token="token",
        )


def test_validate_helper_returns_json_safe_payload(tmp_path) -> None:
    args = argparse.Namespace(
        profile="worker",
        cert_dir=str(tmp_path),
        node_id="node",
        production=False,
    )
    json.dumps(cli._validate(args))
