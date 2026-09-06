"""Operator command line interface for ZeroTrust-FL-Sim."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .sdk import SDK_API_VERSION, WorkerClient, WorkerConfig


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _worker_config(args: argparse.Namespace) -> WorkerConfig:
    cert_dir = Path(args.cert_dir)
    return WorkerConfig(
        address=args.address,
        node_id=args.node_id,
        certificate_common_name=args.node_id,
        ca_certificate=str(cert_dir / "ca.crt"),
        client_certificate=str(cert_dir / f"{args.node_id}.crt"),
        client_private_key=str(cert_dir / f"{args.node_id}.key"),
        model_id=args.model_id,
        jwt_token_file=str(cert_dir / f"{args.node_id}.jwt"),
        server_name_override=args.server_name,
        expected_trust_domain=args.trust_domain,
        timeout_seconds=args.timeout,
    )


def _require_files(paths: Sequence[Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        if not path.is_file():
            problems.append(f"missing file: {path}")
        elif not os.access(path, os.R_OK):
            problems.append(f"unreadable file: {path}")
    return problems


def _validate(args: argparse.Namespace) -> dict[str, Any]:
    cert_dir = Path(args.cert_dir)
    problems: list[str] = []
    warnings: list[str] = []

    if args.profile == "coordinator":
        problems.extend(
            _require_files(
                [
                    cert_dir / "server.crt",
                    cert_dir / "server.key",
                    cert_dir / "ca.crt",
                    cert_dir / "jwt_signing_public.pem",
                ]
            )
        )
        state_file = os.getenv("ZTFL_STATE_FILE", "").strip()
        postgres_dsn = os.getenv("ZTFL_POSTGRES_DSN", "").strip()
        if state_file and postgres_dsn:
            problems.append("ZTFL_STATE_FILE and ZTFL_POSTGRES_DSN are mutually exclusive")
        if args.production:
            required_env = (
                "ZTFL_POSTGRES_DSN",
                "ZTFL_S3_ENDPOINT",
                "ZTFL_S3_BUCKET",
                "ZTFL_S3_ACCESS_KEY_ID",
                "ZTFL_S3_SECRET_ACCESS_KEY",
                "ZTFL_EXPERIMENT_ID",
                "ZTFL_MODEL_ID",
            )
            for name in required_env:
                if not os.getenv(name, "").strip():
                    problems.append(f"production coordinator requires {name}")
            if _bool_env("ZTFL_S3_ALLOW_INSECURE_HTTP", False):
                problems.append("production coordinator must not allow insecure S3 HTTP")
            if state_file:
                problems.append("production reference profile requires PostgreSQL, not ZTFL_STATE_FILE")
        elif not state_file and not postgres_dsn:
            warnings.append("coordinator state is volatile; configure a durable backend")
    else:
        if not args.node_id:
            problems.append("worker validation requires --node-id")
        else:
            problems.extend(
                _require_files(
                    [
                        cert_dir / "ca.crt",
                        cert_dir / f"{args.node_id}.crt",
                        cert_dir / f"{args.node_id}.key",
                        cert_dir / f"{args.node_id}.jwt",
                    ]
                )
            )

    return {
        "ok": not problems,
        "profile": args.profile,
        "production": bool(args.production),
        "sdk_api_version": SDK_API_VERSION,
        "problems": problems,
        "warnings": warnings,
    }


def _print_json(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True))


def _add_worker_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--address",
        default=os.getenv("ZTFL_COORDINATOR_ADDRESS", "127.0.0.1:50051"),
    )
    parser.add_argument("--node-id", default=os.getenv("ZTFL_NODE_ID", ""))
    parser.add_argument("--cert-dir", default=os.getenv("ZTFL_CERT_DIR", "certs/dev"))
    parser.add_argument("--server-name", default=os.getenv("ZTFL_SERVER_NAME", "coordinator"))
    parser.add_argument("--model-id", default=os.getenv("ZTFL_MODEL_ID", "global-model"))
    parser.add_argument(
        "--trust-domain", default=os.getenv("ZTFL_TRUST_DOMAIN", "zerotrust-fl.local")
    )
    parser.add_argument("--timeout", type=float, default=10.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ztfl", description=__doc__)
    parser.add_argument("--version", action="version", version=f"ztfl sdk-v{SDK_API_VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate coordinator or worker configuration")
    validate.add_argument("--profile", choices=["coordinator", "worker"], required=True)
    validate.add_argument("--cert-dir", default=os.getenv("ZTFL_CERT_DIR", "certs/dev"))
    validate.add_argument("--node-id", default=os.getenv("ZTFL_NODE_ID", ""))
    validate.add_argument("--production", action="store_true")

    start = commands.add_parser("coordinator-start", help="exec the coordinator binary")
    start.add_argument(
        "--binary", default=os.getenv("ZTFL_COORDINATOR_BINARY", "coordinator")
    )
    start.add_argument("--dry-run", action="store_true")
    start.add_argument("coordinator_args", nargs=argparse.REMAINDER)

    enroll = commands.add_parser("worker-enroll", help="register one worker identity")
    _add_worker_arguments(enroll)

    status = commands.add_parser("experiment-status", help="read live model/lease status")
    _add_worker_arguments(status)

    diagnostics = commands.add_parser("diagnostics", help="verify credentials and coordinator TLS reachability")
    _add_worker_arguments(diagnostics)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            result = _validate(args)
            _print_json(result)
            return 0 if result["ok"] else 2

        if args.command == "coordinator-start":
            binary = shutil.which(args.binary) or args.binary
            forwarded = list(args.coordinator_args)
            if forwarded and forwarded[0] == "--":
                forwarded = forwarded[1:]
            command = [binary, *forwarded]
            if args.dry_run:
                _print_json({"ok": True, "command": command})
                return 0
            os.execvpe(binary, command, os.environ.copy())
            return 0

        config = _worker_config(args)
        with WorkerClient(config) as client:
            client.wait_ready(timeout=args.timeout)
            if args.command == "diagnostics":
                _print_json(
                    {
                        "ok": True,
                        "address": config.address,
                        "node_id": config.node_id,
                        "model_id": config.model_id,
                        "tls": "1.3-required",
                    }
                )
                return 0

            enrollment = client.enroll()
            if args.command == "worker-enroll":
                _print_json(
                    {
                        "ok": True,
                        "registration_id": enrollment.registration_id,
                        "assigned_role": enrollment.assigned_role,
                        "lease_expires_unix": enrollment.lease_expires_unix,
                        "credential_generation": enrollment.credential_generation,
                    }
                )
                return 0

            snapshot = client.get_model()
            heartbeat = client.heartbeat(snapshot.model_version)
            _print_json(
                {
                    "ok": heartbeat.accepted,
                    "registration_id": enrollment.registration_id,
                    "model_id": snapshot.model_id,
                    "protocol_version": snapshot.protocol_version,
                    "model_version": snapshot.model_version,
                    "round_id": snapshot.round_id,
                    "lease_expires_unix": heartbeat.lease_expires_unix,
                    "credential_generation": heartbeat.credential_generation,
                }
            )
            return 0 if heartbeat.accepted else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
