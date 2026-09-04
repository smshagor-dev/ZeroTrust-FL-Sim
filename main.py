#!/usr/bin/env python3
"""
ZeroTrust-FL-Sim local master orchestrator.

Run:
    python main.py

The orchestrator performs prerequisite validation, installs missing Python
dependencies when allowed, builds the C++20/pybind11 extension when required,
generates a local mTLS PKI, launches the Go coordinator and Python workers,
optionally launches a frontend/WebSocket process, monitors all required child
processes, and shuts down the entire process tree on SIGINT/SIGTERM.

This file intentionally uses only the Python standard library so it can run
before the project's Python dependencies are installed.
"""

from __future__ import annotations

import argparse
import atexit
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.txt"
SETUP_FILE = ROOT / "setup.py"
GO_MOD_FILE = ROOT / "go.mod"
WORKER_SCRIPT = ROOT / "scripts" / "run_grpc_worker.py"
PROTO_GENERATOR = ROOT / "scripts" / "generate_python_proto.py"
SECURITY_DIR = ROOT / "security"
DEFAULT_CERT_DIR = SECURITY_DIR / "certs"
FRONTEND_DIR = ROOT / "frontend"
RUNTIME_DIR = ROOT / "tmp" / "orchestrator"

DEFAULT_GRPC_HOST = "127.0.0.1"
DEFAULT_GRPC_PORT = 50051
DEFAULT_WEBSOCKET_PORT = 8080
DEFAULT_COORDINATOR_METRICS_PORT = 9464
DEFAULT_WORKER_METRICS_BASE_PORT = 9465
MIN_PYTHON = (3, 12)

TAG_SYSTEM = "SYSTEM"
TAG_COORDINATOR = "COORDINATOR"
TAG_CPP = "CPP-AGGREGATOR"
TAG_WORKER_BENIGN = "WORKER-BENIGN"
TAG_WORKER_ATTACKER = "WORKER-ATTACKER"
TAG_DASHBOARD = "DASHBOARD"

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_COLORS = {
    TAG_SYSTEM: "\033[96m",
    TAG_COORDINATOR: "\033[94m",
    TAG_CPP: "\033[95m",
    TAG_WORKER_BENIGN: "\033[92m",
    TAG_WORKER_ATTACKER: "\033[91m",
    TAG_DASHBOARD: "\033[93m",
}


class OrchestratorError(RuntimeError):
    """Fatal orchestrator error with a user-facing message."""


class Console:
    """Thread-safe colorized console logger."""

    _lock = threading.Lock()
    _use_color = (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM", "").lower() != "dumb"
    )

    @classmethod
    def emit(cls, tag: str, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        with cls._lock:
            if cls._use_color:
                color = ANSI_COLORS.get(tag, "")
                prefix = f"{ANSI_BOLD}{color}[{tag}]{ANSI_RESET}"
            else:
                prefix = f"[{tag}]"
            print(f"{timestamp} {prefix} {message}", flush=True)


@dataclass
class ManagedProcess:
    name: str
    tag: str
    process: subprocess.Popen[str]
    required: bool
    reader_thread: threading.Thread
    exit_reported: bool = False


class ProcessManager:
    """Own long-lived child processes and their process groups."""

    def __init__(self, shutdown_timeout: float = 10.0) -> None:
        self.shutdown_timeout = max(1.0, shutdown_timeout)
        self.children: list[ManagedProcess] = []
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._shutting_down = False

    @property
    def shutting_down(self) -> bool:
        with self._lock:
            return self._shutting_down

    def request_shutdown(self, reason: str) -> None:
        if not self.stop_event.is_set():
            Console.emit(TAG_SYSTEM, reason)
        self.stop_event.set()

    def start(
        self,
        *,
        name: str,
        tag: str,
        command: Sequence[str],
        cwd: Path = ROOT,
        env: Mapping[str, str] | None = None,
        required: bool = True,
    ) -> ManagedProcess:
        popen_env = os.environ.copy()
        if env:
            popen_env.update({str(k): str(v) for k, v in env.items()})

        kwargs: dict[str, object] = {
            "cwd": str(cwd),
            "env": popen_env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "stdin": subprocess.DEVNULL,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "bufsize": 1,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        Console.emit(tag, f"starting {name}: {format_command(command)}")
        try:
            process = subprocess.Popen(list(command), **kwargs)  # type: ignore[arg-type]
        except OSError as exc:
            raise OrchestratorError(f"failed to start {name}: {exc}") from exc

        child = ManagedProcess(
            name=name,
            tag=tag,
            process=process,
            required=required,
            reader_thread=threading.Thread(),
        )
        reader = threading.Thread(
            target=self._stream_output,
            args=(child,),
            name=f"log-{name}",
            daemon=True,
        )
        child.reader_thread = reader
        self.children.append(child)
        reader.start()
        return child

    @staticmethod
    def _stream_output(child: ManagedProcess) -> None:
        stdout = child.process.stdout
        if stdout is None:
            return
        try:
            for raw_line in stdout:
                line = raw_line.rstrip("\r\n")
                if line:
                    Console.emit(child.tag, f"{child.name} | {line}")
        except (OSError, ValueError):
            return

    def monitor(self) -> int:
        """Block until a signal or a required child exits."""
        while not self.stop_event.wait(0.35):
            for child in self.children:
                return_code = child.process.poll()
                if return_code is None or child.exit_reported:
                    continue
                child.exit_reported = True
                Console.emit(child.tag, f"{child.name} exited with code {return_code}")
                if child.required and not self.shutting_down:
                    self.request_shutdown(
                        f"required subsystem {child.name!r} stopped unexpectedly"
                    )
                    return return_code if return_code != 0 else 1
        return 0

    def shutdown(self) -> None:
        with self._lock:
            if self._shutting_down:
                return
            self._shutting_down = True

        self.stop_event.set()
        alive = [child for child in self.children if child.process.poll() is None]
        if not alive:
            return

        Console.emit(TAG_SYSTEM, "stopping child process groups")
        for child in reversed(alive):
            self._signal_group(child, graceful=True)

        deadline = time.monotonic() + self.shutdown_timeout
        for child in reversed(alive):
            remaining = max(0.0, deadline - time.monotonic())
            try:
                child.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass

        stubborn = [child for child in alive if child.process.poll() is None]
        for child in reversed(stubborn):
            Console.emit(
                child.tag,
                f"{child.name} did not stop gracefully; forcing termination",
            )
            self._signal_group(child, graceful=False)

        for child in stubborn:
            try:
                child.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                try:
                    child.process.kill()
                except OSError:
                    pass

        for child in self.children:
            if child.reader_thread.is_alive():
                child.reader_thread.join(timeout=1.0)

    @staticmethod
    def _signal_group(child: ManagedProcess, *, graceful: bool) -> None:
        process = child.process
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                if graceful:
                    try:
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    except (AttributeError, OSError):
                        process.terminate()
                else:
                    taskkill = shutil.which("taskkill")
                    if taskkill:
                        subprocess.run(
                            [taskkill, "/PID", str(process.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    else:
                        process.kill()
            else:
                sig = signal.SIGTERM if graceful else signal.SIGKILL
                os.killpg(process.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate() if graceful else process.kill()
            except OSError:
                pass


def format_command(command: Sequence[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(command))
    return shlex.join(list(command))


def run_foreground(
    *,
    tag: str,
    description: str,
    command: Sequence[str],
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
) -> None:
    """Run a setup/build command while streaming prefixed output."""
    full_env = os.environ.copy()
    if env:
        full_env.update({str(k): str(v) for k, v in env.items()})

    Console.emit(tag, f"{description}: {format_command(command)}")
    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        raise OrchestratorError(f"{description} failed to start: {exc}") from exc

    try:
        if process.stdout is not None:
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                if line:
                    Console.emit(tag, line)
        return_code = process.wait()
    except KeyboardInterrupt:
        try:
            process.terminate()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass
        raise

    if return_code != 0:
        raise OrchestratorError(f"{description} failed with exit code {return_code}")


def command_exists(name: str) -> str | None:
    return shutil.which(name)


def check_repository_layout() -> None:
    required = [
        GO_MOD_FILE,
        SETUP_FILE,
        REQUIREMENTS_FILE,
        WORKER_SCRIPT,
        PROTO_GENERATOR,
        SECURITY_DIR / "certgen.go",
        ROOT / "cmd" / "coordinator" / "main.go",
    ]
    missing = [path for path in required if not path.exists()]
    if missing:
        formatted = ", ".join(str(path.relative_to(ROOT)) for path in missing)
        raise OrchestratorError(
            "run this script from a complete ZeroTrust-FL-Sim checkout; "
            f"missing: {formatted}"
        )


def check_prerequisites(args: argparse.Namespace) -> dict[str, str]:
    Console.emit(TAG_SYSTEM, "checking local prerequisites")
    if sys.version_info < MIN_PYTHON:
        raise OrchestratorError(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; "
            f"running {sys.version.split()[0]}"
        )

    paths: dict[str, str] = {}
    for name in ("go", "cmake", "git"):
        resolved = command_exists(name)
        if not resolved:
            raise OrchestratorError(f"required executable {name!r} was not found on PATH")
        paths[name] = resolved

    pip_check = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if pip_check.returncode != 0:
        raise OrchestratorError("pip is unavailable for the active Python interpreter")

    if os.name != "nt":
        compiler = command_exists("c++") or command_exists("g++") or command_exists("clang++")
        if not compiler:
            raise OrchestratorError(
                "a C++ compiler (c++, g++, or clang++) is required for the C++20 native extension"
            )
        paths["c++"] = compiler
    else:
        compiler = command_exists("cl") or command_exists("clang++")
        if compiler:
            paths["c++"] = compiler
        else:
            Console.emit(
                TAG_CPP,
                "no compiler executable detected on PATH; CMake will attempt to discover an installed Visual Studio C++ toolchain",
            )

    Console.emit(
        TAG_SYSTEM,
        f"Python {sys.version.split()[0]} | Go={paths['go']} | CMake={paths['cmake']}",
    )

    if args.dashboard and (FRONTEND_DIR / "package.json").exists():
        npm = command_exists("npm")
        if npm:
            paths["npm"] = npm
    return paths


def python_runtime_imports_ok() -> bool:
    probe = (
        "import torch, grpc, numpy, psutil, cryptography, prometheus_client;"
        "from opentelemetry.sdk.trace import TracerProvider;"
        "from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def project_imports_ok() -> bool:
    probe = (
        "import zerotrust_fl;"
        "import zerotrust_fl_cpp as native;"
        "assert hasattr(native, 'krum_aggregate')"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def ensure_python_runtime(args: argparse.Namespace) -> None:
    if not python_runtime_imports_ok():
        if not args.auto_install:
            raise OrchestratorError(
                "Python dependencies are missing. Re-run without --no-auto-install or install requirements.txt manually."
            )
        run_foreground(
            tag=TAG_CPP,
            description="installing Python dependencies",
            command=[sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
        )

    proto_files = (
        ROOT / "fl" / "zerotrust_fl" / "protocols" / "fl_service_pb2.py",
        ROOT / "fl" / "zerotrust_fl" / "protocols" / "fl_service_pb2_grpc.py",
    )
    if not all(path.exists() for path in proto_files):
        run_foreground(
            tag=TAG_CPP,
            description="generating Python gRPC protocol bindings",
            command=[sys.executable, str(PROTO_GENERATOR)],
        )

    if not project_imports_ok():
        if args.skip_native_build:
            raise OrchestratorError(
                "zerotrust_fl / zerotrust_fl_cpp is not importable and --skip-native-build was requested"
            )
        build_env = {
            "ZTFL_ENABLE_CUDA": os.environ.get("ZTFL_ENABLE_CUDA", "AUTO"),
            "ZTFL_ENABLE_CKKS": os.environ.get("ZTFL_ENABLE_CKKS", "ON"),
            "ZTFL_ENABLE_OPENMP": os.environ.get("ZTFL_ENABLE_OPENMP", "ON"),
            "ZTFL_NATIVE_ARCH": os.environ.get("ZTFL_NATIVE_ARCH", "ON"),
        }
        run_foreground(
            tag=TAG_CPP,
            description="building C++20 pybind11 native extension",
            command=[sys.executable, "-m", "pip", "install", "-e", str(ROOT)],
            env=build_env,
        )

    verify = (
        "import zerotrust_fl_cpp as n;"
        "print('native version:', getattr(n, '__version__', 'unknown'));"
        "print('OpenMP:', getattr(n, 'openmp_enabled', False));"
        "print('SIMD:', getattr(n, 'simd_backend', 'unknown'));"
        "print('CKKS:', getattr(n, 'ckks_enabled', False));"
        "print('CUDA:', getattr(n, 'cuda_enabled', False))"
    )
    run_foreground(
        tag=TAG_CPP,
        description="verifying native extension",
        command=[sys.executable, "-c", verify],
    )


def worker_ids(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    benign = [f"benign-worker-{index}" for index in range(1, args.benign_workers + 1)]
    malicious = [
        f"malicious-worker-{index}" for index in range(1, args.malicious_workers + 1)
    ]
    if not benign and not malicious:
        raise OrchestratorError("at least one worker must be configured")
    return benign, malicious


def certificate_files_complete(cert_dir: Path, node_ids: Sequence[str]) -> bool:
    required = [
        cert_dir / "ca.crt",
        cert_dir / "server.crt",
        cert_dir / "server.key",
        cert_dir / "jwt_signing_public.pem",
    ]
    for node_id in node_ids:
        required.extend(
            [
                cert_dir / f"{node_id}.crt",
                cert_dir / f"{node_id}.key",
                cert_dir / f"{node_id}.jwt",
            ]
        )
    return all(path.is_file() and path.stat().st_size > 0 for path in required)


def ensure_local_git_exclude(cert_dir: Path) -> None:
    """Prevent locally generated certificates from appearing in git status."""
    git_dir = ROOT / ".git"
    if not git_dir.is_dir():
        return
    try:
        relative = cert_dir.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return
    exclude_file = git_dir / "info" / "exclude"
    exclude_file.parent.mkdir(parents=True, exist_ok=True)
    rule = f"/{relative}/"
    existing = exclude_file.read_text(encoding="utf-8") if exclude_file.exists() else ""
    if rule not in {line.strip() for line in existing.splitlines()}:
        with exclude_file.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write(f"{rule}\n")


def ensure_certificates(
    args: argparse.Namespace,
    go_executable: str,
    benign_ids: Sequence[str],
    malicious_ids: Sequence[str],
) -> Path:
    cert_dir = Path(args.cert_dir).expanduser()
    if not cert_dir.is_absolute():
        cert_dir = (ROOT / cert_dir).resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)
    ensure_local_git_exclude(cert_dir)

    nodes = [*benign_ids, *malicious_ids]
    if not args.force_cert_regen and certificate_files_complete(cert_dir, nodes):
        Console.emit(TAG_COORDINATOR, f"mTLS certificate set is complete: {cert_dir}")
        return cert_dir

    clients = ",".join(f"{node}=edge-worker" for node in nodes)
    command = [
        go_executable,
        "run",
        "./security",
        "-out",
        str(cert_dir),
        "-server-name",
        args.server_name,
        "-trust-domain",
        args.trust_domain,
        "-token-issuer",
        args.token_issuer,
        "-token-audience",
        args.token_audience,
        "-token-ttl",
        args.token_ttl,
        "-certificate-algorithm",
        "ed25519",
        "-clients",
        clients,
    ]
    run_foreground(
        tag=TAG_COORDINATOR,
        description="generating local mTLS certificates and JWTs",
        command=command,
    )
    if not certificate_files_complete(cert_dir, nodes):
        raise OrchestratorError(
            f"certificate generation completed but required artifacts are still missing from {cert_dir}"
        )
    return cert_dir


def port_is_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def assert_port_available(host: str, port: int, purpose: str) -> None:
    if port_is_open(host, port):
        raise OrchestratorError(
            f"{purpose} port {host}:{port} is already in use; stop the existing service or select another port"
        )


def wait_for_port(
    *,
    host: str,
    port: int,
    timeout: float,
    tag: str,
    name: str,
    process: subprocess.Popen[str] | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None:
            return_code = process.poll()
            if return_code is not None:
                raise OrchestratorError(
                    f"{name} exited with code {return_code} before {host}:{port} became ready"
                )
        if port_is_open(host, port):
            Console.emit(tag, f"{name} ready on {host}:{port}")
            return
        time.sleep(0.2)
    raise OrchestratorError(
        f"timed out after {timeout:.1f}s waiting for {name} on {host}:{port}"
    )


def wait_for_health_file(*, path: Path, child: ManagedProcess, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            if content == "ready":
                Console.emit(child.tag, f"{child.name} registered with coordinator")
                return
        return_code = child.process.poll()
        if return_code is not None:
            raise OrchestratorError(
                f"{child.name} exited with code {return_code} before registration completed"
            )
        time.sleep(0.2)
    raise OrchestratorError(f"timed out waiting for {child.name} registration health file")


def coordinator_command(
    *, args: argparse.Namespace, go_executable: str, cert_dir: Path
) -> list[str]:
    metrics_address = (
        f"{DEFAULT_GRPC_HOST}:{args.coordinator_metrics_port}"
        if args.coordinator_metrics_port > 0
        else ""
    )
    command = [
        go_executable,
        "run",
        "./cmd/coordinator",
        "-listen",
        f"{args.grpc_host}:{args.grpc_port}",
        "-server-cert",
        str(cert_dir / "server.crt"),
        "-server-key",
        str(cert_dir / "server.key"),
        "-client-ca",
        str(cert_dir / "ca.crt"),
        "-jwt-public-key",
        str(cert_dir / "jwt_signing_public.pem"),
        "-trust-domain",
        args.trust_domain,
        "-token-issuer",
        args.token_issuer,
        "-token-audience",
        args.token_audience,
        "-registration-lease",
        args.registration_lease,
        "-pqc-mode",
        args.pqc_mode,
        "-metrics-address",
        metrics_address,
    ]
    if args.otel_endpoint.strip():
        command.extend(["-otel-endpoint", args.otel_endpoint.strip()])
        command.append("-otel-insecure=true" if args.otel_insecure else "-otel-insecure=false")
    return command


def launch_workers(
    *,
    args: argparse.Namespace,
    manager: ProcessManager,
    cert_dir: Path,
    benign_ids: Sequence[str],
    malicious_ids: Sequence[str],
) -> list[tuple[ManagedProcess, Path]]:
    health_dir = RUNTIME_DIR / "health"
    health_dir.mkdir(parents=True, exist_ok=True)
    launched: list[tuple[ManagedProcess, Path]] = []
    all_specs: list[tuple[str, str, str, int]] = []

    for index, node_id in enumerate(benign_ids, start=1):
        all_specs.append((node_id, TAG_WORKER_BENIGN, "none", 100 + index * 101))
    for index, node_id in enumerate(malicious_ids, start=1):
        all_specs.append((node_id, TAG_WORKER_ATTACKER, args.attack, 900 + index * 101))

    for worker_index, (node_id, tag, attack, seed) in enumerate(all_specs):
        health_file = health_dir / f"{node_id}.ready"
        try:
            health_file.unlink()
        except FileNotFoundError:
            pass

        command = [
            sys.executable,
            str(WORKER_SCRIPT),
            "--address",
            f"{args.grpc_host}:{args.grpc_port}",
            "--server-name",
            args.server_name,
            "--node-id",
            node_id,
            "--cert-dir",
            str(cert_dir),
            "--attack",
            attack,
            "--seed",
            str(seed),
            "--interval",
            str(args.worker_interval),
            "--health-file",
            str(health_file),
        ]
        if attack == "collusion":
            command.extend(
                [
                    "--collusion-scale",
                    str(args.collusion_scale),
                    "--collusion-seed",
                    str(args.collusion_seed),
                ]
            )

        if args.telemetry:
            metrics_port = args.worker_metrics_base_port + worker_index
            assert_port_available(
                DEFAULT_GRPC_HOST, metrics_port, f"{node_id} Prometheus metrics"
            )
            command.extend(
                [
                    "--telemetry",
                    "--metrics-host",
                    DEFAULT_GRPC_HOST,
                    "--metrics-port",
                    str(metrics_port),
                ]
            )
            if args.otel_endpoint:
                command.extend(["--otel-endpoint", args.otel_endpoint])
                command.append("--otel-insecure" if args.otel_insecure else "--no-otel-insecure")
        else:
            command.append("--no-telemetry")

        child = manager.start(
            name=node_id,
            tag=tag,
            command=command,
            required=True,
        )
        launched.append((child, health_file))
    return launched


def resolve_optional_web_process(
    args: argparse.Namespace, tool_paths: Mapping[str, str]
) -> tuple[list[str] | None, Path, str]:
    """Return (command, cwd, description) for the optional 8080 process."""
    explicit = args.websocket_command.strip()
    if explicit:
        try:
            rendered = explicit.format(port=args.websocket_port)
        except (KeyError, IndexError, ValueError) as exc:
            raise OrchestratorError(f"invalid --websocket-command format string: {exc}") from exc
        command = shlex.split(rendered, posix=os.name != "nt")
        if not command:
            raise OrchestratorError("--websocket-command resolved to an empty command")
        return command, ROOT, "WebSocket service"

    if not args.dashboard:
        return None, ROOT, "dashboard"

    package_json = FRONTEND_DIR / "package.json"
    if not package_json.exists():
        Console.emit(
            TAG_DASHBOARD,
            "frontend/ is not present in this repository; dashboard/WebSocket startup skipped",
        )
        return None, ROOT, "dashboard"

    if not (FRONTEND_DIR / "node_modules").exists():
        message = (
            "frontend/package.json exists but frontend/node_modules is missing; "
            "run npm install in frontend/ to enable dashboard startup"
        )
        if args.dashboard_required:
            raise OrchestratorError(message)
        Console.emit(TAG_DASHBOARD, message)
        return None, ROOT, "dashboard"

    npm = tool_paths.get("npm") or command_exists("npm")
    if not npm:
        message = "npm is unavailable; cannot launch the optional frontend"
        if args.dashboard_required:
            raise OrchestratorError(message)
        Console.emit(TAG_DASHBOARD, message)
        return None, ROOT, "dashboard"

    return (
        [npm, "run", "dev", "--", "--port", str(args.websocket_port)],
        FRONTEND_DIR,
        "Next.js dashboard",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch and monitor the complete ZeroTrust-FL-Sim local stack from one terminal."
    )
    parser.add_argument("--grpc-host", default=DEFAULT_GRPC_HOST)
    parser.add_argument("--grpc-port", type=int, default=DEFAULT_GRPC_PORT)
    parser.add_argument("--websocket-port", type=int, default=DEFAULT_WEBSOCKET_PORT)
    parser.add_argument("--benign-workers", type=int, default=3)
    parser.add_argument("--malicious-workers", type=int, default=1)
    parser.add_argument(
        "--attack",
        choices=["label_flip", "gaussian", "sign_flip", "adaptive", "collusion"],
        default=os.environ.get("ZTFL_ATTACK", "gaussian"),
        help="attack used by malicious workers (default: gaussian noise poisoning)",
    )
    parser.add_argument("--collusion-scale", type=float, default=8.0)
    parser.add_argument("--collusion-seed", type=int, default=20271)
    parser.add_argument("--worker-interval", type=float, default=5.0)
    parser.add_argument("--startup-timeout", type=float, default=60.0)
    parser.add_argument("--shutdown-timeout", type=float, default=10.0)

    parser.add_argument(
        "--cert-dir",
        default=str(DEFAULT_CERT_DIR.relative_to(ROOT)),
        help="local generated PKI directory",
    )
    parser.add_argument("--server-name", default="coordinator.local")
    parser.add_argument("--trust-domain", default="zerotrust-fl.local")
    parser.add_argument("--token-issuer", default="zerotrust-fl-sim")
    parser.add_argument("--token-audience", default="zerotrust-fl-services")
    parser.add_argument("--token-ttl", default="24h")
    parser.add_argument("--registration-lease", default="5m")
    parser.add_argument("--pqc-mode", choices=["off", "prefer", "require"], default="prefer")
    parser.add_argument("--force-cert-regen", action="store_true")

    parser.add_argument(
        "--auto-install",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="install requirements.txt automatically when imports are missing",
    )
    parser.add_argument(
        "--skip-native-build",
        action="store_true",
        help="do not build the native extension when it is missing",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="run prerequisites/build/certificate checks and exit",
    )

    parser.add_argument(
        "--dashboard",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="auto-launch frontend/ when it is installed",
    )
    parser.add_argument(
        "--dashboard-required",
        action="store_true",
        help="treat an unavailable frontend as a fatal startup error",
    )
    parser.add_argument(
        "--websocket-command",
        default=os.environ.get("ZTFL_WEBSOCKET_COMMAND", ""),
        help="optional command that provides the 8080 service; {port} is replaced by --websocket-port",
    )
    parser.add_argument(
        "--require-websocket",
        action="store_true",
        help="fail when no WebSocket/dashboard process is available",
    )

    parser.add_argument(
        "--coordinator-metrics-port",
        type=int,
        default=DEFAULT_COORDINATOR_METRICS_PORT,
        help="Prometheus port for Go coordinator; 0 disables it",
    )
    parser.add_argument(
        "--telemetry",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="enable worker Prometheus/OpenTelemetry instrumentation",
    )
    parser.add_argument(
        "--worker-metrics-base-port", type=int, default=DEFAULT_WORKER_METRICS_BASE_PORT
    )
    parser.add_argument("--otel-endpoint", default=os.environ.get("ZTFL_OTEL_ENDPOINT", ""))
    parser.add_argument(
        "--otel-insecure", action=argparse.BooleanOptionalAction, default=True
    )

    args = parser.parse_args()
    if args.grpc_port <= 0 or args.grpc_port > 65535:
        parser.error("--grpc-port must be in 1..65535")
    if args.websocket_port <= 0 or args.websocket_port > 65535:
        parser.error("--websocket-port must be in 1..65535")
    if args.benign_workers < 0 or args.malicious_workers < 0:
        parser.error("worker counts cannot be negative")
    if args.startup_timeout <= 0:
        parser.error("--startup-timeout must be positive")
    if args.shutdown_timeout <= 0:
        parser.error("--shutdown-timeout must be positive")
    if args.worker_interval <= 0:
        parser.error("--worker-interval must be positive")
    if args.coordinator_metrics_port < 0 or args.coordinator_metrics_port > 65535:
        parser.error("--coordinator-metrics-port must be 0..65535")
    if args.worker_metrics_base_port <= 0 or args.worker_metrics_base_port > 65535:
        parser.error("--worker-metrics-base-port must be in 1..65535")
    return args


def install_signal_handlers(manager: ProcessManager) -> None:
    def _handle(signum: int, _frame: object) -> None:
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)
        manager.request_shutdown(f"received {name}; shutting down")
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle)


def orchestrate(args: argparse.Namespace) -> int:
    check_repository_layout()
    tool_paths = check_prerequisites(args)
    ensure_python_runtime(args)

    benign_ids, malicious_ids = worker_ids(args)
    cert_dir = ensure_certificates(
        args,
        go_executable=tool_paths["go"],
        benign_ids=benign_ids,
        malicious_ids=malicious_ids,
    )

    if args.check_only:
        Console.emit(
            TAG_SYSTEM,
            "prerequisites, native extension, protocol bindings, and PKI are ready",
        )
        return 0

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    assert_port_available(args.grpc_host, args.grpc_port, "gRPC coordinator")
    if args.coordinator_metrics_port > 0:
        assert_port_available(
            DEFAULT_GRPC_HOST,
            args.coordinator_metrics_port,
            "coordinator Prometheus metrics",
        )

    web_command, web_cwd, web_description = resolve_optional_web_process(args, tool_paths)
    if web_command is None and args.require_websocket:
        raise OrchestratorError(
            "WebSocket port 8080 was required, but this repository has no dedicated WebSocket service and no runnable frontend/ or ZTFL_WEBSOCKET_COMMAND was provided"
        )
    if web_command is not None:
        assert_port_available(DEFAULT_GRPC_HOST, args.websocket_port, web_description)

    manager = ProcessManager(shutdown_timeout=args.shutdown_timeout)
    install_signal_handlers(manager)
    atexit.register(manager.shutdown)

    try:
        coordinator = manager.start(
            name="go-coordinator",
            tag=TAG_COORDINATOR,
            command=coordinator_command(
                args=args,
                go_executable=tool_paths["go"],
                cert_dir=cert_dir,
            ),
            required=True,
        )
        wait_for_port(
            host=args.grpc_host,
            port=args.grpc_port,
            timeout=args.startup_timeout,
            tag=TAG_COORDINATOR,
            name="gRPC coordinator",
            process=coordinator.process,
        )

        if web_command is not None:
            dashboard = manager.start(
                name=web_description.lower().replace(" ", "-"),
                tag=TAG_DASHBOARD,
                command=web_command,
                cwd=web_cwd,
                env={"PORT": str(args.websocket_port), "HOSTNAME": DEFAULT_GRPC_HOST},
                required=args.dashboard_required or args.require_websocket,
            )
            try:
                wait_for_port(
                    host=DEFAULT_GRPC_HOST,
                    port=args.websocket_port,
                    timeout=args.startup_timeout,
                    tag=TAG_DASHBOARD,
                    name=web_description,
                    process=dashboard.process,
                )
            except OrchestratorError:
                if args.dashboard_required or args.require_websocket:
                    raise
                Console.emit(
                    TAG_DASHBOARD,
                    f"{web_description} did not become ready; continuing without the optional dashboard",
                )

        workers = launch_workers(
            args=args,
            manager=manager,
            cert_dir=cert_dir,
            benign_ids=benign_ids,
            malicious_ids=malicious_ids,
        )
        for child, health_file in workers:
            wait_for_health_file(
                path=health_file,
                child=child,
                timeout=args.startup_timeout,
            )

        Console.emit(
            TAG_SYSTEM,
            f"stack ready: gRPC={args.grpc_host}:{args.grpc_port}, workers={len(workers)} ({len(benign_ids)} benign, {len(malicious_ids)} attacker)",
        )
        if web_command is None:
            Console.emit(
                TAG_DASHBOARD,
                "8080 check skipped because no WebSocket/dashboard component exists in the current checkout",
            )
        else:
            Console.emit(TAG_DASHBOARD, f"port {args.websocket_port} active")
        Console.emit(TAG_SYSTEM, "press Ctrl+C to stop the complete stack")
        return manager.monitor()
    finally:
        manager.shutdown()


def main() -> int:
    args = parse_args()
    try:
        return orchestrate(args)
    except KeyboardInterrupt:
        Console.emit(TAG_SYSTEM, "interrupted")
        return 130
    except OrchestratorError as exc:
        Console.emit(TAG_SYSTEM, f"fatal: {exc}")
        return 1
    except Exception as exc:
        Console.emit(TAG_SYSTEM, f"unexpected fatal error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
