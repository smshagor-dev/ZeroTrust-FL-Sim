#!/usr/bin/env python3
"""Run the complete local ZeroTrust-FL-Sim stack from one terminal."""
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
from typing import Sequence

ROOT = Path(__file__).resolve().parent
REQ = ROOT / "requirements.txt"
PROTO = ROOT / "scripts/generate_python_proto.py"
GRPC_WORKER = ROOT / "scripts/run_grpc_worker.py"
TRAINER = ROOT / "scripts/run_master_training.py"
SECURITY = ROOT / "security"
CERTS = ROOT / "security/certs"
FRONTEND = ROOT / "frontend"
RUNTIME = ROOT / "tmp/orchestrator"
HOST = "127.0.0.1"
COLORS = {
    "SYSTEM": "\033[96m", "COORDINATOR": "\033[94m", "CPP-AGGREGATOR": "\033[95m",
    "WORKER-BENIGN": "\033[92m", "WORKER-ATTACKER": "\033[91m", "DASHBOARD": "\033[93m",
}


class OrchestratorError(RuntimeError):
    pass


def log(tag: str, msg: str) -> None:
    label = f"[{tag}]"
    if sys.stdout.isatty() and os.getenv("NO_COLOR") is None:
        label = f"\033[1m{COLORS.get(tag, '')}{label}\033[0m"
    print(f"{time.strftime('%H:%M:%S')} {label} {msg}", flush=True)


def cmd_text(cmd: Sequence[str]) -> str:
    return subprocess.list2cmdline(list(cmd)) if os.name == "nt" else shlex.join(cmd)


def run_checked(tag: str, label: str, cmd: Sequence[str]) -> None:
    log(tag, f"{label}: {cmd_text(cmd)}")
    p = subprocess.Popen(
        list(cmd), cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    if p.stdout:
        for line in p.stdout:
            if line := line.rstrip():
                log(tag, line)
    if p.wait():
        raise OrchestratorError(f"{label} failed")


def available(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise OrchestratorError(f"{name} not found on PATH")
    return path


def prepare(args: argparse.Namespace) -> str:
    if sys.version_info < (3, 12):
        raise OrchestratorError("Python 3.12+ is required")
    go, cmake, git = available("go"), available("cmake"), available("git")
    if os.name != "nt" and not (shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")):
        raise OrchestratorError("C++20 compiler not found")
    log("SYSTEM", f"Python={sys.version.split()[0]} Go={go} CMake={cmake} Git={git}")
    if subprocess.run([sys.executable, "-c", "import torch,grpc,numpy,psutil"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        if not args.auto_install:
            raise OrchestratorError("Python dependencies are missing")
        run_checked("CPP-AGGREGATOR", "install dependencies",
                    [sys.executable, "-m", "pip", "install", "-r", str(REQ)])
    generated = ROOT / "fl/zerotrust_fl/protocols/fl_service_pb2.py"
    if not generated.exists():
        run_checked("CPP-AGGREGATOR", "generate protobuf", [sys.executable, str(PROTO)])
    native_ok = subprocess.run(
        [sys.executable, "-c", "import zerotrust_fl_cpp as n;assert hasattr(n,'median_aggregate')"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not native_ok:
        if args.skip_native_build:
            raise OrchestratorError("native C++ aggregator missing")
        run_checked("CPP-AGGREGATOR", "build C++20 native extension",
                    [sys.executable, "-m", "pip", "install", "-e", str(ROOT)])
    run_checked("CPP-AGGREGATOR", "native backend", [
        sys.executable, "-c",
        "import zerotrust_fl_cpp as n;print('version',getattr(n,'__version__','?'),"
        "'OpenMP',getattr(n,'openmp_enabled',False),'SIMD',getattr(n,'simd_backend','scalar'),"
        "'CUDA',getattr(n,'cuda_enabled',False))",
    ])
    return go


def worker_ids(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    good = [f"benign-worker-{i}" for i in range(1, args.benign_workers + 1)]
    bad = [f"malicious-worker-{i}" for i in range(1, args.malicious_workers + 1)]
    if not good:
        raise OrchestratorError("at least one benign worker is required")
    return good, bad


def ensure_certs(args: argparse.Namespace, go: str, nodes: list[str]) -> Path:
    directory = Path(args.cert_dir)
    if not directory.is_absolute():
        directory = (ROOT / directory).resolve()
    required = [directory / "ca.crt", directory / "server.crt", directory / "server.key",
                directory / "jwt_signing_public.pem"]
    for node in nodes:
        required += [directory / f"{node}.crt", directory / f"{node}.key", directory / f"{node}.jwt"]
    if args.force_cert_regen or not all(p.exists() and p.stat().st_size for p in required):
        directory.mkdir(parents=True, exist_ok=True)
        run_checked("COORDINATOR", "generate mTLS PKI", [
            go, "run", "./security", "-out", str(directory), "-server-name", args.server_name,
            "-trust-domain", "zerotrust-fl.local", "-token-issuer", "zerotrust-fl-sim",
            "-token-audience", "zerotrust-fl-services", "-token-ttl", "24h",
            "-certificate-algorithm", "ed25519", "-clients",
            ",".join(f"{node}=edge-worker" for node in nodes),
        ])
    return directory


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=.25):
            return True
    except OSError:
        return False


@dataclass
class Child:
    name: str
    tag: str
    p: subprocess.Popen[str]
    final: bool = False
    optional: bool = False
    reader: threading.Thread | None = None


class Manager:
    def __init__(self, timeout: float) -> None:
        self.timeout, self.children, self.stop = timeout, [], threading.Event()
        self.closing = False

    def start(self, name: str, tag: str, cmd: Sequence[str], *, final: bool = False,
              optional: bool = False, cwd: Path = ROOT) -> Child:
        env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
        kw: dict[str, object] = dict(
            cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        if os.name == "nt": kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else: kw["start_new_session"] = True
        log(tag, f"starting {name}: {cmd_text(cmd)}")
        p = subprocess.Popen(list(cmd), **kw)  # type: ignore[arg-type]
        child = Child(name, tag, p, final, optional)
        child.reader = threading.Thread(target=self._read, args=(child,), daemon=True); child.reader.start()
        self.children.append(child); return child

    @staticmethod
    def _read(child: Child) -> None:
        if child.p.stdout:
            for line in child.p.stdout:
                if line := line.rstrip(): log(child.tag, f"{child.name} | {line}")

    def wait(self) -> int:
        seen: set[int] = set()
        while not self.stop.wait(.25):
            for c in self.children:
                rc = c.p.poll()
                if rc is None or c.p.pid in seen: continue
                seen.add(c.p.pid); log(c.tag, f"{c.name} exited with code {rc}")
                if c.final: self.stop.set(); return rc or 0
                if not c.optional and not self.closing: self.stop.set(); return rc or 1
        return 0

    def shutdown(self) -> None:
        if self.closing: return
        self.closing = True; self.stop.set()
        alive = [c for c in self.children if c.p.poll() is None]
        if not alive: return
        log("SYSTEM", "stopping all child process groups")
        for c in reversed(alive): self._signal(c.p, True)
        end = time.monotonic() + self.timeout
        for c in reversed(alive):
            try: c.p.wait(timeout=max(0, end - time.monotonic()))
            except subprocess.TimeoutExpired: pass
        for c in reversed([x for x in alive if x.p.poll() is None]): self._signal(c.p, False)

    @staticmethod
    def _signal(p: subprocess.Popen[str], graceful: bool) -> None:
        try:
            if os.name == "nt":
                if graceful:
                    try: p.send_signal(signal.CTRL_BREAK_EVENT)
                    except (AttributeError, OSError): p.terminate()
                else:
                    taskkill = shutil.which("taskkill")
                    if taskkill: subprocess.run([taskkill, "/PID", str(p.pid), "/T", "/F"],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else: p.kill()
            else: os.killpg(p.pid, signal.SIGTERM if graceful else signal.SIGKILL)
        except OSError: pass


def wait_port(child: Child, host: str, port: int, timeout: float, manager: Manager) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if manager.stop.is_set(): raise KeyboardInterrupt
        if child.p.poll() is not None: raise OrchestratorError(f"{child.name} exited before readiness")
        if port_open(host, port): log(child.tag, f"ready on {host}:{port}"); return
        time.sleep(.2)
    raise OrchestratorError(f"timeout waiting for {child.name}")


def validate(args: argparse.Namespace) -> None:
    n, f = args.benign_workers + args.malicious_workers, args.malicious_workers
    if n <= 0 or f >= n: raise OrchestratorError("training requires at least one benign client")
    if args.aggregator in {"krum", "multi_krum"} and n < 2*f + 3:
        raise OrchestratorError(f"{args.aggregator} needs n>=2f+3; got n={n}, f={f}. Use median or add clients.")


def trainer_cmd(args: argparse.Namespace) -> list[str]:
    n = args.benign_workers + args.malicious_workers
    cmd = [sys.executable, "-u", str(TRAINER), "--dataset", args.dataset, "--clients", str(n),
           "--clients-per-round", str(n), "--min-results", str(n), "--rounds", str(args.rounds),
           "--partition", args.partition, "--alpha", str(args.alpha), "--malicious-fraction",
           str(args.malicious_workers/n), "--attack", args.attack, "--aggregator", args.aggregator,
           "--backend", "native", "--device", args.device, "--seed", str(args.seed), "--no-telemetry"]
    if args.aggregator in {"krum", "multi_krum"}: cmd += ["--byzantine-f", str(args.malicious_workers)]
    if args.attack == "collusion": cmd += ["--collusion-scale", "8", "--collusion-seed", "20271"]
    return cmd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Go + PyTorch workers + native C++ FL aggregation from one terminal.")
    p.add_argument("--grpc-port", type=int, default=50051); p.add_argument("--metrics-port", type=int, default=9464)
    p.add_argument("--benign-workers", type=int, default=3); p.add_argument("--malicious-workers", type=int, default=1)
    p.add_argument("--attack", choices=["label_flip","gaussian","sign_flip","adaptive","collusion"], default="gaussian")
    p.add_argument("--aggregator", choices=["krum","multi_krum","trimmed_mean","median"], default="median")
    p.add_argument("--rounds", type=int, default=5); p.add_argument("--dataset", choices=["synthetic","fashion-mnist","cifar10"], default="synthetic")
    p.add_argument("--partition", choices=["iid","dirichlet"], default="dirichlet"); p.add_argument("--alpha", type=float, default=.3)
    p.add_argument("--device", default="cpu"); p.add_argument("--seed", type=int, default=42); p.add_argument("--worker-interval", type=float, default=5)
    p.add_argument("--server-name", default="coordinator.local"); p.add_argument("--cert-dir", default=str(CERTS.relative_to(ROOT)))
    p.add_argument("--pqc-mode", choices=["off","prefer","require"], default="prefer"); p.add_argument("--force-cert-regen", action="store_true")
    p.add_argument("--network-workers", action=argparse.BooleanOptionalAction, default=True); p.add_argument("--auto-install", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--skip-native-build", action="store_true"); p.add_argument("--check-only", action="store_true")
    p.add_argument("--startup-timeout", type=float, default=90); p.add_argument("--shutdown-timeout", type=float, default=12)
    p.add_argument("--dashboard", action=argparse.BooleanOptionalAction, default=True); p.add_argument("--websocket-port", type=int, default=8080)
    args = p.parse_args(); validate(args); return args


def orchestrate(args: argparse.Namespace) -> int:
    for path in (REQ, PROTO, GRPC_WORKER, TRAINER, SECURITY/"certgen.go", ROOT/"cmd/coordinator/main.go"):
        if not path.exists(): raise OrchestratorError(f"missing {path.relative_to(ROOT)}")
    go = prepare(args); good, bad = worker_ids(args); certs = ensure_certs(args, go, good+bad)
    if args.check_only: log("SYSTEM", "prerequisites/native backend/PKI/topology ready"); return 0
    for port in (args.grpc_port, args.metrics_port):
        if port_open(HOST, port): raise OrchestratorError(f"port {port} already in use")
    m = Manager(args.shutdown_timeout); atexit.register(m.shutdown); RUNTIME.mkdir(parents=True, exist_ok=True)
    def on_signal(signum: int, _frame: object) -> None:
        log("SYSTEM", f"received {signal.Signals(signum).name}; shutting down"); m.stop.set()
    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGTERM"): signal.signal(signal.SIGTERM, on_signal)
    try:
        coord_cmd = [go,"run","./cmd/coordinator","-listen",f"{HOST}:{args.grpc_port}","-server-cert",str(certs/"server.crt"),
                     "-server-key",str(certs/"server.key"),"-client-ca",str(certs/"ca.crt"),"-jwt-public-key",str(certs/"jwt_signing_public.pem"),
                     "-trust-domain","zerotrust-fl.local","-token-issuer","zerotrust-fl-sim","-token-audience","zerotrust-fl-services",
                     "-pqc-mode",args.pqc_mode,"-metrics-address",f"{HOST}:{args.metrics_port}"]
        coord = m.start("go-coordinator","COORDINATOR",coord_cmd); wait_port(coord,HOST,args.grpc_port,args.startup_timeout,m)
        if args.network_workers:
            health_dir = RUNTIME/"health"; health_dir.mkdir(parents=True, exist_ok=True)
            specs = [(n,"WORKER-BENIGN","none",1000+i) for i,n in enumerate(good)] + [(n,"WORKER-ATTACKER",args.attack,9000+i) for i,n in enumerate(bad)]
            for node,tag,attack,seed in specs:
                hf=health_dir/f"{node}.ready"; hf.unlink(missing_ok=True)
                wc=[sys.executable,"-u",str(GRPC_WORKER),"--address",f"{HOST}:{args.grpc_port}","--server-name",args.server_name,"--node-id",node,
                    "--cert-dir",str(certs),"--attack",attack,"--seed",str(seed),"--interval",str(args.worker_interval),"--health-file",str(hf),"--no-telemetry"]
                child=m.start(node,tag,wc); end=time.monotonic()+args.startup_timeout
                while not hf.exists() and time.monotonic()<end:
                    if child.p.poll() is not None: raise OrchestratorError(f"{node} failed registration")
                    time.sleep(.2)
                if not hf.exists(): raise OrchestratorError(f"timeout registering {node}")
                log(tag,f"{node} registered")
        if args.dashboard and (FRONTEND/"package.json").exists() and (FRONTEND/"node_modules").exists() and shutil.which("npm"):
            m.start("dashboard","DASHBOARD",[shutil.which("npm") or "npm","run","dev","--","--port",str(args.websocket_port)],cwd=FRONTEND,optional=True)
        else: log("DASHBOARD","frontend not installed; skipped")
        log("CPP-AGGREGATOR",f"training {len(good)} benign + {len(bad)} attacker(s), native {args.aggregator}, rounds={args.rounds}")
        train=m.start("federated-training","CPP-AGGREGATOR",trainer_cmd(args),final=True)
        time.sleep(.5)
        if train.p.poll() is not None: raise OrchestratorError(f"training exited immediately: {train.p.returncode}")
        log("SYSTEM","Go + secure workers + multi-process PyTorch + native C++ filtering are live")
        return m.wait()
    finally: m.shutdown()


def main() -> int:
    try: return orchestrate(parse_args())
    except KeyboardInterrupt: log("SYSTEM","interrupted"); return 130
    except OrchestratorError as exc: log("SYSTEM",f"fatal: {exc}"); return 1
    except Exception as exc: log("SYSTEM",f"unexpected {type(exc).__name__}: {exc}"); return 1


if __name__ == "__main__": raise SystemExit(main())
