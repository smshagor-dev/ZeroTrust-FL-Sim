#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VERIFY_DIR="$ROOT_DIR/.cache/verify"
VENV_DIR="$VERIFY_DIR/venv"
TOOLS_DIR="$VERIFY_DIR/bin"
CERT_DIR="$ROOT_DIR/certs/verify"
COORDINATOR_LOG="$VERIFY_DIR/coordinator.log"
COORDINATOR_PID=""

cleanup() {
  if [[ -n "$COORDINATOR_PID" ]] && kill -0 "$COORDINATOR_PID" 2>/dev/null; then
    kill "$COORDINATOR_PID" 2>/dev/null || true
    wait "$COORDINATOR_PID" 2>/dev/null || true
  fi
  rm -rf "$ROOT_DIR/gen"
  rm -f \
    "$ROOT_DIR/fl/zerotrust_fl/protocols/fl_service_pb2.py" \
    "$ROOT_DIR/fl/zerotrust_fl/protocols/fl_service_pb2_grpc.py"
}
trap cleanup EXIT INT TERM

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

require_command go
require_command protoc
require_command "$PYTHON_BIN"

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12 or newer is required")
PY

rm -rf "$VERIFY_DIR" "$ROOT_DIR/cpp/build" "$ROOT_DIR/build" "$ROOT_DIR/.pytest_cache" "$CERT_DIR"
mkdir -p "$TOOLS_DIR" "$VERIFY_DIR"

export GOBIN="$TOOLS_DIR"
export PATH="$TOOLS_DIR:$PATH"

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

protoc \
  --go_out=. --go_opt=module=github.com/smshagor-dev/ZeroTrust-FL-Sim \
  --go-grpc_out=. --go-grpc_opt=module=github.com/smshagor-dev/ZeroTrust-FL-Sim \
  proto/fl_service.proto

go fmt ./...
if ! git diff --quiet -- '*.go'; then
  echo "go fmt changed tracked source files" >&2
  git diff -- '*.go'
  exit 1
fi

go vet ./...
go test -v ./...

"$PYTHON_BIN" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python scripts/generate_python_proto.py
ZTFL_NATIVE_ARCH=OFF python -m pip install -e .
python -m pytest -q

go run ./security \
  -out "$CERT_DIR" \
  -server-name coordinator.local \
  -clients 'verify-worker=edge-worker'

ZTFL_LISTEN_ADDRESS=127.0.0.1:55051 \
ZTFL_SERVER_CERT="$CERT_DIR/server.crt" \
ZTFL_SERVER_KEY="$CERT_DIR/server.key" \
ZTFL_CLIENT_CA="$CERT_DIR/ca.crt" \
ZTFL_JWT_PUBLIC_KEY="$CERT_DIR/jwt_signing_public.pem" \
go run ./cmd/coordinator >"$COORDINATOR_LOG" 2>&1 &
COORDINATOR_PID=$!

for _ in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/55051) >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$COORDINATOR_PID" 2>/dev/null; then
    cat "$COORDINATOR_LOG" >&2
    exit 1
  fi
  sleep 1
done

python scripts/run_grpc_worker.py \
  --address 127.0.0.1:55051 \
  --server-name coordinator.local \
  --node-id verify-worker \
  --cert-dir "$CERT_DIR" \
  --attack none \
  --once

kill "$COORDINATOR_PID"
wait "$COORDINATOR_PID" || true
COORDINATOR_PID=""

python scripts/run_fl_sim.py \
  --dataset synthetic \
  --clients 4 \
  --rounds 3 \
  --partition dirichlet \
  --alpha 0.5 \
  --malicious-fraction 0.25 \
  --attack sign_flip \
  --aggregator median \
  --backend native \
  --max-compute-delay 0.01 \
  --max-network-delay 0.01

echo "ZeroTrust-FL-Sim verification completed successfully"
