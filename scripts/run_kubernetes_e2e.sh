#!/usr/bin/env bash
set -euo pipefail

COMMIT_SHA="${ZTFL_COMMIT_SHA:-${GITHUB_SHA:-}}"
if [[ ! "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ZTFL_COMMIT_SHA or GITHUB_SHA must be a full lowercase 40-character commit SHA" >&2
  exit 2
fi

CLUSTER_NAME="${ZTFL_KIND_CLUSTER:-ztfl-ci}"
REGISTRY_NAME="${ZTFL_KIND_REGISTRY:-ztfl-kind-registry}"
REGISTRY_PORT="${ZTFL_KIND_REGISTRY_PORT:-5001}"
NAMESPACE="zerotrust-fl"
RELEASE="ztfl"
FULLNAME="ztfl-zerotrust-fl"
COORDINATOR_DEPLOYMENT="${FULLNAME}-coordinator"
WORKER_NAME="benign-worker-1"
WORKER_DEPLOYMENT="${FULLNAME}-${WORKER_NAME}"
WORKDIR="${ZTFL_E2E_WORKDIR:-.k8s-e2e}"
BENCHMARK_DIR="${ZTFL_BENCHMARK_DIR:-benchmarks/results}"
COORDINATOR_IMAGE="localhost:${REGISTRY_PORT}/ztfl-coordinator:${COMMIT_SHA}"
WORKER_IMAGE="localhost:${REGISTRY_PORT}/ztfl-worker:${COMMIT_SHA}"

cleanup() {
  set +e
  kubectl -n "$NAMESPACE" get all -o wide >"$WORKDIR/kubernetes-resources.txt" 2>&1 || true
  kubectl -n "$NAMESPACE" logs deployment/"$COORDINATOR_DEPLOYMENT" --all-containers=true >"$WORKDIR/coordinator.log" 2>&1 || true
  kubectl -n "$NAMESPACE" logs deployment/"$WORKER_DEPLOYMENT" --all-containers=true >"$WORKDIR/worker.log" 2>&1 || true
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/pki" "$BENCHMARK_DIR"
chmod 0777 "$BENCHMARK_DIR"

docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
docker run -d --restart=always \
  -p "127.0.0.1:${REGISTRY_PORT}:5000" \
  --name "$REGISTRY_NAME" \
  registry:2.8.3 >/dev/null

cat >"$WORKDIR/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REGISTRY_PORT}"]
      endpoint = ["http://${REGISTRY_NAME}:5000"]
EOF

kind create cluster --name "$CLUSTER_NAME" --config "$WORKDIR/kind-config.yaml" --wait 120s
docker network connect kind "$REGISTRY_NAME" >/dev/null 2>&1 || true
kubectl cluster-info

docker build --pull -f docker/Dockerfile.coordinator -t "$COORDINATOR_IMAGE" .
docker build --pull -f docker/Dockerfile.worker -t "$WORKER_IMAGE" .
docker push "$COORDINATOR_IMAGE"
docker push "$WORKER_IMAGE"

registry_digest() {
  local repository="$1"
  local digest
  digest="$(curl -fsSI \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "http://127.0.0.1:${REGISTRY_PORT}/v2/${repository}/manifests/${COMMIT_SHA}" \
    | tr -d '\r' \
    | awk -F': ' 'tolower($1) == "docker-content-digest" {print $2}')"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "could not resolve immutable registry digest for ${repository}: ${digest}" >&2
    exit 1
  fi
  printf '%s\n' "$digest"
}

COORDINATOR_DIGEST="$(registry_digest ztfl-coordinator)"
WORKER_DIGEST="$(registry_digest ztfl-worker)"

# Generate CI-only PKI with the exact Kubernetes coordinator DNS name used by workers.
docker run --rm --user 0:0 \
  -e "ZTFL_SERVER_NAME=${COORDINATOR_DEPLOYMENT}" \
  -v "$PWD/$WORKDIR/pki:/out" \
  --entrypoint /bin/sh \
  "$COORDINATOR_IMAGE" \
  /usr/local/bin/generate-dev-pki.sh
sudo chown -R "$(id -u):$(id -g)" "$WORKDIR/pki"

kubectl create namespace "$NAMESPACE"
kubectl -n "$NAMESPACE" create secret generic ci-coordinator-pki \
  --from-file=ca.crt="$WORKDIR/pki/coordinator/ca.crt" \
  --from-file=server.crt="$WORKDIR/pki/coordinator/server.crt" \
  --from-file=server.key="$WORKDIR/pki/coordinator/server.key" \
  --from-file=jwt_signing_public.pem="$WORKDIR/pki/coordinator/jwt_signing_public.pem"
kubectl -n "$NAMESPACE" create secret generic ci-coordinator-runtime \
  --from-literal=ZTFL_STATE_FILE=/tmp/coordinator-state.json \
  --from-literal=ZTFL_MIN_UPDATES=1 \
  --from-literal=ZTFL_MAX_UPDATES_PER_MINUTE=120
kubectl -n "$NAMESPACE" create secret generic ci-worker-01-pki \
  --from-file=ca.crt="$WORKDIR/pki/${WORKER_NAME}/ca.crt" \
  --from-file="${WORKER_NAME}.crt=$WORKDIR/pki/${WORKER_NAME}/${WORKER_NAME}.crt" \
  --from-file="${WORKER_NAME}.key=$WORKDIR/pki/${WORKER_NAME}/${WORKER_NAME}.key" \
  --from-file="${WORKER_NAME}.jwt=$WORKDIR/pki/${WORKER_NAME}/${WORKER_NAME}.jwt"

cat >"$WORKDIR/values.yaml" <<EOF
global:
  modelId: ci-model
  experimentId: ci-kubernetes
  trustDomain: zerotrust-fl.local
coordinator:
  image:
    repository: localhost:${REGISTRY_PORT}/ztfl-coordinator
    digest: ${COORDINATOR_DIGEST}
  pkiSecretName: ci-coordinator-pki
  runtimeSecretName: ci-coordinator-runtime
  service:
    port: 50051
    metricsPort: 9464
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: "2"
      memory: 1Gi
workers:
  - name: ${WORKER_NAME}
    image:
      repository: localhost:${REGISTRY_PORT}/ztfl-worker
      digest: ${WORKER_DIGEST}
    secretName: ci-worker-01-pki
    attack: none
    resources:
      requests:
        cpu: 250m
        memory: 512Mi
      limits:
        cpu: "2"
        memory: 4Gi
networkPolicy:
  enabled: true
  externalEgressPorts:
    - 443
    - 5432
    - 9000
EOF

helm lint deploy/helm/zerotrust-fl -f "$WORKDIR/values.yaml"
helm upgrade --install "$RELEASE" deploy/helm/zerotrust-fl \
  --namespace "$NAMESPACE" \
  -f "$WORKDIR/values.yaml" \
  --wait --timeout 5m

kubectl -n "$NAMESPACE" rollout status deployment/"$COORDINATOR_DEPLOYMENT" --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/"$WORKER_DEPLOYMENT" --timeout=240s

for _ in $(seq 1 90); do
  if kubectl -n "$NAMESPACE" logs deployment/"$WORKER_DEPLOYMENT" --all-containers=true 2>/dev/null | grep -q 'update='; then
    break
  fi
  sleep 2
done
if ! kubectl -n "$NAMESPACE" logs deployment/"$WORKER_DEPLOYMENT" --all-containers=true | grep -q 'update='; then
  echo "worker never completed an authenticated model update" >&2
  exit 1
fi

# Quiesce the writer before taking the durable-state baseline. Capturing the
# file while the worker remains live races a legitimate subsequent update and
# can make model_proto differ even when coordinator restart recovery is exact.
kubectl -n "$NAMESPACE" scale deployment/"$WORKER_DEPLOYMENT" --replicas=0
kubectl -n "$NAMESPACE" wait --for=delete pod -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=worker" --timeout=120s || true

kubectl -n "$NAMESPACE" exec deployment/"$COORDINATOR_DEPLOYMENT" -- cat /tmp/coordinator-state.json >"$WORKDIR/state-before.json"
python - "$WORKDIR/state-before.json" <<'PY'
import base64
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if state.get("schema_version") != 3:
    raise SystemExit(f"unexpected durable schema: {state.get('schema_version')}")
policy = state.get("policy") or {}
if policy.get("model_id") != "ci-model":
    raise SystemExit(f"unexpected durable model_id: {policy.get('model_id')!r}")
model = base64.b64decode(state.get("model_proto", ""))
if b"round-" not in model:
    raise SystemExit("Kubernetes worker did not advance the global model beyond bootstrap")
PY

# Restart only the coordinator container and verify the emptyDir-backed state
# survives the container restart without identity or model drift.
COORD_POD="$(kubectl -n "$NAMESPACE" get pod -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=coordinator" -o jsonpath='{.items[0].metadata.name}')"
RESTART_BEFORE="$(kubectl -n "$NAMESPACE" get pod "$COORD_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
kubectl -n "$NAMESPACE" exec "$COORD_POD" -- sh -c 'kill -TERM 1' >/dev/null 2>&1 || true

for _ in $(seq 1 90); do
  RESTART_AFTER="$(kubectl -n "$NAMESPACE" get pod "$COORD_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
  READY="$(kubectl -n "$NAMESPACE" get pod "$COORD_POD" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo false)"
  if (( RESTART_AFTER > RESTART_BEFORE )) && [[ "$READY" == "true" ]]; then
    break
  fi
  sleep 2
done
RESTART_AFTER="$(kubectl -n "$NAMESPACE" get pod "$COORD_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
if (( RESTART_AFTER <= RESTART_BEFORE )); then
  echo "coordinator container did not restart" >&2
  exit 1
fi
kubectl -n "$NAMESPACE" exec "$COORD_POD" -- cat /tmp/coordinator-state.json >"$WORKDIR/state-after.json"
python - "$WORKDIR/state-before.json" "$WORKDIR/state-after.json" <<'PY'
import json
import sys
from pathlib import Path

before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
for field in ("schema_version", "policy", "model_proto", "pending_updates"):
    if before.get(field) != after.get(field):
        raise SystemExit(f"coordinator restart changed durable field {field}")
PY

kubectl -n "$NAMESPACE" scale deployment/"$WORKER_DEPLOYMENT" --replicas=1
kubectl -n "$NAMESPACE" rollout status deployment/"$WORKER_DEPLOYMENT" --timeout=240s

# Produce benchmark evidence from the same immutable worker image used above.
docker run --rm \
  -e "ZTFL_COMMIT_SHA=${COMMIT_SHA}" \
  -v "$PWD/$BENCHMARK_DIR:/app/benchmarks/results" \
  --entrypoint python \
  "$WORKER_IMAGE" \
  /app/benchmarks/run_release_benchmark.py \
  --profile quick \
  --sections aggregation network convergence \
  --output-dir /app/benchmarks/results

python - "$BENCHMARK_DIR/benchmark-manifest.json" "$COMMIT_SHA" <<'PY'
import hashlib
import json
import sys
import tomllib
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
expected_release_version = project["project"]["version"]
if manifest.get("schema_version") != 1:
    raise SystemExit("unexpected benchmark manifest schema")
if manifest.get("release_version") != expected_release_version:
    raise SystemExit(
        "benchmark manifest release version mismatch: "
        f"expected {expected_release_version}, got {manifest.get('release_version')!r}"
    )
if manifest.get("commit_sha") != sys.argv[2]:
    raise SystemExit("benchmark manifest commit mismatch")
benchmark = manifest.get("benchmark")
canonical = json.dumps(benchmark, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
if manifest.get("benchmark_config_sha256") != actual:
    raise SystemExit("benchmark manifest configuration digest mismatch")
PY

echo "Kubernetes supported-profile E2E and benchmark evidence passed for ${COMMIT_SHA}"
