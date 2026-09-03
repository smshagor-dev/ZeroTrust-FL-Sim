# Asynchronous Federated Learning Simulation

The Python runtime simulates independent FL edge workers as persistent operating-system processes. Each worker owns one dataset partition, receives a global parameter vector, trains locally, optionally applies an adversarial transformation, and returns a model delta to the parent coordinator.

## Execution model

The local simulation path is intentionally independent of the network path:

1. The parent coordinator creates one persistent process per simulated edge worker.
2. Worker datasets are transferred once when processes are spawned.
3. Each round broadcasts the current trainable parameter vector to selected workers.
4. Workers perform local SGD or Adam with independently sampled epoch counts, learning-rate jitter, computation delay, and network delay.
5. A round may close when the configured successful-result quorum is reached. Late workers remain busy and are reclaimed when their results arrive.
6. The parent aggregates model deltas with the native C++ backend when available, or a deterministic PyTorch fallback when explicitly selected.
7. The aggregate delta is applied to the global model and the evaluation dataset is measured.

Model buffers are preserved by the coordinator. The current simulation aggregates trainable parameters, so models used for comparative experiments should avoid stateful BatchNorm buffers unless buffer synchronization is added explicitly.

## Dataset partitioning

IID:

```python
from zerotrust_fl.data import iid_partition

partitions = iid_partition(labels, num_clients=10, seed=42)
```

Dirichlet non-IID:

```python
from zerotrust_fl.data import dirichlet_partition

partitions = dirichlet_partition(
    labels,
    num_clients=10,
    alpha=0.2,
    seed=42,
    min_samples_per_client=20,
)
```

Smaller Dirichlet alpha values create stronger per-client class skew. Every sample is assigned exactly once.

## Attack suite

Available worker attack modes:

- `label_flip`: targeted or mapping-based local label manipulation before loss computation.
- `gaussian`: additive Gaussian noise applied directly to the final model delta.
- `sign_flip`: `delta -> -gamma * delta`.
- `adaptive`: reverses the local delta while clipping it to a configurable norm envelope.
- `none`: benign worker.

The attack configuration is deterministic per worker and round when a seed is supplied.

## Native aggregation

The coordinator supports:

- mean
- Krum
- Multi-Krum
- trimmed mean
- coordinate-wise median

`backend="auto"` uses `zerotrust_fl_cpp` when the compiled extension is available and otherwise falls back to PyTorch. `backend="native"` fails closed when the native extension cannot be loaded.

## Generate Python gRPC stubs

The Python mTLS worker uses the same `proto/fl_service.proto` contract as the Go coordinator.

```bash
python scripts/generate_python_proto.py
```

The generator writes:

```text
fl/zerotrust_fl/protocols/fl_service_pb2.py
fl/zerotrust_fl/protocols/fl_service_pb2_grpc.py
```

It also rewrites the generated sibling import to a package-relative import so the stubs work inside the installed `zerotrust_fl` package.

## Secure gRPC worker

```python
from zerotrust_fl.client import GrpcWorkerClient, GrpcWorkerConfig, UpdateMetrics

config = GrpcWorkerConfig(
    address="127.0.0.1:50051",
    node_id="edge-worker-01",
    certificate_common_name="edge-worker-01",
    ca_certificate="certs/dev/ca.crt",
    client_certificate="certs/dev/edge-worker-01.crt",
    client_private_key="certs/dev/edge-worker-01.key",
    jwt_token_file="certs/dev/edge-worker-01.jwt",
)

with GrpcWorkerClient(config) as client:
    client.wait_ready()
    registration = client.register()
    model = client.get_global_model()
```

The channel always uses `grpc.secure_channel` with the configured root CA, client certificate, and private key. Every RPC carries `Authorization: Bearer <token>` metadata. Bearer credentials are not duplicated into the protobuf request body.

The current Go coordinator validates registration, model version, round ID, update digest, mTLS identity, and JWT/RBAC policy. It does not yet advance the global model after accepting updates. Therefore the local multi-process simulator owns training-round progression, while `GrpcWorkerClient` is the secure transport integration for coordinator registration/model retrieval/update submission against the coordinator's current round state.

## Run a local attack simulation

Install and build:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python scripts/generate_python_proto.py
pip install -e .
```

Run 10 workers with 20% malicious sign-flipping clients and Multi-Krum:

```bash
python scripts/run_fl_sim.py \
  --dataset synthetic \
  --clients 10 \
  --rounds 10 \
  --partition dirichlet \
  --alpha 0.2 \
  --malicious-fraction 0.2 \
  --attack sign_flip \
  --aggregator multi_krum \
  --byzantine-f 2 \
  --multi-krum-k 3 \
  --backend native
```

Allow a round to close after eight successful workers to model stragglers:

```bash
python scripts/run_fl_sim.py \
  --clients 10 \
  --clients-per-round 10 \
  --min-results 8 \
  --rounds 5 \
  --aggregator median \
  --max-compute-delay 1.0 \
  --max-network-delay 0.2
```

Fashion-MNIST and CIFAR-10 are also supported:

```bash
python scripts/run_fl_sim.py --dataset fashion-mnist --clients 10 --rounds 5
python scripts/run_fl_sim.py --dataset cifar10 --clients 10 --rounds 5
```

## Test

```bash
pytest tests/test_fl_engine.py -q
```

The engine tests verify exact partition coverage, non-IID class skew, label attacks, update attacks, safe non-pickle update serialization, multi-round spawned-process training, clean child-process shutdown, and quorum-based straggler handling.
