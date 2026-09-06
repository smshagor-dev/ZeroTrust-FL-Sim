# Stable Python SDK

The supported Python API for the v0.7 line is the top-level `zerotrust_fl` package and `zerotrust_fl.sdk`. Internal modules remain implementation details unless they are explicitly re-exported by that stable surface.

## Compatibility contract

`SDK_API_VERSION = "1"` identifies the source-level SDK contract independently from the package release number. Within SDK API v1, public names are not removed or given incompatible signatures in a patch/minor release. Additive optional fields and new public types are permitted. A future incompatible SDK requires a new API version and migration notes.

The stable public types are `WorkerConfig`, `WorkerClient`, `Enrollment`, `HeartbeatStatus`, `ModelSnapshot`, `TensorManifest`, `UpdateMetrics`, and `UpdateSubmission`.

`WorkerClient` is a typed facade over the existing strict mTLS gRPC transport. It retains TLS 1.3 peer verification, workload certificate checks, JWT authorization, model-envelope validation, payload SHA-256 validation, and protocol-v1 schema validation. It intentionally does not expose protobuf response objects as the stable API.

## Example

```python
from zerotrust_fl import WorkerClient, WorkerConfig

config = WorkerConfig(
    address="coordinator.example.net:50051",
    node_id="worker-01",
    certificate_common_name="worker-01",
    ca_certificate="/run/ztfl/ca.crt",
    client_certificate="/run/ztfl/worker-01.crt",
    client_private_key="/run/ztfl/worker-01.key",
    jwt_token_file="/run/ztfl/worker-01.jwt",
    server_name_override="coordinator.example.net",
    model_id="experiment-model",
)

with WorkerClient(config) as client:
    client.wait_ready()
    enrollment = client.enroll()
    model = client.get_model()
```

Each workload must receive only its own client certificate, private key, and JWT credential. Do not mount a shared worker credential bundle into multiple production workers.

## Operator CLI

Installing the package exposes `ztfl`:

- `ztfl validate --profile coordinator --production` validates production-critical coordinator inputs.
- `ztfl validate --profile worker --node-id worker-01` validates one worker credential set.
- `ztfl coordinator-start --binary /usr/local/bin/coordinator -- ...` replaces the current process with the coordinator binary.
- `ztfl worker-enroll ...` performs authenticated enrollment and prints machine-readable JSON.
- `ztfl experiment-status ...` returns the live model/round and lease status as JSON.
- `ztfl diagnostics ...` verifies credential loading, TLS server identity, and coordinator reachability without submitting an update.
