# ZeroTrust-FL-Sim

ZeroTrust-FL-Sim is a software-only federated learning simulation platform for evaluating secure distributed learning under adversarial, faulty, and partially trusted conditions.

The system combines a Go control plane for secure gRPC communication and authorization, a Python/PyTorch federated learning runtime, and a native C++ aggregation layer for performance-sensitive Byzantine-robust aggregation.

No physical hardware, sensors, embedded devices, or external robotics platforms are required.

## System Overview

```text
                    +-----------------------------+
                    |       Go Control Plane      |
                    |-----------------------------|
                    | gRPC                        |
                    | Mutual TLS                  |
                    | Token Authentication        |
                    | RBAC / Policy Enforcement   |
                    | Audit Events                |
                    +-------------+---------------+
                                  |
                           Secure RPC Boundary
                                  |
              +-------------------+-------------------+
              |                                       |
       +------v-------+                         +------v-------+
       | FL Client 01 |           ...           | FL Client N  |
       | Python       |                         | Python       |
       | PyTorch      |                         | PyTorch      |
       +------+-------+                         +------+-------+
              |                                       |
              +-------------------+-------------------+
                                  |
                           Model Updates
                                  |
                        +---------v---------+
                        | FL Coordinator    |
                        | Python / PyTorch  |
                        +---------+---------+
                                  |
                           Native Extension
                                  |
                        +---------v---------+
                        | C++ Aggregation   |
                        |-------------------|
                        | Trimmed Mean      |
                        | Krum / Multi-Krum |
                        | Adaptive Methods  |
                        +-------------------+
```

## Core Goals

- Enforce authenticated and encrypted communication between distributed components.
- Treat peers as untrusted until identity and permissions are verified.
- Separate authentication, authorization, and transport security.
- Support mutual TLS identities, signed tokens, and role-based access control.
- Simulate federated clients using local processes or isolated Docker containers.
- Support benign, faulty, and Byzantine client behavior.
- Provide reproducible IID and non-IID training experiments.
- Keep performance-sensitive aggregation logic in a small native C++ boundary.
- Measure correctness, robustness, latency, throughput, and convergence behavior.
- Keep generated secrets, model artifacts, datasets, and experiment outputs out of source control.

## Technology Stack

| Area | Technology |
| --- | --- |
| Control plane | Go 1.27+ |
| RPC | gRPC |
| Transport security | TLS / Mutual TLS |
| Authentication | Certificate identity and signed tokens |
| Authorization | RBAC and policy checks |
| FL runtime | Python 3.12+ |
| ML framework | PyTorch |
| Native aggregation | C++20 |
| Python/C++ bridge | pybind11 |
| Serialization | Protocol Buffers |
| Native build system | CMake |
| Distributed simulation | Multiprocessing / Docker |
| Tests | Go test / pytest / CTest |
| Automation | GitHub Actions |

## Repository Layout

```text
ZeroTrust-FL-Sim/
├── .github/workflows/        CI workflows
├── cmd/control-plane/        Go executable entry point
├── internal/                 Go control-plane implementation
│   ├── config/               Configuration loading
│   ├── security/             Authentication, authorization, TLS and tokens
│   ├── server/               gRPC server implementation
│   └── telemetry/            Logging and audit events
├── proto/zerotrust/v1/       Language-neutral RPC contracts
├── fl/                       Python federated learning runtime
│   ├── zerotrust_fl/         Python package
│   └── tests/                Python tests
├── cpp/                      Native robust aggregation extension
│   ├── include/              Public C++ headers
│   ├── src/                  Native sources and bindings
│   └── tests/                Native tests
├── configs/                  Development and benchmark configuration
├── deploy/                   Docker and compose definitions
├── certs/                    Local certificate workspace
├── scripts/                  Development and build utilities
├── tests/                    Cross-component integration/security tests
├── docs/                     Architecture, threat model and ADRs
└── benchmarks/               Benchmark definitions and outputs
```

## Requirements

Recommended development environment:

- Go 1.27 or newer
- Python 3.12 or newer
- C++20-compatible compiler
- CMake 3.24 or newer
- Git
- Docker with Compose support for isolated multi-node simulations

Supported native toolchains include Microsoft Visual C++ 2022+, GCC 12+, and Clang 16+.

## Installation

Clone the repository:

```bash
git clone https://github.com/smshagor-dev/ZeroTrust-FL-Sim.git
cd ZeroTrust-FL-Sim
```

### Python

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Linux or macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify the main ML dependency:

```bash
python -c "import torch; print(torch.__version__)"
```

### Go

```bash
go version
go mod tidy
```

The initial Go module intentionally contains no unused third-party packages. gRPC, Protocol Buffers, and security dependencies are added together with the code that imports them.

### C++ Extension

Activate the Python environment first, then configure and build the extension:

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build --config Release
```

The extension is written to `cpp/build/python/`.

Windows PowerShell:

```powershell
$env:PYTHONPATH="$PWD\cpp\build\python"
python -c "import zerotrust_agg; print(zerotrust_agg.backend_info())"
```

Linux or macOS:

```bash
PYTHONPATH="$PWD/cpp/build/python" python -c "import zerotrust_agg; print(zerotrust_agg.backend_info())"
```

## Development Configuration

Create a local environment file before running services:

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Linux or macOS:

```bash
cp .env.example .env
```

Never commit private keys, tokens, passwords, generated certificates, or environment-specific secrets.

## Security Model

The system follows a deny-by-default model. Network reachability does not grant federation membership or RPC authorization.

Requests are intended to pass through layered controls:

1. Mutual TLS peer authentication.
2. Certificate identity validation.
3. Application token validation where required.
4. Role and permission evaluation.
5. RPC-level authorization policy.
6. Request validation and resource limits.
7. Security-relevant audit logging.

Private signing keys and generated development certificates remain local and are ignored by Git.

## Federated Learning Scope

The simulation runtime is structured to support:

- configurable client populations
- synchronous and asynchronous execution
- local client training
- IID and non-IID data partitioning
- deterministic random seeds
- configurable local epochs and batch sizes
- client dropout and failure simulation
- Byzantine update generation
- model poisoning experiments
- aggregation correctness comparisons
- experiment metrics and result export

## Native Aggregation Scope

The native extension is reserved for computationally intensive robust aggregation routines such as:

- coordinate-wise median
- trimmed mean
- adaptive trimmed mean
- Krum
- Multi-Krum
- configurable Byzantine filtering

Reference Python implementations can be retained for correctness comparison before native optimization is accepted.

## Testing Strategy

Testing is separated by trust boundary and implementation language:

- Go unit, TLS, authentication, authorization, and RPC tests
- Python training, partitioning, aggregation, and adversarial-behavior tests
- C++ numerical correctness and boundary-condition tests
- Go/Python protocol integration tests
- invalid-certificate and unauthorized-request tests
- malicious-client simulation tests
- deterministic end-to-end benchmark scenarios

## Benchmarking

Benchmark scenarios will measure:

- aggregation latency
- aggregation throughput
- client scaling
- RPC latency
- training round duration
- CPU and memory utilization
- Byzantine tolerance
- convergence under adversarial updates

Benchmark configuration belongs under `configs/benchmark/`. Generated results are intentionally excluded from source control unless a specific result artifact is selected for publication.

## Development Rules

- Deny access by default.
- Validate all data crossing a trust boundary.
- Do not trust network location as identity.
- Keep cryptographic configuration explicit.
- Never store secrets in the repository.
- Keep cross-language interfaces small and versioned.
- Prefer deterministic tests where practical.
- Separate security policy from training logic.
- Compare optimized native code against a correctness reference.
- Document security assumptions and known limitations.

## Current Status

The repository currently contains the foundational project layout and build configuration. Secure RPC communication, federated training, adversarial simulation, robust aggregation, integration tests, benchmarks, and CI validation will be added incrementally.

## Repository

https://github.com/smshagor-dev/ZeroTrust-FL-Sim
