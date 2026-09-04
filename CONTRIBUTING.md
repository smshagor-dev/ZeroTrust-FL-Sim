# Contributing to ZeroTrust-FL-Sim

Thank you for considering a contribution to ZeroTrust-FL-Sim. The project welcomes bug fixes, tests, documentation improvements, reproducibility work, performance improvements, security hardening, and well-scoped research features.

## Before You Start

- Read the README and the relevant document under `docs/` before changing behavior.
- Search existing issues and pull requests to avoid duplicate work.
- For a substantial feature, protocol change, cryptographic change, new attack model, or change to a published benchmark methodology, open an issue first and describe the motivation, assumptions, and validation plan.
- Do not open a public issue for a vulnerability. Follow `SECURITY.md`.

## Development Environment

The repository contains Python/PyTorch, C++20/pybind11, Go, protobuf/gRPC, Docker, observability, and optional CUDA/CKKS components.

Minimum development requirements are documented in `README.md`. A typical Python/native setup is:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python scripts/generate_python_proto.py
ZTFL_ENABLE_CKKS=ON pip install -e .
```

For a portable CPU-only native build:

```bash
ZTFL_NATIVE_ARCH=OFF ZTFL_ENABLE_CUDA=OFF ZTFL_ENABLE_CKKS=ON pip install -e .
```

## Branches and Commits

Use a short branch name that describes the work, for example:

```text
fix/krum-bound-check
feat/attack-replay
perf/cuda-distance-kernel
docs/reproducibility-guide
```

Keep commits focused. Prefer clear imperative commit subjects such as:

```text
fix: reject invalid Byzantine bounds
feat: add deterministic attack replay
perf: reduce CUDA aggregation allocations
docs: document experiment metadata
```

## Code Quality

### Python

- Target Python 3.12+.
- Keep simulation paths deterministic when a seed is supplied.
- Avoid hidden global state in workers, attacks, aggregators, and privacy accounting.
- Preserve tensor dtype/device semantics across Python/native boundaries.
- Add or update tests for behavior changes.

### C++ / CUDA

- Target C++20.
- Preserve scalar fallbacks when adding architecture-specific acceleration.
- Do not assume AVX-512, NEON, OpenMP, CKKS, or CUDA is available unless the build/runtime capability check guarantees it.
- Validate dimensions, contiguous layout, dtype, device, and Byzantine bounds at native boundaries.
- Performance changes should include a benchmark or a reproducible measurement method.

### Go

Run formatting and static checks before submitting:

```bash
go fmt ./...
go vet ./...
go test ./...
```

Changes to mTLS, JWT binding, RBAC, PQC policy, certificate handling, or RPC authorization must include focused tests and must not silently weaken the default security posture.

## Testing

Run the smallest relevant test set during development, then the complete applicable suite before opening a pull request.

Python/C++:

```bash
pytest -q
```

Go:

```bash
make proto
go mod tidy
go fmt ./...
go vet ./...
go test -v ./...
```

Observability overlay validation:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.observability.yml \
  config >/dev/null
```

Full repository verification where the required toolchains are available:

```bash
./scripts/verify_system.sh
```

If CUDA, CKKS, Kubernetes, Chaos Mesh, or another optional dependency is unavailable in your environment, state that clearly in the pull request and report exactly what you did validate.

## Reproducibility Requirements

Changes that affect experiments, attacks, aggregation, privacy, performance, or resilience measurement should preserve or extend the reproducibility metadata described in the README. Include, as applicable:

- commit SHA and random seeds;
- dataset and partition parameters;
- client count, malicious fraction, attack settings, and Byzantine bound;
- aggregator/backend configuration;
- LDP/RDP and CKKS parameters;
- PQC/TLS policy;
- hardware/runtime/compiler information;
- chaos profile and observability versions;
- benchmark command and raw measurement conditions.

Do not present synthetic, estimated, or idealized values as measured results.

## Security and Safety

- Never commit private keys, production certificates, access tokens, credentials, real user data, or secrets.
- Use only development certificates and isolated environments for test PKI.
- Chaos experiments must target a dedicated test namespace or environment. Do not run repository fault-injection profiles against production systems.
- Attack simulators are for controlled research and validation. Keep malicious behavior scoped to the simulator/test environment.

## Documentation

Update documentation when a change affects commands, configuration, APIs, security assumptions, threat models, metrics, benchmark interpretation, or build requirements.

## Pull Requests

A pull request should be small enough to review and should include:

- what changed and why;
- affected components;
- tests and commands run;
- security/privacy impact;
- compatibility or migration notes when applicable;
- benchmark evidence for performance claims;
- documentation updates when behavior changed.

The pull request template provides a checklist for these items.

## Licensing of Contributions

ZeroTrust-FL-Sim is licensed under the Apache License 2.0. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project is provided under the same Apache License 2.0 terms, consistent with Section 5 of the license.

By contributing, you confirm that you have the right to submit the contribution and that it does not knowingly include code, data, or other material under incompatible terms.

## Code of Conduct

Participation in this project is governed by `CODE_OF_CONDUCT.md`.
