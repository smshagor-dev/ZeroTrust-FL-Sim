# Support

ZeroTrust-FL-Sim is an open-source research and engineering project. Support is community/maintainer best effort and does not include a production SLA.

## Where to Ask

Use GitHub Issues for:

- reproducible bugs;
- build or installation failures;
- documentation problems;
- feature proposals;
- benchmark or experiment reproducibility questions;
- compatibility problems that can be demonstrated from the repository.

Before opening an issue, search existing issues and read the relevant section of `README.md` and `docs/`.

## What to Include

For technical problems, include:

- exact commit SHA or release/tag;
- operating system and architecture;
- Python, PyTorch, Go, compiler, CMake, and CUDA versions as relevant;
- SIMD/OpenMP/CUDA/CKKS capability state when relevant;
- command run;
- sanitized logs or traceback;
- minimal reproduction steps;
- expected and observed behavior.

For experiment/reproducibility questions, also include the dataset, random seeds, partition parameters, attack configuration, aggregator/backend, privacy configuration, and hardware/runtime details relevant to the result.

## Security Issues

Do not report vulnerabilities through a public issue. Follow `SECURITY.md`.

## Scope

The project does not guarantee support for undocumented deployment environments, modified forks, production use, or claims that contradict the security/measurement boundaries documented in the README.
