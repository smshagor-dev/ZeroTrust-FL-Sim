"""Run the release benchmark suite and emit its reproducibility manifest."""

from __future__ import annotations

import sys
from pathlib import Path

from benchmark_suite import main as run_benchmark_suite
from benchmark_suite import parse_args
from reproducibility import build_manifest, resolve_commit_sha, write_manifest


def _research_configuration(profile: str) -> tuple[dict[str, object], ...]:
    full = profile == "full"
    partition = {
        "convergence_strategy": "dirichlet",
        "alpha": 0.5,
        "min_samples_per_client": 8,
        "clients": 20 if full else 5,
    }
    privacy = {
        "local_dp": False,
        "ckks_on_network_updates": False,
    }
    threat_model = {
        "convergence_attack": "sign_flip",
        "sign_scale": 4.0,
        "malicious_fractions": [0.0, 0.10, 0.25, 0.40],
        "aggregation_corpus_byzantine_outliers": 0,
    }
    aggregation = {
        "native_reference_algorithms": ["krum", "multi_krum", "adaptive_trimmed_mean"],
        "native_reference_clients": 7,
        "native_reference_f": 1,
        "native_reference_multi_krum_k": 3,
        "native_reference_beta": 0.2,
        "convergence_method": "median",
        "convergence_backend": "auto",
    }
    return partition, privacy, threat_model, aggregation


def main() -> int:
    args = parse_args()
    run_benchmark_suite()

    partition, privacy, threat_model, aggregation = _research_configuration(args.profile)
    manifest = build_manifest(
        commit_sha=resolve_commit_sha(),
        profile=args.profile,
        sections=list(args.sections),
        seed=args.seed,
        dataset="synthetic-classification+synthetic-aggregation+grpc-echo",
        partition=partition,
        privacy=privacy,
        threat_model=threat_model,
        aggregation=aggregation,
        command=list(sys.argv),
    )
    write_manifest(Path(args.output_dir) / "benchmark-manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
