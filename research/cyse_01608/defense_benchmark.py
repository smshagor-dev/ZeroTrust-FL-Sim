"""Independent real IDS benchmark for existing robust FL alternatives.

Designed for cross-method comparability, with shared dataset split/seed and
identical attacker scenario. NOT original submitted CYSE-D-26-01608 data.
Plaintext server-enforced norm projection explicitly changes trust assumptions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np

from reproduce import FIELDS, Config, paired_results, run_case
from robust_baselines import EXTENSION_AGGREGATORS
from nsl_data import prepare_nsl
from modern_iot_data import prepare_ciciot
from unsw_data import prepare_unsw

METHODS = ("mean", "multi_krum", "rfa",
           "server_clipped_mean", "server_clipped_rfa",
           "server_clipped_multi_krum")
PRIVACY = ("clip_only", "dp_1")
ATTACKS = ("sign_flip", "alie_oracle", "targeted_label_poison", "in_ball_oracle")
POLICIES = ("compliant", "bypass")
OPTIONAL_METHODS = ("fltrust",)
METRICS = ("macro_f1", "balanced_accuracy", "per_class_recall_json",
           "confusion_matrix_json", "trusted_root_rows",
           "root_label_poison_fraction")
SUMMARY = (
    "dataset", "aggregator", "privacy_mode", "attacker_compliance",
    "threat", "observations", "mean_clean_accuracy",
    "mean_attacked_accuracy", "mean_accuracy_drop_pp",
    "mean_macro_f1_drop_pp", "mean_balanced_accuracy_drop_pp"
)


def evaluate(
    *, dataset: str, train: Path, test: Path, output: Path,
    seeds: tuple[int, ...] = (0, 1, 2, 3, 4),
    methods: tuple[str, ...] = METHODS,
    privacy_modes: tuple[str, ...] = PRIVACY,
    policies: tuple[str, ...] = POLICIES,
    attacks: tuple[str, ...] = ("sign_flip",),
    rounds: int = 20, malicious_clients: int = 3,
    train_limit: int | None = 6000, test_limit: int | None = 3000,
    partition: str = "dirichlet", alpha: float = 0.3,
    verify_sources: bool = True,
    trusted_root_fraction: float = 0.0,
    root_label_poison_fraction: float = 0.0,
) -> dict:
    if dataset not in {"UNSW-NB15", "NSL-KDD", "CICIoT2023"}:
        raise ValueError("unsupported dataset")
    if not all((seeds, methods, privacy_modes, policies, attacks)):
        raise ValueError("empty experiment selection")
    if (set(methods) - set(METHODS + OPTIONAL_METHODS) or set(privacy_modes) - set(PRIVACY)
            or set(policies) - set(POLICIES) or set(attacks) - set(ATTACKS)):
        raise ValueError("unknown experimental factor")
    if len(set(seeds)) != len(seeds) or len(set(methods)) != len(methods):
        raise ValueError("duplicate seeds or aggregation methods")
    if rounds < 1:
        raise ValueError("at least one training round required")
    if "fltrust" in methods and trusted_root_fraction <= 0:
        raise ValueError("FLTrust requires a positive independent trusted root fraction")
    if not np.isfinite(root_label_poison_fraction) or not 0 <= root_label_poison_fraction <= 1:
        raise ValueError("invalid root corruption factor")
    if root_label_poison_fraction > 0 and trusted_root_fraction <= 0:
        raise ValueError("root corruption requires a trusted root data allocation")
    if not 0 <= trusted_root_fraction < .5:
        raise ValueError("invalid trusted root allocation")
    if not 0 < malicious_clients < 15:
        raise ValueError("invalid malicious client population")

    loader = {"UNSW-NB15": prepare_unsw, "NSL-KDD": prepare_nsl,
              "CICIoT2023": prepare_ciciot}[dataset]
    output.mkdir(parents=True, exist_ok=True)
    records = []
    manifest_splits = []
    for seed in seeds:
        if dataset == "CICIoT2023":
            opts = {"require_manifest": verify_sources}
        else:
            opts = {} if verify_sources else (
                {"expected_train_blob": None, "expected_test_blob": None,
                 "require_official_row_counts": False}
                if dataset == "UNSW-NB15" else
                {"expected_train_blob": None, "expected_test_blob": None,
                 "require_standard_counts": False}
            )
        task, info = loader(
            train, test, seed=seed, train_limit=train_limit,
            test_limit=test_limit, **opts
        )
        manifest_splits.append(info)
        for method, privacy, policy in itertools.product(
            methods, privacy_modes, policies
        ):
            cfg = Config(
                rounds=rounds, malicious_clients=malicious_clients,
                partition=partition, alpha=alpha, attacker_compliance=policy,
                multi_krum_k=min(5, 15-malicious_clients-2),
                trusted_root_fraction=trusted_root_fraction,
                root_label_poison_fraction=root_label_poison_fraction,
            )
            for threat in ("benign", *attacks):
                records.append(run_case(
                    dataset, seed, method, privacy, threat, cfg,
                    external_task=task, include_classification_metrics=True
                ))

    with (output / "baseline_runs.csv").open(
        "w", newline="", encoding="utf-8"
    ) as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS+METRICS)
        writer.writeheader()
        writer.writerows(records)

    indexed = {
        (r["seed"], r["aggregator"], r["privacy_mode"],
         r["attacker_compliance"], r["threat"]): r for r in records
    }
    paired = paired_results(records)
    for row in paired:
        key = (row["seed"], row["aggregator"], row["privacy_mode"],
               row["attacker_compliance"])
        benign = indexed[key+("benign",)]
        attacked = indexed[key+(row["threat"],)]
        row["macro_f1_drop_pp"] = 100.*(
            benign["macro_f1"]-attacked["macro_f1"]
        )
        row["balanced_accuracy_drop_pp"] = 100.*(
            benign["balanced_accuracy"]-attacked["balanced_accuracy"]
        )
    with (output / "baseline_pairs.csv").open(
        "w", newline="", encoding="utf-8"
    ) as out:
        writer = csv.DictWriter(out, fieldnames=list(paired[0]))
        writer.writeheader()
        writer.writerows(paired)

    summary_rows = []
    for method, privacy, policy, threat in itertools.product(
        methods, privacy_modes, policies, attacks
    ):
        matched = [r for r in paired if r["aggregator"] == method
                   and r["privacy_mode"] == privacy
                   and r["attacker_compliance"] == policy
                   and r["threat"] == threat]
        if len(matched) != len(seeds):
            raise AssertionError("lost paired seed units")
        summary_rows.append({
            "dataset": dataset, "aggregator": method,
            "privacy_mode": privacy, "attacker_compliance": policy,
            "threat": threat, "observations": len(matched),
            "mean_clean_accuracy": float(np.mean([r["clean_accuracy"] for r in matched])),
            "mean_attacked_accuracy": float(np.mean([r["attacked_accuracy"] for r in matched])),
            "mean_accuracy_drop_pp": float(np.mean([r["accuracy_drop_pp"] for r in matched])),
            "mean_macro_f1_drop_pp": float(np.mean([r["macro_f1_drop_pp"] for r in matched])),
            "mean_balanced_accuracy_drop_pp": float(np.mean([r["balanced_accuracy_drop_pp"] for r in matched])),
        })
    with (output / "baseline_summary.csv").open(
        "w", newline="", encoding="utf-8"
    ) as out:
        writer = csv.DictWriter(out, fieldnames=SUMMARY)
        writer.writeheader()
        writer.writerows(summary_rows)

    provenance = {
        "study": "independent known RFA and plaintext server norm-gate baselines",
        "dataset": dataset, "not_original_720_runs": True,
        "dataset_split_manifests": manifest_splits,
        "seeds": seeds, "methods": methods, "privacy": privacy_modes,
        "policies": policies, "attacks": attacks,
        "targeted_label_poison_target_class": 0,
        "targeted_label_poison_is_not_trigger_backdoor": True,
        "rounds": rounds, "malicious_clients": malicious_clients,
        "partition": partition, "alpha": alpha,
        "trusted_root_fraction": trusted_root_fraction,
        "root_label_poison_fraction": root_label_poison_fraction,
        "root_integrity_status": "assumed clean" if root_label_poison_fraction==0 else "root label integrity deliberately breached",
        "executions": len(records), "federated_rounds": len(records)*rounds,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "robust_baselines_sha256": hashlib.sha256(
            (Path(__file__).parent/"robust_baselines.py").read_bytes()
        ).hexdigest(),
        "raw_csv_sha256": hashlib.sha256(
            (output/"baseline_runs.csv").read_bytes()
        ).hexdigest(),
        "paired_csv_sha256": hashlib.sha256(
            (output/"baseline_pairs.csv").read_bytes()
        ).hexdigest(),
        "limitations": [
            "RFA geometric median and norm projection are known techniques, not a novel algorithm.",
            "Server norm gate requires authenticated, plaintext/noisy vectors before aggregation; it cannot inspect CKKS ciphertext.",
            "Client-side noise was deterministically seeded for comparison, not operational local differential privacy.",
            "Post-noise server clipping changes the utility distribution and may clip honest updates.",
            "Only the explicitly listed attacks and model/dataset settings are evaluated.",
            "Source data is not redistributed; GitHub artifacts expire.",
        ],
    }
    (output/"baseline_manifest.json").write_text(
        json.dumps(provenance, indent=2)+"\n", encoding="utf-8"
    )
    return provenance


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", choices=("UNSW-NB15","NSL-KDD","CICIoT2023"),required=True)
    p.add_argument("--train",type=Path,required=True)
    p.add_argument("--test",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--seeds",nargs="+",type=int,default=[0,1,2,3,4])
    p.add_argument("--methods",nargs="+",choices=METHODS+OPTIONAL_METHODS,default=list(METHODS))
    p.add_argument("--privacy",nargs="+",choices=PRIVACY,default=list(PRIVACY))
    p.add_argument("--attacks",nargs="+",choices=ATTACKS,default=["sign_flip"])
    p.add_argument("--policies",nargs="+",choices=POLICIES,default=list(POLICIES))
    p.add_argument("--rounds",type=int,default=20)
    p.add_argument("--trusted-root-fraction",type=float,default=0.0)
    p.add_argument("--root-label-poison-fraction",type=float,default=0.0)
    p.add_argument("--train-limit",type=int,default=6000)
    p.add_argument("--test-limit",type=int,default=3000)
    a=p.parse_args()
    manifest=evaluate(
        dataset=a.dataset,train=a.train,test=a.test,output=a.output,
        seeds=tuple(a.seeds),methods=tuple(a.methods),
        privacy_modes=tuple(a.privacy),attacks=tuple(a.attacks),
        policies=tuple(a.policies),rounds=a.rounds,
        train_limit=a.train_limit,test_limit=a.test_limit,
        trusted_root_fraction=a.trusted_root_fraction,
        root_label_poison_fraction=a.root_label_poison_fraction,
    )
    print(json.dumps({"dataset":a.dataset,
                      "executions":manifest["executions"],
                      "rounds":manifest["federated_rounds"]},indent=2))


if __name__=="__main__":
    main()
