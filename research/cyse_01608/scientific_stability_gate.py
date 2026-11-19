"""Independent, fail-closed scientific results gate for CYSE-01608 P1.

This cross-artifact reanalysis does NOT import the experiment's analysis code.
It validates numerical internal consistency, not external dataset ownership,
scientific novelty, production differential privacy or historic provenance.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import numpy as np

SOURCES = ("UNSW-NB15", "NSL-KDD", "CICIoT2023")
SEEDS = tuple(range(101, 131))
METHODS = ("multi_krum", "fltrust")
MODES = ("clip_only", "dp_1")
POLICIES = ("compliant", "bypass")
FIELDS = ("final_accuracy", "macro_f1", "balanced_accuracy")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value) -> str:
    """SHA-256 for stable scientific JSON with canonical key/order encoding."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def records(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def close(observed, expected, label: str, tolerance=1e-10):
    a, b = float(observed), float(expected)
    if not (math.isfinite(a) and math.isfinite(b) and
            math.isclose(a, b, rel_tol=1e-10, abs_tol=tolerance)):
        raise ValueError("inconsistent " + label + ": " + str((a, b)))


def metric_from_confusion(row: dict, source: str):
    matrix = np.asarray(json.loads(row["confusion_matrix_json"]), dtype=float)
    recalls = np.asarray(json.loads(row["per_class_recall_json"]), dtype=float)
    if (matrix.shape != (2, 2) or recalls.shape != (2,) or
            not np.isfinite(matrix).all() or (matrix < 0).any() or
            not np.all(matrix == np.floor(matrix)) or
            matrix.sum() != 3000):
        raise ValueError(source + ": invalid holdout confusion matrix")
    row_totals = matrix.sum(axis=1)
    if (row_totals == 0).any():
        raise ValueError(source + ": missing heldout class")
    tp = np.diag(matrix)
    calculated_recall = tp / row_totals
    for j in (0, 1):
        close(recalls[j], calculated_recall[j], "class recall")
    f1 = []
    for j in (0, 1):
        denom = row_totals[j] + matrix[:, j].sum()
        f1.append(2 * tp[j] / denom if denom > 0 else 0)
    close(row["final_accuracy"], tp.sum() / matrix.sum(), "confusion accuracy")
    close(row["balanced_accuracy"], calculated_recall.mean(), "balanced accuracy")
    close(row["macro_f1"], np.mean(f1), "macro F1")


def inspect_source(parent: Path, source: str) -> dict:
    data = parent / "evidence" / "confirmatory"
    publication = parent / "evidence" / "primary_analysis"
    manifest_path = data / "baseline_manifest.json"
    runs_path = data / "baseline_runs.csv"
    pairs_path = data / "baseline_pairs.csv"
    summary_path = data / "baseline_summary.csv"
    published_path = publication / "source_result.json"
    j_path = publication / "J_by_seed.csv"
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("dataset") != source or
            manifest.get("seeds") != list(SEEDS) or
            set(manifest.get("methods", [])) != set(METHODS) or
            set(manifest.get("privacy", [])) != set(MODES) or
            set(manifest.get("policies", [])) != set(POLICIES) or
            manifest.get("attacks") != ["sign_flip"] or
            manifest.get("trusted_root_fraction") != .05 or
            manifest.get("root_label_poison_fraction", 0) != 0 or
            manifest.get("malicious_clients") != 3 or
            manifest.get("rounds") != 20 or
            manifest.get("partition") != "dirichlet" or
            manifest.get("alpha") != .3 or
            manifest.get("executions") != 480 or
            manifest.get("federated_rounds") != 9600):
        raise ValueError(source + ": incorrect frozen study factors")
    for name, path in (("raw_csv_sha256", runs_path), ("paired_csv_sha256", pairs_path)):
        if sha(path) != manifest.get(name):
            raise ValueError(source + ": tampered " + name)
    splits = manifest.get("dataset_split_manifests", [])
    if len(splits) != 30 or sorted(s.get("seed") for s in splits) != list(SEEDS):
        raise ValueError(source + ": incomplete source/seed provenance")
    if any(s.get("sampled_train") != 6000 or s.get("sampled_test") != 3000 for s in splits):
        raise ValueError(source + ": source sample count changed")
    pins = {
        "UNSW-NB15": "44bbd02b9e70f74dd915218d5eb702f125341ffc",
        "NSL-KDD": "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9",
    }
    if source in pins:
        if any(s.get("mirror_commit") != pins[source] for s in splits):
            raise ValueError(source + ": upstream source pin changed")
    else:
        if any(not s.get("not_group_or_temporal_heldout") for s in splits):
            raise ValueError("CICIoT2023 derivative requires random-split disclosure")
        snapshot = parent / "data" / "source" / "snapshot_manifest.json"
        if not snapshot.is_file() or any(
                s.get("source_manifest_sha256") != sha(snapshot) for s in splits):
            raise ValueError("CICIoT2023 source snapshot provenance mismatch")
    expected = set(itertools.product(SEEDS, METHODS, MODES, POLICIES, ("benign", "sign_flip")))
    indexed = {}
    raw = records(runs_path)
    for row in raw:
        key = (int(row["seed"]), row["aggregator"], row["privacy_mode"],
               row["attacker_compliance"], row["threat"])
        if key not in expected or key in indexed or row.get("dataset") != source:
            raise ValueError(source + ": duplicate or unexpected raw grid cell")
        if (int(row["trusted_root_rows"]) != 300 or int(row["rounds"]) != 20 or
                int(row["n_clients"]) != 15 or int(row["malicious_clients"]) != 3 or
                row.get("partition") != "dirichlet"):
            raise ValueError(source + ": invalid client/round/root metadata")
        close(row["alpha"], .3, "alpha")
        close(row["clip_norm"], .1, "L2 clip")
        close(row["noise_std"], 0. if row["privacy_mode"] == "clip_only" else .2,
              "noise scale")
        if row["privacy_mode"] == "dp_1":
            if not math.isfinite(float(row["epsilon"])) or float(row["epsilon"]) <= 0:
                raise ValueError(source + ": missing conditional reference epsilon")
        elif row["epsilon"] != "":
            raise ValueError(source + ": clipping-only epsilon must be empty")
        for field in FIELDS:
            value = float(row[field])
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(source + ": non-finite or out-of-range " + field)
        if not math.isfinite(float(row["final_loss"])) or float(row["final_loss"]) < 0:
            raise ValueError(source + ": invalid cross-entropy loss")
        metric_from_confusion(row, source)
        indexed[key] = row
    if set(indexed) != expected or len(raw) != 480:
        raise ValueError(source + ": missing raw conditions")
    for seed, method, mode in itertools.product(SEEDS, METHODS, MODES):
        compliant = indexed[(seed, method, mode, "compliant", "benign")]
        bypass = indexed[(seed, method, mode, "bypass", "benign")]
        for field in FIELDS + ("final_loss",):
            close(compliant[field], bypass[field], "benign policy invariance")
    pair_keys = set(itertools.product(SEEDS, METHODS, MODES, POLICIES))
    observed_pairs = {}
    for pair in records(pairs_path):
        key = (int(pair["seed"]), pair["aggregator"],
               pair["privacy_mode"], pair["attacker_compliance"])
        if (key in observed_pairs or key not in pair_keys or
                pair["threat"] != "sign_flip" or pair["dataset"] != source):
            raise ValueError(source + ": invalid paired attack entry")
        clean = indexed[key + ("benign",)]
        attack = indexed[key + ("sign_flip",)]
        close(pair["clean_accuracy"], clean["final_accuracy"], "clean pair")
        close(pair["attacked_accuracy"], attack["final_accuracy"], "attacked pair")
        for metric, column in (
                ("final_accuracy", "accuracy_drop_pp"),
                ("macro_f1", "macro_f1_drop_pp"),
                ("balanced_accuracy", "balanced_accuracy_drop_pp")):
            close(pair[column], 100 * (float(clean[metric]) - float(attack[metric])),
                  column)
        observed_pairs[key] = pair
    if set(observed_pairs) != pair_keys or len(observed_pairs) != 240:
        raise ValueError(source + ": incomplete paired grid")

    summary_index = {}
    for row in records(summary_path):
        key = (row["aggregator"], row["privacy_mode"], row["attacker_compliance"])
        if key in summary_index or key not in set(itertools.product(METHODS, MODES, POLICIES)):
            raise ValueError(source + ": invalid summary row")
        if row["dataset"] != source or row["threat"] != "sign_flip" or int(row["observations"]) != 30:
            raise ValueError(source + ": summary factors inconsistent")
        ps = [observed_pairs[(s,) + key] for s in SEEDS]
        for column, base_column in (
                ("mean_clean_accuracy", "clean_accuracy"),
                ("mean_attacked_accuracy", "attacked_accuracy"),
                ("mean_accuracy_drop_pp", "accuracy_drop_pp"),
                ("mean_macro_f1_drop_pp", "macro_f1_drop_pp"),
                ("mean_balanced_accuracy_drop_pp", "balanced_accuracy_drop_pp")):
            close(row[column], np.mean([float(p[base_column]) for p in ps]), column)
        summary_index[key] = row
    if len(summary_index) != 8:
        raise ValueError(source + ": incomplete 8-cell summary")
    primary = []
    j_rows = records(j_path)
    if len(j_rows) != 30:
        raise ValueError(source + ": wrong published seed table length")
    j_lookup = {}
    for row in j_rows:
        if row["dataset"] != source or int(row["seed"]) not in SEEDS or int(row["seed"]) in j_lookup:
            raise ValueError(source + ": invalid published seed")
        j_lookup[int(row["seed"])] = row
    if set(j_lookup) != set(SEEDS):
        raise ValueError(source + ": missing published seed")
    for seed in SEEDS:
        def penalty(method: str, mode: str) -> float:
            return float(observed_pairs[(seed, method, mode, "bypass")]["accuracy_drop_pp"]) - float(
                observed_pairs[(seed, method, mode, "compliant")]["accuracy_drop_pp"])
        mk = penalty("multi_krum", "dp_1") - penalty("multi_krum", "clip_only")
        fl = penalty("fltrust", "dp_1") - penalty("fltrust", "clip_only")
        row = j_lookup[seed]
        close(row["multi_krum_privacy_bypass_interaction_pp"], mk, "MK seed interaction")
        close(row["fltrust_privacy_bypass_interaction_pp"], fl, "FLTrust seed interaction")
        close(row["preregistered_J_pp"], mk - fl, "preregistered seed J")
        primary.append(mk - fl)
    values = np.asarray(primary, dtype=float)
    positives = int(np.count_nonzero(values > 0))
    negatives = int(np.count_nonzero(values < 0))
    zeros = 30 - positives - negatives
    n = positives + negatives
    if not n:
        raise ValueError(source + ": no nonzero primary contrasts")
    p = sum(math.comb(n, k) for k in range(positives, n + 1)) / (2 ** n)
    rng = np.random.default_rng(16082026)
    resamples = values[rng.integers(0, 30, size=(10000, 30))].mean(axis=1)
    lo, hi = np.quantile(resamples, [.025, .975])
    # Post-hoc robustness triangulation: two secondary classification metrics.
    # These are descriptive checks and do not add inferential hypotheses to P1.
    secondary = {}
    for metric in ("macro_f1", "balanced_accuracy"):
        values_secondary = []
        for seed in SEEDS:
            def interaction(method, mode):
                def loss(policy):
                    benign = indexed[(seed, method, mode, policy, "benign")]
                    attacked = indexed[(seed, method, mode, policy, "sign_flip")]
                    return 100 * (float(benign[metric]) - float(attacked[metric]))
                return loss("bypass") - loss("compliant")
            effect = (
                interaction("multi_krum", "dp_1") -
                interaction("multi_krum", "clip_only") -
                interaction("fltrust", "dp_1") +
                interaction("fltrust", "clip_only")
            )
            values_secondary.append(effect)
        arr = np.asarray(values_secondary, dtype=float)
        secondary[metric] = {
            "descriptive_only_post_hoc": True,
            "mean_interaction_pp": float(arr.mean()),
            "min_interaction_pp": float(arr.min()),
            "max_interaction_pp": float(arr.max()),
            "positive_seed_count": int((arr > 0).sum()),
            "negative_seed_count": int((arr < 0).sum()),
            "zero_seed_count": int((arr == 0).sum()),
        }
    published = json.loads(published_path.read_text(encoding="utf-8"))
    exact = {
        "mean_J_pp": values.mean(),
        "median_J_pp": np.median(values),
        "conditional_seed_bootstrap_95_lo_pp": lo,
        "conditional_seed_bootstrap_95_hi_pp": hi,
        "exact_positive_sign_test_p": p,
    }
    if (published.get("dataset") != source or published.get("n_observations") != 30
            or published.get("protocol_id") != "CYSE-01608-P1-root-trust-vs-distance-selection"
            or published.get("positive") != positives or published.get("negative") != negatives
            or published.get("zero") != zeros):
        raise ValueError(source + ": altered reported inferential metadata")
    for k, v in exact.items():
        close(published[k], v, "published " + k)
    for k, path in (
            ("csv_sha256", j_path),
            ("original_experiment_manifest_sha256", manifest_path),
            ("original_experiment_runs_sha256", runs_path),
            ("original_experiment_pairs_sha256", pairs_path)):
        if published.get(k) != sha(path):
            raise ValueError(source + ": published artifact hash mismatch: " + k)
    return {
        "dataset": source, "n_seeds": 30, "raw_rows": 480,
        "paired_rows": 240, "summary_rows": 8,
        "positive": positives, "negative": negatives, "zero": zeros,
        "mean_J_pp": float(values.mean()),
        "one_sided_exact_p": float(p),
        "run_sha256": sha(runs_path), "pair_sha256": sha(pairs_path),
        "summary_sha256": sha(summary_path),
        "seed_J_sha256": sha(j_path), "result_sha256": sha(published_path),
        "manifest_sha256": sha(manifest_path),
        # Only the 12th decimal of final cross-entropy may vary under
        # equivalent CPU floating-point reductions. Never canonicalize
        # accuracy/F1/recall, classification outcomes or paired J.
        "semantic_run_sha256": canonical_sha([
            dict(row, final_loss=format(float(row["final_loss"]), ".12f"))
            for row in raw
        ]),
        "semantic_manifest_sha256": canonical_sha({
            k: v for k, v in manifest.items() if k != "raw_csv_sha256"
        }),
        "semantic_result_sha256": canonical_sha({
            k: v for k, v in published.items()
            if k not in ("original_experiment_runs_sha256",
                         "original_experiment_manifest_sha256")
        }),
        "secondary_metric_sensitivity": secondary,
    }


def check_three(unsw: Path, nsl: Path, ciciot: Path, output: Path,
                frozen_path: Path | None = None,
                published_holm: Path | None = None):
    evidence = [
        inspect_source(unsw, SOURCES[0]),
        inspect_source(nsl, SOURCES[1]),
        inspect_source(ciciot, SOURCES[2]),
    ]
    if len({r["run_sha256"] for r in evidence}) != 3:
        raise ValueError("cross-source raw evidence was reused")
    order = sorted(range(3), key=lambda i: evidence[i]["one_sided_exact_p"])
    prev = 0.
    for rank, index in enumerate(order):
        row = evidence[index]
        prev = max(prev, (3-rank) * row["one_sided_exact_p"])
        row["holm3_adjusted_p"] = min(1., prev)
        row["significant_at_familywise_0_05"] = row["holm3_adjusted_p"] < .05
    if frozen_path is not None:
        freeze = json.loads(frozen_path.read_text(encoding="utf-8"))
        if (freeze.get("protocol_id") != "CYSE-01608-P1-root-trust-vs-distance-selection"
                or freeze.get("freeze_id") != "P1-2026-11-09-semantic-evidence-v2"
                or set(freeze.get("sha256_by_source", {})) != set(SOURCES)):
            raise ValueError("unknown or incomplete frozen P1 experiment identity")
        for record in evidence:
            for field, expected_hash in freeze["sha256_by_source"][record["dataset"]].items():
                if (field not in ("semantic_run_sha256", "pair_sha256", "summary_sha256",
                                  "semantic_manifest_sha256", "seed_J_sha256",
                                  "semantic_result_sha256")
                        or record[field] != expected_hash):
                    raise ValueError(record["dataset"] + ": P1 frozen evidence drift: " + field +
                                     " observed=" + str(record.get(field)) +
                                     " expected=" + str(expected_hash))
    if published_holm is not None:
        published = json.loads(published_holm.read_text(encoding="utf-8"))
        if (not isinstance(published, list) or len(published) != 3 or
                {p.get("dataset") for p in published} != set(SOURCES)):
            raise ValueError("invalid published three-source Holm family")
        by_source = {x["dataset"]: x for x in evidence}
        for reported in published:
            current = by_source[reported["dataset"]]
            for published_field, computed_field in (
                    ("exact_positive_sign_test_p", "one_sided_exact_p"),
                    ("mean_J_pp", "mean_J_pp"),
                    ("holm3_adjusted_p", "holm3_adjusted_p")):
                close(reported[published_field], current[computed_field],
                      "published Holm " + published_field)
            if (reported["positive"] != current["positive"] or
                    reported["negative"] != current["negative"] or
                    reported["zero"] != current["zero"] or
                    reported["significant_at_familywise_0_05"] !=
                        current["significant_at_familywise_0_05"]):
                raise ValueError("incorrect published Holm significance decision")
    result = {
        "protocol": "CYSE-01608-P1-root-trust-vs-distance-selection",
        "validation": "Independent raw-to-figure numerical integrity, NOT origin/authenticity or scientific novelty proof",
        "all_three_sources_passed": True,
        "total_raw_executions": 1440,
        "total_federated_rounds": 28800,
        "source_results": evidence,
        "frozen_sha256": sha(frozen_path) if frozen_path is not None else None,
        "published_holm_sha256": sha(published_holm) if published_holm is not None else None,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "independent_scientific_stability_gate.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--unsw", type=Path, required=True)
    p.add_argument("--nsl", type=Path, required=True)
    p.add_argument("--ciciot", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--freeze-file", type=Path)
    p.add_argument("--published-holm", type=Path)
    args = p.parse_args()
    print(json.dumps(check_three(args.unsw, args.nsl, args.ciciot, args.output,
                                 args.freeze_file, args.published_holm),
                     indent=2))


if __name__ == "__main__":
    main()
