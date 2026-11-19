"""Small synthetic-only regression fixtures for the independent P1 evidence gate."""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scientific_stability_gate import check_three
from confirmatory_analysis import evaluate

SOURCES = ("UNSW-NB15", "NSL-KDD", "CICIoT2023")
SEEDS = tuple(range(101, 131))
METHODS = ("multi_krum", "fltrust")
MODES = ("clip_only", "dp_1")
POLICIES = ("compliant", "bypass")


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def source_fixture(root: Path, source: str):
    target = root / "evidence" / "confirmatory"
    target.mkdir(parents=True)
    result_dir = root / "evidence" / "primary_analysis"
    runs, pairs, summaries = [], [], []
    split = []
    for seed in SEEDS:
        info = {"seed": seed, "sampled_train": 6000, "sampled_test": 3000}
        if source == "UNSW-NB15":
            info["mirror_commit"] = "44bbd02b9e70f74dd915218d5eb702f125341ffc"
        elif source == "NSL-KDD":
            info["mirror_commit"] = "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9"
        else:
            info["not_group_or_temporal_heldout"] = True
        split.append(info)
    if source == "CICIoT2023":
        snap = root / "data" / "source" / "snapshot_manifest.json"
        snap.parent.mkdir(parents=True)
        snap.write_text('{"synthetic_only":true}\n')
        for s in split:
            s["source_manifest_sha256"] = digest(snap)
    indexed = {}
    for seed, method, mode, policy in itertools.product(SEEDS, METHODS, MODES, POLICIES):
        for threat in ("benign", "sign_flip"):
            correct = 1100 + seed % 5
            if threat == "sign_flip":
                if method == "multi_krum" and mode == "dp_1" and policy == "bypass":
                    correct -= 380
                elif method == "fltrust" and mode == "dp_1" and policy == "bypass":
                    correct -= 70
                else:
                    correct -= 20
            accuracy = correct / 1500.
            confusion = [[correct, 1500-correct], [1500-correct, correct]]
            row = dict(
                dataset=source, seed=seed, aggregator=method, privacy_mode=mode,
                attacker_compliance=policy, threat=threat, rounds=20,
                n_clients=15, malicious_clients=3, trusted_root_rows=300,
                partition="dirichlet", alpha=.3, clip_norm=.1,
                noise_std=.2 if mode == "dp_1" else 0.,
                epsilon=5. if mode == "dp_1" else "",
                final_accuracy=accuracy, macro_f1=accuracy,
                balanced_accuracy=accuracy, final_loss=.6,
                confusion_matrix_json=json.dumps(confusion),
                per_class_recall_json=json.dumps([accuracy, accuracy]),
            )
            runs.append(row)
            indexed[(seed, method, mode, policy, threat)] = row
        benign = indexed[(seed, method, mode, policy, "benign")]
        attacked = indexed[(seed, method, mode, policy, "sign_flip")]
        drop = 100 * (benign["final_accuracy"]-attacked["final_accuracy"])
        pairs.append(dict(
            dataset=source, seed=seed, aggregator=method, privacy_mode=mode,
            attacker_compliance=policy, threat="sign_flip",
            clean_accuracy=benign["final_accuracy"],
            attacked_accuracy=attacked["final_accuracy"],
            accuracy_drop_pp=drop, macro_f1_drop_pp=drop,
            balanced_accuracy_drop_pp=drop,
        ))
    for method, mode, policy in itertools.product(METHODS, MODES, POLICIES):
        rows = [p for p in pairs if p["aggregator"] == method and
                p["privacy_mode"] == mode and p["attacker_compliance"] == policy]
        summaries.append(dict(
            dataset=source, aggregator=method, privacy_mode=mode,
            attacker_compliance=policy, threat="sign_flip", observations=30,
            mean_clean_accuracy=sum(p["clean_accuracy"] for p in rows)/30,
            mean_attacked_accuracy=sum(p["attacked_accuracy"] for p in rows)/30,
            mean_accuracy_drop_pp=sum(p["accuracy_drop_pp"] for p in rows)/30,
            mean_macro_f1_drop_pp=sum(p["macro_f1_drop_pp"] for p in rows)/30,
            mean_balanced_accuracy_drop_pp=sum(p["balanced_accuracy_drop_pp"] for p in rows)/30,
        ))
    write_csv(target/"baseline_runs.csv", runs)
    write_csv(target/"baseline_pairs.csv", pairs)
    write_csv(target/"baseline_summary.csv", summaries)
    manifest = dict(
        dataset=source, seeds=list(SEEDS), methods=list(METHODS),
        privacy=list(MODES), policies=list(POLICIES), attacks=["sign_flip"],
        trusted_root_fraction=.05, root_label_poison_fraction=0.,
        malicious_clients=3, rounds=20, partition="dirichlet", alpha=.3,
        executions=480, federated_rounds=9600, dataset_split_manifests=split,
        raw_csv_sha256=digest(target/"baseline_runs.csv"),
        paired_csv_sha256=digest(target/"baseline_pairs.csv"),
    )
    (target/"baseline_manifest.json").write_text(json.dumps(manifest))
    evaluate(target, result_dir, draws=10000)
    return root


@pytest.fixture
def three(tmp_path):
    return [
        source_fixture(tmp_path/name, source)
        for name, source in (("unsw", SOURCES[0]),
                             ("nsl", SOURCES[1]), ("ciciot", SOURCES[2]))
    ]


def test_three_source_raw_gate_accepts_synthetic_fixtures(three, tmp_path):
    report = check_three(*three, tmp_path/"out")
    assert report["all_three_sources_passed"] is True
    assert report["total_raw_executions"] == 1440
    assert len(report["source_results"]) == 3
    assert all(r["positive"] == 30 for r in report["source_results"])
    for row in report["source_results"]:
        for metric in ("macro_f1", "balanced_accuracy"):
            stats = row["secondary_metric_sensitivity"][metric]
            assert stats["descriptive_only_post_hoc"] is True
            assert stats["positive_seed_count"] == 30
            assert stats["negative_seed_count"] == 0



def test_tampered_published_primary_p_rejected(three, tmp_path):
    f = three[0]/"evidence"/"primary_analysis"/"source_result.json"
    data = json.loads(f.read_text())
    data["exact_positive_sign_test_p"] = 1e-50
    f.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="published exact_positive"):
        check_three(*three, tmp_path/"out")


def test_tampered_summary_rejected_without_manifest_hash(three, tmp_path):
    f = three[1]/"evidence"/"confirmatory"/"baseline_summary.csv"
    rows = list(csv.DictReader(f.open()))
    rows[0]["mean_macro_f1_drop_pp"] = "42"
    write_csv(f, rows)
    with pytest.raises(ValueError, match="mean_macro_f1_drop_pp"):
        check_three(*three, tmp_path/"out")


def test_tampered_seed_csv_rejected(three, tmp_path):
    f = three[0]/"evidence"/"primary_analysis"/"J_by_seed.csv"
    rows = list(csv.DictReader(f.open()))
    rows[0]["preregistered_J_pp"] = "999"
    write_csv(f, rows)
    with pytest.raises(ValueError, match="preregistered seed J"):
        check_three(*three, tmp_path/"out")


def test_raw_confusion_inconsistency_rejected_even_if_hash_reset(three, tmp_path):
    data = three[2]/"evidence"/"confirmatory"
    f = data/"baseline_runs.csv"
    rows = list(csv.DictReader(f.open()))
    rows[0]["macro_f1"] = "0.999"
    write_csv(f, rows)
    manifest_path = data/"baseline_manifest.json"
    m = json.loads(manifest_path.read_text())
    m["raw_csv_sha256"] = digest(f)
    manifest_path.write_text(json.dumps(m))
    with pytest.raises(ValueError, match="macro F1"):
        check_three(*three, tmp_path/"out")


def test_frozen_three_source_digest_rejects_drift(three, tmp_path):
    result = check_three(*three, tmp_path/"first")
    fields = ("semantic_run_sha256", "pair_sha256", "summary_sha256",
              "semantic_manifest_sha256", "seed_J_sha256",
              "semantic_result_sha256")
    freeze = dict(
        protocol_id="CYSE-01608-P1-root-trust-vs-distance-selection",
        freeze_id="P1-2026-11-09-semantic-evidence-v2",
        sha256_by_source={
            r["dataset"]: {k: r[k] for k in fields}
            for r in result["source_results"]
        },
    )
    frozen_path = tmp_path/"frozen.json"
    frozen_path.write_text(json.dumps(freeze))
    check_three(*three, tmp_path/"second", frozen_path=frozen_path)
    freeze["sha256_by_source"]["UNSW-NB15"]["semantic_run_sha256"] = "0"*64
    frozen_path.write_text(json.dumps(freeze))
    with pytest.raises(ValueError, match="frozen evidence drift"):
        check_three(*three, tmp_path/"third", frozen_path=frozen_path)


def test_published_holm_cannot_disagree_with_raw_results(three, tmp_path):
    result = check_three(*three, tmp_path/"first")
    published = [dict(
        dataset=r["dataset"], mean_J_pp=r["mean_J_pp"],
        exact_positive_sign_test_p=r["one_sided_exact_p"],
        holm3_adjusted_p=r["holm3_adjusted_p"],
        positive=r["positive"], negative=r["negative"], zero=r["zero"],
        significant_at_familywise_0_05=r["significant_at_familywise_0_05"]
    ) for r in result["source_results"]]
    report = tmp_path/"holm.json"
    report.write_text(json.dumps(published))
    check_three(*three, tmp_path/"second", published_holm=report)
    published[2]["holm3_adjusted_p"] = .99
    report.write_text(json.dumps(published))
    with pytest.raises(ValueError, match="published Holm"):
        check_three(*three, tmp_path/"third", published_holm=report)


def _edit_loss_and_relink_source_hashes(root, replacement):
    data = root/"evidence"/"confirmatory"
    runs = data/"baseline_runs.csv"
    manifest = data/"baseline_manifest.json"
    reported = root/"evidence"/"primary_analysis"/"source_result.json"
    rows = list(csv.DictReader(runs.open()))
    # Modify an attacked run so benign policy invariance cannot mask the
    # independent frozen-data scientific-drift assertion.
    next(row for row in rows if row["threat"] == "sign_flip")["final_loss"] = replacement
    write_csv(runs, rows)
    m = json.loads(manifest.read_text())
    m["raw_csv_sha256"] = digest(runs)
    manifest.write_text(json.dumps(m))
    p = json.loads(reported.read_text())
    p["original_experiment_runs_sha256"] = digest(runs)
    p["original_experiment_manifest_sha256"] = digest(manifest)
    reported.write_text(json.dumps(p))


def test_loss_last_bit_tolerance_does_not_rewrite_p1_claim(three, tmp_path):
    original = check_three(*three, tmp_path/"a")["source_results"][0]
    _edit_loss_and_relink_source_hashes(three[0], "0.60000000000001")
    revised = check_three(*three, tmp_path/"b")["source_results"][0]
    assert original["run_sha256"] != revised["run_sha256"]
    assert original["semantic_run_sha256"] == revised["semantic_run_sha256"]
    assert original["semantic_manifest_sha256"] == revised["semantic_manifest_sha256"]
    assert original["semantic_result_sha256"] == revised["semantic_result_sha256"]
    assert original["seed_J_sha256"] == revised["seed_J_sha256"]


def test_material_loss_change_is_not_tolerated_by_semantic_freeze(three, tmp_path):
    original = check_three(*three, tmp_path/"a")["source_results"]
    frozen = dict(
        protocol_id="CYSE-01608-P1-root-trust-vs-distance-selection",
        freeze_id="P1-2026-11-09-semantic-evidence-v2",
        sha256_by_source={
            r["dataset"]: {
                k: r[k] for k in (
                    "semantic_run_sha256", "pair_sha256", "summary_sha256",
                    "semantic_manifest_sha256", "seed_J_sha256",
                    "semantic_result_sha256",
                )
            }
            for r in original
        },
    )
    path = tmp_path/"freeze.json"
    path.write_text(json.dumps(frozen))
    _edit_loss_and_relink_source_hashes(three[0], "0.61")
    with pytest.raises(ValueError, match="P1 frozen evidence drift"):
        check_three(*three, tmp_path/"b", frozen_path=path)
