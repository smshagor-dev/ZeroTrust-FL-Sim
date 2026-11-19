"""Explicit trust-model tests for FLTrust prior-art comparator."""
import csv
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from robust_baselines import aggregate_extended, fltrust_aggregate
from reproduce import Config, run_case
from defense_benchmark import evaluate
from test_unsw_data import fixture_pair as unsw_fixture


def test_trusted_direction_rejects_anti_aligned_large_adversaries():
    vectors = np.vstack([
        np.tile(np.array([1., 0.]), (12, 1)),
        np.tile(np.array([-1e9, 0.]), (3, 1)),
    ])
    np.testing.assert_allclose(fltrust_aggregate(vectors, np.array([.5, 0.])),
                               [.5, 0.], atol=1e-12)


def test_trusted_direction_filters_orthogonal_vectors():
    values = np.array([[5., 0.], [0., 100.], [-6., 0.]])
    np.testing.assert_allclose(fltrust_aggregate(values, np.array([2., 0.])),
                               [2., 0.], atol=1e-12)


def test_fltrust_needs_valid_root_and_explicit_assignment():
    u = np.ones((3, 2))
    with pytest.raises(ValueError, match="trusted"):
        aggregate_extended(u, "fltrust", cap=.1)
    with pytest.raises(ValueError, match="trusted root"):
        fltrust_aggregate(u, np.zeros(2))
    with pytest.raises(ValueError, match="trusted root"):
        run_case("breast_cancer", 0, "fltrust", "clip_only", "benign",
                 Config(rounds=2))
    with pytest.raises(ValueError, match="invalid trusted root allocation"):
        Config(trusted_root_fraction=.5)


def test_fltrust_experiment_is_seeded_and_disjoint_from_client_shards():
    cfg = Config(rounds=2, trusted_root_fraction=.10, attacker_compliance="bypass")
    a = run_case("breast_cancer", 0, "fltrust", "clip_only", "sign_flip",
                 cfg, include_classification_metrics=True)
    b = run_case("breast_cancer", 0, "fltrust", "clip_only", "sign_flip",
                 cfg, include_classification_metrics=True)
    assert a == b
    assert a["trusted_root_rows"] > 0
    assert 0 <= a["macro_f1"] <= 1
    # Comparator must see identical CLIENT shard allocation/root exclusion.
    m = run_case("breast_cancer", 0, "mean", "clip_only", "sign_flip",
                 cfg, include_classification_metrics=True)
    assert m["trusted_root_rows"] == a["trusted_root_rows"]


def test_fltrust_and_mean_share_small_source_dataset(tmp_path):
    train, test = unsw_fixture(tmp_path)
    result = tmp_path / "results"
    manifest = evaluate(
        dataset="UNSW-NB15", train=train, test=test, output=result,
        seeds=(0,), methods=("mean", "fltrust"),
        privacy_modes=("clip_only", "dp_1"),
        policies=("bypass",), attacks=("sign_flip",),
        rounds=2, malicious_clients=3, train_limit=300, test_limit=100,
        verify_sources=False, trusted_root_fraction=.1,
    )
    assert manifest["executions"] == 8
    assert manifest["trusted_root_fraction"] == .1
    with (result / "baseline_runs.csv").open(newline="") as f:
        records = list(csv.DictReader(f))
    assert {row["aggregator"] for row in records} == {"mean", "fltrust"}
    assert all(int(row["trusted_root_rows"]) == 30 for row in records)
    with (result / "baseline_pairs.csv").open(newline="") as f:
        paired = list(csv.DictReader(f))
    assert len(paired) == 4

def test_targeted_label_poison_is_explicit_and_seeded():
    cfg = Config(rounds=3, attacker_compliance="bypass", targeted_class=0)
    first = run_case("breast_cancer", 1, "mean", "clip_only",
                     "targeted_label_poison", cfg,
                     include_classification_metrics=True)
    again = run_case("breast_cancer", 1, "mean", "clip_only",
                     "targeted_label_poison", cfg,
                     include_classification_metrics=True)
    assert first == again
    assert first["threat"] == "targeted_label_poison"
    assert len(__import__("json").loads(first["per_class_recall_json"])) == 2
    with pytest.raises(ValueError,match="targeted class outside"):
        run_case("breast_cancer", 1, "mean", "clip_only",
                 "targeted_label_poison", Config(rounds=2,targeted_class=3))
    with pytest.raises(ValueError, match="targeted class must"):
        Config(targeted_class=-1)
