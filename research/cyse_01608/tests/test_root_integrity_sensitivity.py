"""Negative-control tests: server root data integrity is a threat assumption."""
import sys
from pathlib import Path
import numpy as np
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from reproduce import Config, run_case
from defense_benchmark import evaluate
from test_unsw_data import fixture_pair


def test_root_corruption_requires_root():
    for value in (-.01, 1.01, float("nan")):
        with pytest.raises(ValueError,match="invalid root-label"):
            Config(root_label_poison_fraction=value, trusted_root_fraction=.1)
    with pytest.raises(ValueError,match="root corruption requires"):
        Config(root_label_poison_fraction=.2)


def test_fltrust_root_breach_is_reproducible_and_isolated_from_client_shards():
    a=Config(rounds=3,trusted_root_fraction=.1,root_label_poison_fraction=0)
    b=Config(rounds=3,trusted_root_fraction=.1,root_label_poison_fraction=1)
    clean=run_case("breast_cancer",7,"fltrust","clip_only","sign_flip",
                   a,include_classification_metrics=True)
    dirty=run_case("breast_cancer",7,"fltrust","clip_only","sign_flip",
                   b,include_classification_metrics=True)
    again=run_case("breast_cancer",7,"fltrust","clip_only","sign_flip",
                   b,include_classification_metrics=True)
    assert clean["trusted_root_rows"]==dirty["trusted_root_rows"]
    assert clean["root_label_poison_fraction"]==0
    assert dirty["root_label_poison_fraction"]==1
    assert dirty==again
    assert clean["final_accuracy"]!=dirty["final_accuracy"]
    # Both have identical client data: only FLTrust's root-use changes.
    mean_clean=run_case("breast_cancer",7,"mean","clip_only","sign_flip",
                        a,include_classification_metrics=True)
    mean_dirty=run_case("breast_cancer",7,"mean","clip_only","sign_flip",
                        b,include_classification_metrics=True)
    assert mean_clean["final_accuracy"]==mean_dirty["final_accuracy"]
    assert mean_clean["final_loss"]==mean_dirty["final_loss"]


def test_external_source_root_breach_manifest(tmp_path):
    train,test=fixture_pair(tmp_path)
    base=evaluate(dataset="UNSW-NB15",train=train,test=test,
                  output=tmp_path/"results",seeds=(0,),
                  methods=("mean","fltrust"),privacy_modes=("clip_only",),
                  policies=("bypass",),attacks=("sign_flip",),
                  rounds=2,train_limit=300,test_limit=100,
                  trusted_root_fraction=.1,root_label_poison_fraction=.5,
                  verify_sources=False)
    assert base["root_label_poison_fraction"]==.5
    assert base["root_integrity_status"].startswith("root label integrity")
    assert base["executions"]==4
