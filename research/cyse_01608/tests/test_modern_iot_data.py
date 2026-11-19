"""Tests use synthetic arrays, NOT CICIoT2023 research evidence."""
import csv
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modern_iot_data import snapshot,prepare_ciciot
from defense_benchmark import evaluate


def synthetic_source(rows, seed):
    rng=np.random.default_rng(seed)
    data={f"feature_{i:02}":rng.normal(size=rows) for i in range(39)}
    data["Number"]=np.arange(rows)
    labels=np.arange(rows)%2
    data["Label"]=np.where(labels==0,"BenignTraffic","DDoS-UDP_Flood")
    data["attack_class"]=np.where(labels==0,"Benign","DDoS")
    data["label"]=labels
    return pd.DataFrame(data)


def test_modern_source_manifest_and_root_holdout(tmp_path):
    train=synthetic_source(500,7)
    val=synthetic_source(400,29)
    m=snapshot(train,val,tmp_path,revision_sha="ae15e93-fixed-synthetic",
               train_rows=200,validation_rows=100)
    assert m["sampled_train"]==200 and m["sampled_test"]==100
    assert "Number" not in m["features"]
    assert "Label" not in m["features"] and "attack_class" not in m["features"]
    task,info=prepare_ciciot(tmp_path/"train.csv",tmp_path/"validation.csv",seed=0,
                             train_limit=200,test_limit=100)
    assert task[0].shape==(200,40) and task[2].shape==(100,40)
    assert len(set(task[3]))==2
    assert info["sampled_train"]==200
    result=evaluate(dataset="CICIoT2023",train=tmp_path/"train.csv",
                    test=tmp_path/"validation.csv",output=tmp_path/"out",
                    seeds=(0,),methods=("mean","fltrust"),
                    privacy_modes=("clip_only",),
                    policies=("bypass",),attacks=("sign_flip",),
                    rounds=2,malicious_clients=3,
                    train_limit=200,test_limit=100,
                    trusted_root_fraction=.05)
    assert result["executions"]==4
    with (tmp_path/"out"/"baseline_runs.csv").open(newline="") as f:
        rows=list(csv.DictReader(f))
    assert len(rows)==4
    assert all(int(row["trusted_root_rows"])==10 for row in rows)


def test_modern_tamper_is_rejected(tmp_path):
    snapshot(synthetic_source(500,7),synthetic_source(400,29),
             tmp_path,revision_sha="ae15e93-fixture",
             train_rows=200,validation_rows=100)
    with (tmp_path/"validation.csv").open("a",encoding="utf-8") as f:
        f.write("malicious,extra\n")
    with pytest.raises(ValueError,match="modified"):
        prepare_ciciot(tmp_path/"train.csv",tmp_path/"validation.csv",seed=0)


def test_modern_cross_split_duplicate_detection(tmp_path):
    a=synthetic_source(500,7)
    b=a.copy(deep=True)
    with pytest.raises(ValueError,match="insufficient independent unique feature vectors"):
        snapshot(a,b,tmp_path,revision_sha="ae15e93-fixture",
                 train_rows=400,validation_rows=200,
                 sample_seed=2023)
