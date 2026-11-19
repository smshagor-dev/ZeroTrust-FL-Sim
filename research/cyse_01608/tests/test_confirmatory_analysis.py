"""Synthetic fixture tests for NEW-seed confirmatory workflow. Not real data."""
import csv
import hashlib
import itertools
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from confirmatory_analysis import evaluate,holm3,SEEDS,METHODS,MODES,POLICIES,THREATS


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def fixture(tmp_path):
    rows=[]
    paired=[]
    for seed,method,mode,policy in itertools.product(SEEDS,METHODS,MODES,POLICIES):
        loss=1.
        if mode=="dp_1" and method=="multi_krum" and policy=="bypass":
            loss+=14+(seed%3)
        elif mode=="dp_1" and method=="fltrust" and policy=="bypass":
            loss+=1+(seed%2)*.1
        benign=dict(dataset="UNSW-NB15",seed=seed,aggregator=method,
                    privacy_mode=mode,attacker_compliance=policy,
                    threat="benign",final_accuracy=.80,
                    macro_f1=.80,balanced_accuracy=.80,
                    trusted_root_rows=300,rounds=20,malicious_clients=3)
        attack=dict(benign,threat="sign_flip",final_accuracy=.80-loss/100,
                    macro_f1=.80-loss/100,balanced_accuracy=.80-loss/100)
        rows.extend((benign,attack))
        paired.append(dict(seed=seed,aggregator=method,privacy_mode=mode,
                           attacker_compliance=policy,threat="sign_flip",
                           clean_accuracy=.80,attacked_accuracy=.80-loss/100,
                           accuracy_drop_pp=loss))
    paths=[tmp_path/n for n in ("baseline_runs.csv","baseline_pairs.csv")]
    for path,records in zip(paths,(rows,paired)):
        with path.open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=list(records[0]))
            w.writeheader();w.writerows(records)
    m=dict(dataset="UNSW-NB15",seeds=SEEDS,methods=METHODS,privacy=MODES,
           policies=POLICIES,attacks=("sign_flip",),trusted_root_fraction=.05,
           rounds=20,malicious_clients=3,partition="dirichlet",alpha=.3,
           executions=480,federated_rounds=9600,
           dataset_split_manifests=[dict(sampled_train=6000,sampled_test=3000)
                                    for _ in SEEDS],
           raw_csv_sha256=_sha(paths[0]),paired_csv_sha256=_sha(paths[1]))
    (tmp_path/"baseline_manifest.json").write_text(json.dumps(m))
    return tmp_path


def test_p1_primary_contrast_reproducible_and_positive(tmp_path):
    d=fixture(tmp_path)
    result=evaluate(d,tmp_path/"audit",draws=1000)
    assert result["n_observations"]==30
    assert result["positive"]==30 and result["negative"]==0
    assert result["exact_positive_sign_test_p"]==pytest.approx(2**-30)
    assert result["mean_J_pp"]>10
    assert (tmp_path/"audit"/"J_by_seed.csv").exists()


def test_p1_experiment_hash_mismatch_blocks_claim(tmp_path):
    d=fixture(tmp_path)
    with (d/"baseline_pairs.csv").open("a") as f:
        f.write("tampered\n")
    with pytest.raises(ValueError,match="tampered"):
        evaluate(d,d/"audit",draws=1000)


def test_confirmatory_three_source_holm_is_required():
    base=dict(protocol_id="CYSE-01608-P1-root-trust-vs-distance-selection",
              n_observations=30)
    rows=[dict(base,dataset=k,exact_positive_sign_test_p=p)
          for k,p in zip(("UNSW-NB15","NSL-KDD","CICIoT2023"),
                         (.01,.02,.03))]
    result=holm3(rows)
    assert all(0<=x["holm3_adjusted_p"]<=1 for x in result)
    with pytest.raises(ValueError,match="three unique source"):
        holm3(rows[:2])
