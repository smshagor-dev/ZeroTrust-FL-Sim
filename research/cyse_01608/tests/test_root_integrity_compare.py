"""Synthetic-only root-integrity audit fixtures, not measured IDS evidence."""
import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from root_integrity_compare import compare


def make_input(tmp_path):
    dirs={}
    for fraction in (0.,.5,1.):
        root=tmp_path/str(fraction)
        root.mkdir()
        rr=[];pairs=[]
        for seed in range(5):
            for method in ("multi_krum","fltrust"):
                for privacy in ("clip_only","dp_1"):
                    for policy in ("compliant","bypass"):
                        penalty=(20*fraction if method=="fltrust" else 0.)
                        benign=.8-penalty/100.
                        attacked=benign-(5 if privacy=="dp_1" else 3)/100.
                        for threat,acc in (("benign",benign),("sign_flip",attacked)):
                            rr.append(dict(dataset="UNSW-NB15",seed=seed,
                                           aggregator=method,privacy_mode=privacy,
                                           attacker_compliance=policy,threat=threat,
                                           final_accuracy=acc,final_loss=1-acc,
                                           macro_f1=acc,balanced_accuracy=acc,
                                           root_label_poison_fraction=fraction,
                                           trusted_root_rows=300))
                        pairs.append(dict(seed=seed,aggregator=method,privacy_mode=privacy,
                                          attacker_compliance=policy,threat="sign_flip",
                                          clean_accuracy=benign,
                                          attacked_accuracy=attacked,
                                          accuracy_drop_pp=100*(benign-attacked)))
        for name,rec in (("baseline_runs.csv",rr),("baseline_pairs.csv",pairs)):
            with (root/name).open("w",newline="") as handle:
                w=csv.DictWriter(handle,fieldnames=list(rec[0]))
                w.writeheader();w.writerows(rec)
        h=lambda name:hashlib.sha256((root/name).read_bytes()).hexdigest()
        m=dict(dataset="UNSW-NB15",seeds=[0,1,2,3,4],
               methods=("multi_krum","fltrust"),privacy=("clip_only","dp_1"),
               policies=("compliant","bypass"),attacks=("sign_flip",),
               root_label_poison_fraction=fraction,trusted_root_fraction=.05,
               executions=80,federated_rounds=1600,source_sha256="synthetic-fixture",
               raw_csv_sha256=h("baseline_runs.csv"),
               paired_csv_sha256=h("baseline_pairs.csv"))
        (root/"baseline_manifest.json").write_text(json.dumps(m))
        dirs[fraction]=root
    return dirs


def test_complete_root_sensitivity_grid_and_negative_control(tmp_path):
    inputs=make_input(tmp_path)
    result=compare(inputs,tmp_path/"out")
    assert result["distance_only_model_negative_control_passed"]
    assert result["n_total_executions"]==240
    assert result["n_seed_observations"]==60
    assert result["n_level_contrasts"]==4


def test_detects_changed_negative_control(tmp_path):
    inputs=make_input(tmp_path)
    path=inputs[1.]/"baseline_runs.csv"
    with path.open(newline="") as f:
        old=list(csv.DictReader(f))
    old[0]["final_accuracy"]="0.123"
    with path.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(old[0]))
        w.writeheader();w.writerows(old)
    manifestpath=inputs[1.]/"baseline_manifest.json"
    m=json.loads(manifestpath.read_text())
    m["raw_csv_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
    manifestpath.write_text(json.dumps(m))
    with pytest.raises(ValueError,match="negative control changed"):
        compare(inputs,tmp_path/"out")
