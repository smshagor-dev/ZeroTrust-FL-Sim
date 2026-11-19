"""Independent P1 preregistered source-specific 30-seed inference.

Do not pool fixed datasets into an iid population. All outputs are conditional
on deterministic simulation seeds, study-specific trust assumptions and source.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
from scipy.stats import binomtest

SEEDS = tuple(range(101, 131))
METHODS = ("multi_krum", "fltrust")
MODES = ("clip_only", "dp_1")
POLICIES = ("compliant", "bypass")
THREATS = ("benign", "sign_flip")
SOURCES = ("UNSW-NB15", "NSL-KDD", "CICIoT2023")


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path):
    with path.open(newline="",encoding="utf-8") as source:
        return list(csv.DictReader(source))


def _expected_manifest(m):
    if (m.get("dataset") not in SOURCES or list(m.get("seeds",[]))!=list(SEEDS)
            or set(m.get("methods",[]))!=set(METHODS)
            or set(m.get("privacy",[]))!=set(MODES)
            or set(m.get("policies",[]))!=set(POLICIES)
            or set(m.get("attacks",[]))!={"sign_flip"}
            or m.get("trusted_root_fraction")!=.05
            or m.get("rounds")!=20 or m.get("malicious_clients")!=3
            or m.get("partition")!="dirichlet" or m.get("alpha")!=.3
            or m.get("executions")!=480 or m.get("federated_rounds")!=9600):
        raise ValueError("experiment does not match pre-registered P1 protocol")
    if len(m.get("dataset_split_manifests",[]))!=30:
        raise ValueError("30 dataset-seed split manifests required")
    if any(s.get("sampled_train")!=6000 or s.get("sampled_test")!=3000
           for s in m["dataset_split_manifests"]):
        raise ValueError("unexpected source dataset sample counts")


def evaluate(input_dir: Path, output_dir: Path, draws: int = 10000):
    manifest_file=input_dir/"baseline_manifest.json"
    runs_file=input_dir/"baseline_runs.csv"
    paired_file=input_dir/"baseline_pairs.csv"
    manifest=json.loads(manifest_file.read_text(encoding="utf-8"))
    _expected_manifest(manifest)
    if (_hash(runs_file)!=manifest["raw_csv_sha256"] or
            _hash(paired_file)!=manifest["paired_csv_sha256"]):
        raise ValueError("tampered source CSV evidence")
    raw=_rows(runs_file)
    paired=_rows(paired_file)
    possible=set(itertools.product(SEEDS,METHODS,MODES,POLICIES,THREATS))
    index={}
    for row in raw:
        key=(int(row["seed"]),row["aggregator"],row["privacy_mode"],
             row["attacker_compliance"],row["threat"])
        if key in index or key not in possible:
            raise ValueError("duplicate/unexpected raw condition")
        if (row["dataset"]!=manifest["dataset"] or
                int(row["rounds"])!=20 or int(row["malicious_clients"])!=3 or
                int(row["trusted_root_rows"])!=300):
            raise ValueError("raw source condition diverges from protocol")
        acc=float(row["final_accuracy"])
        f1=float(row["macro_f1"])
        balanced=float(row["balanced_accuracy"])
        if not np.isfinite([acc,f1,balanced]).all() or min(acc,f1,balanced)<0 or max(acc,f1,balanced)>1:
            raise ValueError("invalid classification metrics")
        index[key]=row
    if len(raw)!=480 or set(index)!=possible:
        raise ValueError("incomplete 480-grid")
    paired_keys=set(itertools.product(SEEDS,METHODS,MODES,POLICIES,("sign_flip",)))
    mapped={}
    for row in paired:
        key=(int(row["seed"]),row["aggregator"],row["privacy_mode"],
             row["attacker_compliance"],row["threat"])
        if key in mapped or key not in paired_keys:
            raise ValueError("unexpected paired attack")
        benign=index[key[:4]+("benign",)]
        attack=index[key]
        if not np.isclose(float(row["clean_accuracy"]),float(benign["final_accuracy"]),atol=1e-10):
            raise ValueError("invalid matched benign accuracy")
        if not np.isclose(float(row["attacked_accuracy"]),float(attack["final_accuracy"]),atol=1e-10):
            raise ValueError("invalid attacked accuracy")
        expected=100*(float(benign["final_accuracy"])-float(attack["final_accuracy"]))
        if not np.isclose(float(row["accuracy_drop_pp"]),expected,atol=1e-8):
            raise ValueError("recomputed attack drop disagrees with paired file")
        mapped[key]=float(row["accuracy_drop_pp"])
    if len(paired)!=240 or set(mapped)!=paired_keys:
        raise ValueError("incomplete benign/attack pairings")
    output=[]
    for seed in SEEDS:
        def penalty(agg,mode):
            return mapped[(seed,agg,mode,"bypass","sign_flip")] - mapped[
                (seed,agg,mode,"compliant","sign_flip")]
        mk=penalty("multi_krum","dp_1")-penalty("multi_krum","clip_only")
        fl=penalty("fltrust","dp_1")-penalty("fltrust","clip_only")
        output.append(dict(dataset=manifest["dataset"],seed=seed,
                           multi_krum_privacy_bypass_interaction_pp=mk,
                           fltrust_privacy_bypass_interaction_pp=fl,
                           preregistered_J_pp=mk-fl))
    j=np.array([x["preregistered_J_pp"] for x in output],dtype=float)
    if not np.isfinite(j).all() or len(j)!=30:
        raise ValueError("nonfinite or incomplete primary contrast")
    signs=np.sign(j)
    nonzero=signs[signs!=0]
    positive=int(np.count_nonzero(nonzero>0))
    negative=int(np.count_nonzero(nonzero<0))
    zero=int(np.count_nonzero(signs==0))
    if len(nonzero)<1:
        raise ValueError("all zero: no estimable primary one-sided direction")
    p=float(binomtest(positive, len(nonzero),p=.5,alternative="greater").pvalue)
    rng=np.random.default_rng(16082026)
    draws_array=j[rng.integers(0,len(j),size=(draws,len(j)))].mean(axis=1)
    lo,hi=np.quantile(draws_array,[.025,.975])
    output_dir.mkdir(parents=True,exist_ok=True)
    output_path=output_dir/"J_by_seed.csv"
    with output_path.open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(output[0]))
        writer.writeheader()
        writer.writerows(output)
    result=dict(
        protocol_id="CYSE-01608-P1-root-trust-vs-distance-selection",
        dataset=manifest["dataset"],n_observations=30,
        mean_J_pp=float(j.mean()),median_J_pp=float(np.median(j)),
        conditional_seed_bootstrap_95_lo_pp=float(lo),
        conditional_seed_bootstrap_95_hi_pp=float(hi),
        exact_positive_sign_test_p=p,
        positive=positive,negative=negative,zero=zero,
        csv_sha256=_hash(output_path),
        original_experiment_manifest_sha256=_hash(manifest_file),
        original_experiment_runs_sha256=_hash(runs_file),
        original_experiment_pairs_sha256=_hash(paired_file),
        statistical_unit="dataset-specific seed",
        inference_limitation="One-sided source-specific sign test; three-source familywise Holm correction requires independent final aggregation; no population-level dataset inference.",
    )
    (output_dir/"source_result.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def holm3(results: list[dict]) -> list[dict]:
    if len(results)!=3 or {x["dataset"] for x in results}!=set(SOURCES):
        raise ValueError("three unique source comparisons required; fail closed")
    if any(x["protocol_id"]!="CYSE-01608-P1-root-trust-vs-distance-selection"
           or x["n_observations"]!=30 for x in results):
        raise ValueError("protocol mismatch")
    indices=sorted(range(3),key=lambda i:results[i]["exact_positive_sign_test_p"])
    previous=0.
    for rank,i in enumerate(indices):
        previous=max(previous,(3-rank)*results[i]["exact_positive_sign_test_p"])
        results[i]["holm3_adjusted_p"]=min(1.,previous)
        results[i]["significant_at_familywise_0_05"]=previous<.05
    return results


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--source-results",type=Path,nargs=3)
    a=p.parse_args()
    if a.source_results:
        rows=[json.loads(x.read_text()) for x in a.source_results]
        complete=holm3(rows)
        a.output_dir.mkdir(parents=True,exist_ok=True)
        (a.output_dir/"holm_three_source_confirmatory.json").write_text(
            json.dumps(complete,indent=2)+"\n")
        print(json.dumps(complete,indent=2))
    else:
        if a.input_dir is None:
            p.error("--input-dir required for per-source inference")
        print(json.dumps(evaluate(a.input_dir,a.output_dir),indent=2))


if __name__=="__main__":
    main()
