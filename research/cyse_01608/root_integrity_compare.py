"""Exploratory trusted-root data-integrity sensitivity, with negative-control checks.

Unlike FLTrust baseline, this deliberately assumes the server-owned trusted
dataset contains mislabeled samples. It does not claim a network attacker has
access to the trusted server or solve root-data integrity attestation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

LEVELS = (0., .5, 1.)


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path):
    with path.open(newline="",encoding="utf-8") as f:
        return list(csv.DictReader(f))


def compare(paths: dict[float,Path], output: Path) -> dict:
    if set(paths)!=set(LEVELS):
        raise ValueError("exact pre-listed integrity levels required")
    source=None
    indices={}
    manifests={}
    for frac,root in sorted(paths.items()):
        m=json.loads((root/"baseline_manifest.json").read_text())
        rr=root/"baseline_runs.csv"; pp=root/"baseline_pairs.csv"
        if m["raw_csv_sha256"]!=_sha(rr) or m["paired_csv_sha256"]!=_sha(pp):
            raise ValueError("baseline integrity mismatch")
        if (m.get("root_label_poison_fraction")!=frac
                or m.get("trusted_root_fraction")!=.05 or
                set(m.get("methods",[]))!={"multi_krum","fltrust"} or
                set(m.get("privacy",[]))!={"clip_only","dp_1"} or
                set(m.get("policies",[]))!={"compliant","bypass"} or
                list(m.get("attacks",[]))!=["sign_flip"] or
                list(m.get("seeds",[]))!=[0,1,2,3,4] or
                m.get("executions")!=80 or m.get("federated_rounds")!=1600):
            raise ValueError("baseline does not match exploratory root corruption protocol")
        if source is None:
            source=m["dataset"]
        elif source!=m["dataset"]:
            raise ValueError("mixed source datasets")
        ix={}
        for row in _read(rr):
            key=(int(row["seed"]),row["aggregator"],row["privacy_mode"],
                 row["attacker_compliance"],row["threat"])
            if key in ix or (row["dataset"]!=source or
                             float(row["root_label_poison_fraction"])!=frac
                             or int(row["trusted_root_rows"])!=300):
                raise ValueError("invalid dataset, duplicate, missing root fields")
            if not 0<=float(row["final_accuracy"])<=1:
                raise ValueError("nonfinite or invalid accuracy")
            ix[key]=row
        expected={(seed,meth,mode,policy,threat) for seed in range(5)
                  for meth in ("fltrust","multi_krum")
                  for mode in ("clip_only","dp_1")
                  for policy in ("compliant","bypass")
                  for threat in ("benign","sign_flip")}
        if set(ix)!=expected:
            raise ValueError("missing or unexpected root integrity condition")
        indices[frac]=ix
        manifests[frac]={"source_sha256":m["source_sha256"],
                         "raw_sha256":_sha(rr),"paired_sha256":_sha(pp)}
    # Strong negative control: MK NEVER observes root labels and both
    # methods have exactly the same original root exclusion/client shards.
    for key in indices[0]:
        if key[1]!="multi_krum":
            continue
        origin=indices[0][key]
        for frac in (.5,1.):
            row=indices[frac][key]
            for metric in ("final_accuracy","final_loss","macro_f1","balanced_accuracy"):
                if not np.isclose(float(row[metric]),float(origin[metric]),atol=1e-12,rtol=1e-12):
                    raise ValueError("unpoisoned distance-only negative control changed")
    observations=[]
    for seed in range(5):
        for mode in ("clip_only","dp_1"):
            for policy in ("compliant","bypass"):
                for level in LEVELS:
                    row=indices[level][seed,"fltrust",mode,policy,"sign_flip"]
                    clean=indices[level][seed,"fltrust",mode,policy,"benign"]
                    observations.append(dict(
                        dataset=source,seed=seed,root_label_poison_fraction=level,
                        method="fltrust",privacy_mode=mode,attacker_compliance=policy,
                        attacked_accuracy=float(row["final_accuracy"]),
                        benign_accuracy=float(clean["final_accuracy"]),
                        attack_accuracy_drop_pp=100*(float(clean["final_accuracy"])-float(row["final_accuracy"])),
                        attacked_macro_f1=float(row["macro_f1"]),
                        attacked_balanced_accuracy=float(row["balanced_accuracy"]),
                    ))
    target=[]
    for mode in ("clip_only","dp_1"):
        for policy in ("compliant","bypass"):
            r_clean=[indices[0][seed,"fltrust",mode,policy,"sign_flip"] for seed in range(5)]
            r_bad=[indices[1][seed,"fltrust",mode,policy,"sign_flip"] for seed in range(5)]
            delta=np.asarray([100*(float(a["final_accuracy"])-float(b["final_accuracy"]))
                              for a,b in zip(r_clean,r_bad)])
            target.append(dict(dataset=source, privacy_mode=mode,
                               attacker_compliance=policy, n_paired_seeds=5,
                               clean_root_accuracy_mean=float(np.mean([float(x["final_accuracy"]) for x in r_clean])),
                               fully_corrupt_root_accuracy_mean=float(np.mean([float(x["final_accuracy"]) for x in r_bad])),
                               mean_accuracy_loss_from_root_corruption_pp=float(np.mean(delta)),
                               min_paired_effect_pp=float(np.min(delta)),
                               max_paired_effect_pp=float(np.max(delta))))
    output.mkdir(parents=True,exist_ok=True)
    for name,rec in (("root_level_observations.csv",observations),
                     ("root_clean_vs_corrupt.csv",target)):
        with (output/name).open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=list(rec[0]))
            w.writeheader();w.writerows(rec)
    report=dict(study="root integrity corruption experimental negative control",
                dataset=source,seeds=[0,1,2,3,4],levels=LEVELS,
                methods=["fltrust","multi_krum"],
                n_total_executions=240,n_total_rounds=4800,
                n_seed_observations=len(observations),n_level_contrasts=len(target),
                distance_only_model_negative_control_passed=True,
                root_separation_and_matching_required=True,
                source_manifests=manifests,
                observations_sha256=_sha(output/"root_level_observations.csv"),
                contrasts_sha256=_sha(output/"root_clean_vs_corrupt.csv"),
                limitation="Exploratory five paired seeds; assumed server-root label corruption, not a proven real attacker action; no encrypted Byzantine or deployable DP security.")
    (output/"root_integrity_manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for label in ("clean","half","full"):
        p.add_argument("--"+label,type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(compare({0.:a.clean,.5:a.half,1.:a.full},a.output),indent=2))


if __name__=="__main__":
    main()
