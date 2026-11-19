"""Numerical consistency and corrected paired-inference audit for author-supplied CSVs.

NO source files are bundled or created. The result establishes internal numerical
consistency only, NOT an authenticated historical Editorial Manager submission.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

DATASETS = ("breast_cancer", "digits")
METHODS = ("mean", "median", "trimmed_mean", "multi_krum")
PRIVACY = ("none", "clip_only", "dp_0.5", "dp_1", "dp_2", "dp_4")
THREATS = ("benign", "sign_flip", "label_flip")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _holm(pvalues):
    order = np.argsort(np.asarray(pvalues))
    result = np.empty(len(order), dtype=float)
    maximum = 0.0
    for rank, idx in enumerate(order):
        maximum = max(maximum, (len(order)-rank)*float(pvalues[idx]))
        result[idx] = min(1., maximum)
    return result


def audit(original: Path, summary: Path, reported: Path, output: Path):
    runs = pd.read_csv(original)
    groups = pd.read_csv(summary)
    statistics = pd.read_csv(reported)
    required = {"dataset", "seed", "aggregator", "privacy_mode", "threat",
                "final_accuracy", "final_loss", "mean_accuracy",
                "mean_original_update_norm", "mean_clipped_update_norm"}
    if not required.issubset(runs.columns):
        raise ValueError("missing original raw run fields")
    if len(runs) != 720 or runs[list(required - {"mean_accuracy", "final_loss",
        "mean_original_update_norm", "mean_clipped_update_norm"})].isna().any().any():
        raise ValueError("original factorial experiment incomplete")
    if set(runs.dataset) != set(DATASETS) or set(runs.aggregator) != set(METHODS):
        raise ValueError("original aggregator/dataset identities differ")
    if set(runs.privacy_mode) != set(PRIVACY) or set(runs.threat) != set(THREATS):
        raise ValueError("original privacy/attack factors differ")
    seeds = sorted(runs.seed.unique().tolist())
    if len(seeds) != 5 or any(not isinstance(s,(int,np.integer)) for s in seeds):
        raise ValueError("five seed identities required")
    expected = set(itertools.product(DATASETS,seeds,METHODS,PRIVACY,THREATS))
    observed = [tuple(row) for row in runs[[
        "dataset","seed","aggregator","privacy_mode","threat"
    ]].itertuples(index=False,name=None)]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("original matrix has missing/duplicate conditions")
    for field in ("final_accuracy", "mean_accuracy"):
        vals=runs[field].to_numpy(dtype=float)
        if not np.isfinite(vals).all() or not ((vals>=0)&(vals<=1)).all():
            raise ValueError("invalid original accuracy metric: "+field)
    for field in ("final_loss","mean_original_update_norm","mean_clipped_update_norm"):
        vals=runs[field].to_numpy(dtype=float)
        if not np.isfinite(vals).all() or (vals<0).any():
            raise ValueError("invalid loss/norm: "+field)

    if len(groups)!=72:
        raise ValueError("summary must have 72 rows")
    summed = runs.groupby(["privacy_mode","aggregator","threat"])[
        ["final_accuracy","final_loss"]].mean()
    keys = list(groups[["privacy_mode","aggregator","threat"]].itertuples(index=False,name=None))
    if set(keys)!=set(summed.index) or len(keys)!=len(set(keys)):
        raise ValueError("missing/duplicate aggregated conditions")
    for row in groups.itertuples(index=False):
        key = (row.privacy_mode,row.aggregator,row.threat)
        clean=(row.privacy_mode,row.aggregator,"benign")
        raw_accuracy=float(summed.loc[key,"final_accuracy"])
        raw_loss=float(summed.loc[key,"final_loss"])
        expected_drop=100*(float(summed.loc[clean,"final_accuracy"])-raw_accuracy)
        expected_inflation=raw_loss-float(summed.loc[clean,"final_loss"])
        for field, actual, expected_value in (
            ("final_accuracy",row.final_accuracy,raw_accuracy),
            ("final_loss",row.final_loss,raw_loss),
            ("accuracy_drop_pp",row.accuracy_drop_pp,expected_drop),
            ("loss_inflation",row.loss_inflation,expected_inflation),
        ):
            if not np.isclose(actual,expected_value,atol=1e-8,rtol=1e-8):
                raise ValueError("aggregated field inconsistent: "+field+" "+str(key))
    # Pair at the actual experimental unit: (dataset, seed), NOT per-run.
    def drop(mode, method):
        sub = runs.loc[(runs.privacy_mode==mode)&(runs.aggregator==method)]
        pivot = sub.pivot(index=["dataset","seed"],columns="threat",
                          values="final_accuracy")
        return 100*(pivot["benign"]-pivot["sign_flip"])

    if len(statistics)!=19 or not {"privacy_mode","comparison",
        "mean_drop_reduction_pp","p_value"}.issubset(statistics.columns):
        raise ValueError("original statistical table incomplete")
    rows=[]
    for row in statistics.itertuples(index=False):
        if row.comparison=="mean_none_vs_clip_only":
            if row.privacy_mode!="clip_ablation":
                raise ValueError("clip ablation label inconsistent")
            diff=drop("none","mean")-drop("clip_only","mean")
        else:
            parts=row.comparison.split("_vs_")
            if (len(parts)!=2 or parts[0]!="mean" or parts[1] not in METHODS
                    or parts[1]=="mean" or row.privacy_mode not in PRIVACY):
                raise ValueError("unknown statistical contrast")
            diff=drop(row.privacy_mode,"mean")-drop(row.privacy_mode,parts[1])
        vals=diff.to_numpy(dtype=float)
        if len(vals)!=10 or not np.isfinite(vals).all():
            raise ValueError("paired experimental units missing")
        mean=float(vals.mean())
        if not np.isclose(mean,row.mean_drop_reduction_pp,atol=1e-8):
            raise ValueError("published mean effect disagrees with raw rows")
        # Exact Wilcoxon recheck with tie-stable rounding is a newly defined
        # analysis convention; NOT reconstructed original author source.
        x=np.round(vals,10)
        p=float(wilcoxon(x,method="exact",alternative="two-sided").pvalue)
        rows.append(dict(
            privacy_mode=row.privacy_mode,comparison=row.comparison,
            n_dataset_seed_pairs=10,mean_drop_reduction_pp=mean,
            original_reported_p=float(row.p_value),
            corrected_exact_wilcoxon_p=p,
            disagreement=abs(p-float(row.p_value))>1e-9,
        ))
    if len({(r["privacy_mode"],r["comparison"]) for r in rows})!=19:
        raise ValueError("duplicated statistical comparisons")
    adjusted = _holm([r["corrected_exact_wilcoxon_p"] for r in rows])
    for row, p in zip(rows, adjusted):
        row["corrected_holm19_p"]=float(p)
        row["exploratory_only"]=True
    output.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(rows).to_csv(output/"rechecked_statistical_comparisons.csv",
                              index=False,float_format="%.17g")
    report=dict(
        manuscript_id="CYSE-D-26-01608",
        run_grid_verified=True,run_rows=720,group_rows=72,
        statistical_comparisons=19,
        corrected_p_disagreements=sum(x["disagreement"] for x in rows),
        corrected_holm19_significant=sum(x["corrected_holm19_p"]<.05 for x in rows),
        source_sha256={
            "Additional_file_1.csv":_sha(original),
            "Additional_file_2.csv":_sha(summary),
            "Additional_file_3.csv":_sha(reported),
        },
        provenance_status="INTERNAL CONSISTENCY ONLY; historic author run and Editorial Manager attachments not authenticated",
        inference="Two-sided exact Wilcoxon on 10 paired dataset-seed effects rounded to 10 decimals; Holm across all 19 contrasts. Exploratory only.",
        corrected_table_sha256=_sha(output/"rechecked_statistical_comparisons.csv"),
    )
    (output/"audit.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-runs",type=Path,required=True)
    p.add_argument("--original-summary",type=Path,required=True)
    p.add_argument("--original-comparisons",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.original_runs,a.original_summary,
                           a.original_comparisons,a.output),indent=2))
