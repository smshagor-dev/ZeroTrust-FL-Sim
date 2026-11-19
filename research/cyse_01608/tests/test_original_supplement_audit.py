"""Synthetic CSV fixtures for the historical author-data numerical audit."""
import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from original_supplement_audit import audit,DATASETS,METHODS,PRIVACY,THREATS


def fixture_csvs(tmp_path):
    rows=[]
    for di,seed,mi,pi,threat in itertools.product(
        range(2),range(5),range(4),range(6),THREATS
    ):
        acc=.85-.015*di+.003*seed-.005*mi-.006*pi
        if threat=="sign_flip":
            acc-=.015*(1+mi+pi) + .002*(seed+1)**2*(mi+1)
        if threat=="label_flip":
            acc-=.011*(1+pi)+.001*(seed+1)*mi
        rows.append(dict(dataset=DATASETS[di],seed=seed+11,
                         aggregator=METHODS[mi],privacy_mode=PRIVACY[pi],
                         threat=threat,final_accuracy=acc,final_loss=1.3-acc,
                         mean_accuracy=acc,mean_original_update_norm=.05,
                         mean_clipped_update_norm=.04))
    raw=pd.DataFrame(rows)
    grp=raw.groupby(["privacy_mode","aggregator","threat"],as_index=False)[
        ["final_accuracy","final_loss"]].mean()
    benign=grp[grp.threat=="benign"].set_index(["privacy_mode","aggregator"])
    grp["accuracy_drop_pp"]=[
        100*(benign.loc[(r.privacy_mode,r.aggregator),"final_accuracy"]-r.final_accuracy)
        for r in grp.itertuples(index=False)]
    grp["loss_inflation"]=[
        r.final_loss-benign.loc[(r.privacy_mode,r.aggregator),"final_loss"]
        for r in grp.itertuples(index=False)]
    grp["sigma"]=0
    grp["epsilon_20"]=0
    grp["optimal_order"]=2
    def drop(mode,method):
        sub=raw[(raw.privacy_mode==mode)&(raw.aggregator==method)]
        a=sub.pivot(index=["dataset","seed"],columns="threat",values="final_accuracy")
        return 100*(a.benign-a.sign_flip)
    stats=[]
    for mode,method in itertools.product(PRIVACY,("median","trimmed_mean","multi_krum")):
        diff=drop(mode,"mean")-drop(mode,method)
        stats.append(dict(privacy_mode=mode,comparison="mean_vs_"+method,
                          mean_drop_reduction_pp=float(diff.mean()),p_value=.5))
    stats.append(dict(privacy_mode="clip_ablation",comparison="mean_none_vs_clip_only",
                      mean_drop_reduction_pp=float((drop("none","mean")-drop("clip_only","mean")).mean()),
                      p_value=.5))
    paths=[tmp_path/name for name in ("Additional_file_1.csv",
             "Additional_file_2.csv","Additional_file_3.csv")]
    raw.to_csv(paths[0],index=False)
    grp.to_csv(paths[1],index=False)
    pd.DataFrame(stats).to_csv(paths[2],index=False)
    return paths


def test_complete_synthetic_matrix_and_corrected_inference(tmp_path):
    files=fixture_csvs(tmp_path)
    result=audit(*files,tmp_path/"audit")
    assert result["run_grid_verified"]
    assert result["run_rows"]==720
    assert result["statistical_comparisons"]==19
    assert result["corrected_holm19_significant"]<=19
    assert "INTERNAL CONSISTENCY ONLY" in result["provenance_status"]


def test_duplicate_raw_condition_rejected(tmp_path):
    files=fixture_csvs(tmp_path)
    raw=pd.read_csv(files[0])
    raw.loc[1,["dataset","seed","aggregator","privacy_mode","threat"]] = raw.loc[
        0,["dataset","seed","aggregator","privacy_mode","threat"]].values
    raw.to_csv(files[0],index=False)
    with pytest.raises(ValueError,match="missing/duplicate"):
        audit(*files,tmp_path/"audit")


def test_falsified_summary_rejected(tmp_path):
    files=fixture_csvs(tmp_path)
    s=pd.read_csv(files[1])
    s.loc[0,"final_accuracy"]+=.1
    s.to_csv(files[1],index=False)
    with pytest.raises(ValueError,match="inconsistent"):
        audit(*files,tmp_path/"audit")
