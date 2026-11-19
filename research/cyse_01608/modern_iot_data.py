"""Pinned, stratified 2023 CICIoT2023 supplementary binary IDS benchmark.

Third-party source is a documented 1.34M-row subsample of UNB CICIoT2023,
NOT the raw full dataset. Uses source-supplied train and validation partitions.
No temporal, site or capture-file separation is claimed.

No data files are bundled in this repository. Only source-hashed results are
eligible as scientific evidence; generated test fixtures are clearly separate.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

DATASET_ID = "lacg030175/CIC-IoT-2023"
DATASET_REVISION_PREFIX = "ae15e93"
CONFIG = "random_3way"
EXCLUDED = frozenset({
    "label", "Label", "Label_orig", "attack_class", "Number",
    "source", "flow_id", "filename", "id",
})


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _features(df: pd.DataFrame) -> list[str]:
    return [col for col in df.columns
            if col not in EXCLUDED and pd.api.types.is_numeric_dtype(df[col])]


def _balanced_sample(df: pd.DataFrame, feature_cols: list[str],
                     samples: int, seed: int,
                     exclude_hashes: set[int] | None = None) -> pd.DataFrame:
    if samples < 100 or samples % 2:
        raise ValueError("sample size must be even, >=100")
    if set(pd.unique(df["label"])) != {0, 1}:
        raise ValueError("both binary source classes required")
    # Sample extra unique candidates to avoid underfilling from identical flows.
    selected = []
    seen = set(exclude_hashes or ())
    for cls in (0, 1):
        members = df[df["label"] == cls]
        if len(members) < samples // 2:
            raise ValueError("not enough source rows for balanced sample")
        budget = min(len(members), max(samples*8, samples//2))
        candidates = members.sample(n=budget, replace=False,
                                    random_state=seed + int(cls)*9973)
        candidates = candidates.drop_duplicates(subset=feature_cols)
        fingerprints = pd.util.hash_pandas_object(
            candidates[feature_cols], index=False
        ).astype("uint64")
        candidates = candidates.loc[~fingerprints.isin(seen)]
        if len(candidates) < samples // 2:
            raise ValueError("insufficient independent unique feature vectors")
        selected_rows = candidates.iloc[:samples//2]
        seen.update(_row_hashes(selected_rows, feature_cols))
        selected.append(selected_rows)
    return pd.concat(selected, ignore_index=True)


def _row_hashes(df: pd.DataFrame, columns: list[str]) -> set[int]:
    return set(pd.util.hash_pandas_object(df[columns], index=False).astype("uint64").tolist())


def snapshot(train_frame: pd.DataFrame, validation_frame: pd.DataFrame,
             output_dir: Path, *, revision_sha: str,
             train_rows: int = 6000, validation_rows: int = 3000,
             sample_seed: int = 2023) -> dict:
    if not revision_sha.startswith(DATASET_REVISION_PREFIX):
        raise ValueError("unexpected dataset revision; fail closed")
    if not set(("Label", "attack_class", "label")).issubset(train_frame.columns):
        raise ValueError("required source labels absent")
    feature_cols = _features(train_frame)
    if (len(feature_cols) < 20 or set(feature_cols) != set(_features(validation_frame))
            or "Number" in feature_cols):
        raise ValueError("invalid numeric feature specification")
    if feature_cols != _features(validation_frame):
        raise ValueError("source feature order differs across splits")
    t = _balanced_sample(train_frame, feature_cols, train_rows, sample_seed)
    train_hash = _row_hashes(t, feature_cols)
    # The published random splits contain some identical measured flow vectors.
    # Exclude their signatures BEFORE choosing the held-out validation sample.
    # Never keep leaked duplicates or silently reduce the intended class count.
    v = _balanced_sample(validation_frame, feature_cols, validation_rows,
                         sample_seed + 149, exclude_hashes=train_hash)
    cols = feature_cols + ["label"]
    # Remove collisions and repeat deterministic validation draw if necessary.
    # Fail rather than presenting random-split flow duplicates as independent.
    validation_hash = _row_hashes(v, feature_cols)
    overlap = train_hash & validation_hash
    if overlap:
        raise ValueError(
            f"train/validation duplicate flow-vector leakage: {len(overlap)} hashes"
        )
    if len(train_hash) != len(t) or len(validation_hash) != len(v):
        raise ValueError("duplicate vectors remaining in selected partitions")
    if not set(t["label"].unique()) == {0, 1} or not set(v["label"].unique()) == {0, 1}:
        raise ValueError("invalid sampled class labels")
    output_dir.mkdir(parents=True, exist_ok=True)
    train_csv, validation_csv = output_dir/"train.csv", output_dir/"validation.csv"
    t[cols].to_csv(train_csv, index=False, float_format="%.17g")
    v[cols].to_csv(validation_csv, index=False, float_format="%.17g")
    manifest = dict(
        source_dataset=DATASET_ID, version_sha=revision_sha,
        source_config=CONFIG, train_source_split="train",
        final_holdout_source_split="validation",
        source_is_2023_subsample=True, not_full_source_corpus=True,
        not_temporally_or_capture_group_heldout=True,
        sampled_train=train_rows, sampled_test=validation_rows,
        sample_seed=sample_seed, balanced_binary_sampling=True,
        class_counts_train={str(k):int(v) for k,v in t["label"].value_counts().items()},
        class_counts_holdout={str(k):int(v) for k,v in v["label"].value_counts().items()},
        features=feature_cols, excluded=sorted(EXCLUDED),
        no_duplicate_feature_vectors_within_or_across_splits=True,
        sample_duplicate_policy="filter validation candidate signatures against all train sample feature hashes",
        train_sha256=_sha(train_csv), test_sha256=_sha(validation_csv),
        limitations=[
            "Public HF derivative, not CIC original full release; data release source lineage is a stated assumption.",
            "Binary balanced sub-sample differs from original class prevalence.",
            "Source split is randomized, not temporal/device/session grouped.",
            "Labels and attack families cannot be read as test features.",
            "Final holdout is never used to choose training or attack parameters.",
        ],
    )
    (output_dir/"snapshot_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def prepare_ciciot(train: Path, test: Path, *, seed: int,
                   train_limit: int | None = 6000,
                   test_limit: int | None = 3000,
                   require_manifest: bool = True):
    manifest_path = train.parent / "snapshot_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if require_manifest else None
    if require_manifest:
        if (manifest["source_dataset"] != DATASET_ID or
                not manifest["version_sha"].startswith(DATASET_REVISION_PREFIX) or
                not manifest.get("no_duplicate_feature_vectors_within_or_across_splits")
                or manifest["train_sha256"] != _sha(train)
                or manifest["test_sha256"] != _sha(test)):
            raise ValueError("source provenance or sampled rows were modified")
    training = pd.read_csv(train)
    heldout = pd.read_csv(test)
    if "label" not in training.columns or "label" not in heldout.columns:
        raise ValueError("binary label missing")
    feature_cols = [col for col in training.columns if col != "label"]
    if feature_cols != [col for col in heldout.columns if col != "label"]:
        raise ValueError("train-test feature specification mismatch")
    if not feature_cols or any(c in EXCLUDED for c in feature_cols):
        raise ValueError("invalid or leaky model feature column")
    if set(training["label"].unique()) != {0, 1} or set(heldout["label"].unique()) != {0, 1}:
        raise ValueError("classes must be binary 0/1")
    if len(_row_hashes(training, feature_cols)) != len(training):
        raise ValueError("duplicate training feature vectors")
    if len(_row_hashes(heldout, feature_cols)) != len(heldout):
        raise ValueError("duplicate heldout feature vectors")
    if _row_hashes(training, feature_cols) & _row_hashes(heldout, feature_cols):
        raise ValueError("test leakage through duplicated feature vectors")
    if train_limit is not None and train_limit < len(training):
        training = training.sample(n=train_limit, random_state=seed+8089)
    if test_limit is not None and test_limit < len(heldout):
        heldout = heldout.sample(n=test_limit, random_state=seed+9113)
    # Trust/source rows never enter test; train-fitted median and scale ONLY.
    xtr = training[feature_cols].to_numpy(dtype=np.float64)
    xte = heldout[feature_cols].to_numpy(dtype=np.float64)
    xtr[~np.isfinite(xtr)] = np.nan
    xte[~np.isfinite(xte)] = np.nan
    med = np.nanmedian(xtr, axis=0)
    if not np.isfinite(med).all():
        raise ValueError("source feature entirely invalid")
    for x in (xtr,xte):
        bad = np.where(~np.isfinite(x))
        x[bad] = med[bad[1]]
    scaler = StandardScaler().fit(xtr)
    xtr = scaler.transform(xtr)
    xte = scaler.transform(xte)
    if not np.isfinite(xtr).all() or not np.isfinite(xte).all():
        raise ValueError("nonfinite normalized features")
    xtr = np.column_stack((xtr, np.ones(len(xtr))))
    xte = np.column_stack((xte, np.ones(len(xte))))
    ytr = training["label"].to_numpy(dtype=np.int64)
    yte = heldout["label"].to_numpy(dtype=np.int64)
    metadata = dict(
        dataset="CICIoT2023", seed=seed,
        source_sha256_train=_sha(train), source_sha256_holdout=_sha(test),
        sampled_train=len(training), sampled_test=len(heldout),
        feature_count=len(feature_cols),
        leakage_exclusions=sorted(EXCLUDED),
        source_manifest_sha256=_sha(manifest_path) if require_manifest else "synthetic_fixture",
        data_split_method="HF random_3way train vs validation; balanced sampled; duplicate screened",
        not_group_or_temporal_heldout=True,
    )
    return (xtr,ytr,xte,yte,2),metadata


def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--revision", default=DATASET_REVISION_PREFIX)
    args=p.parse_args()
    from datasets import load_dataset
    from huggingface_hub import HfApi
    sha=HfApi().dataset_info(DATASET_ID,revision=args.revision).sha
    if not sha or not sha.startswith(DATASET_REVISION_PREFIX):
        raise ValueError("unexpected dataset revision")
    ds=load_dataset(DATASET_ID,CONFIG,revision=sha)
    m=snapshot(ds["train"].to_pandas(),ds["validation"].to_pandas(),
               args.output,revision_sha=sha)
    print(json.dumps({"revision":sha,"training":m["sampled_train"],
                      "holdout":m["sampled_test"],"features":len(m["features"])},
                     indent=2))


if __name__ == "__main__":
    main()
