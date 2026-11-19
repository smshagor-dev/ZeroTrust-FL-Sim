"""Reimplement the controlled CYSE-D-26-01608 experimental design.

This is independent reproduction code, not verified original-author source.
Seeded Gaussian randomness is ONLY suitable for repeatable utility experiments.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import platform
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import scipy
import sklearn
from scipy.special import softmax
from sklearn.datasets import load_breast_cancer, load_digits
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from robust_baselines import EXTENSION_AGGREGATORS, TRUSTED_ROOT_AGGREGATORS, aggregate_extended

ORDERS = (1.25, 1.5, 1.75, 2., 3., 4., 5., 8., 10., 16., 32., 64.)
AGGREGATORS = ("mean", "trimmed_mean", "median", "multi_krum")
PRIVACY_MODES = ("none", "clip_only", "dp_0.5", "dp_1", "dp_2", "dp_4")
THREATS = ("benign", "sign_flip", "label_flip")
EXTENSION_THREATS = THREATS + ("alie_oracle", "targeted_label_poison", "in_ball_oracle")
DATASETS = ("breast_cancer", "digits")
FIELDS = ("dataset", "seed", "partition", "alpha", "aggregator", "privacy_mode",
          "threat", "attacker_compliance", "rounds", "n_clients", "malicious_clients",
          "final_accuracy", "final_loss", "epsilon", "delta", "clip_norm", "noise_std")


@dataclass(frozen=True)
class Config:
    clients: int = 15
    malicious_clients: int = 3
    rounds: int = 20
    learning_rate: float = 0.12
    l2: float = 1e-4
    clip_norm: float = 0.1
    delta: float = 1e-5
    sign_scale: float = 5.0
    multi_krum_k: int = 5
    trim_each_tail: int = 3
    train_fraction: float = .75
    partition: str = "iid"
    alpha: float = 0.3
    attacker_compliance: str = "compliant"
    trusted_root_fraction: float = 0.0  # 0 preserves submitted design unchanged
    targeted_class: int = 0  # supplementary target-label manipulation only
    root_label_poison_fraction: float = 0.0  # supplementary assumed root-trust breach

    def __post_init__(self):
        if self.clients < 3 or not 0 <= self.malicious_clients < self.clients:
            raise ValueError("invalid client population")
        if self.rounds < 1 or self.clip_norm <= 0 or self.learning_rate <= 0:
            raise ValueError("rounds, clip norm and learning rate must be positive")
        if not 0 < self.delta < 1 or not 0 < self.train_fraction < 1:
            raise ValueError("invalid delta/train fraction")
        if self.partition not in {"iid", "dirichlet"} or self.alpha <= 0:
            raise ValueError("invalid partition/alpha")
        if self.attacker_compliance not in {"compliant", "bypass"}:
            raise ValueError("attacker_compliance must be compliant or bypass")
        if self.targeted_class < 0:
            raise ValueError("targeted class must be nonnegative")
        if not math.isfinite(self.root_label_poison_fraction) or not 0 <= self.root_label_poison_fraction <= 1:
            raise ValueError("invalid root-label corruption fraction")
        if self.root_label_poison_fraction > 0 and self.trusted_root_fraction <= 0:
            raise ValueError("root corruption requires an allocated server-held root")
        if not 0 <= self.trusted_root_fraction < 0.5:
            raise ValueError("invalid trusted root allocation")
        if self.trim_each_tail * 2 >= self.clients:
            raise ValueError("trimming would remove all clients")
        if self.clients < 2 * self.malicious_clients + 3:
            raise ValueError("Krum requires n >= 2*f+3")
        if not 1 <= self.multi_krum_k <= self.clients-self.malicious_clients-2:
            raise ValueError("invalid Multi-Krum k")


def load_task(name: str, seed: int, config: Config):
    if name == "breast_cancer":
        ds = load_breast_cancer()
    elif name == "digits":
        ds = load_digits()
    else:
        raise ValueError(f"unknown dataset: {name}")
    x = np.asarray(ds.data, dtype=np.float64)
    y = np.asarray(ds.target, dtype=np.int64)
    indices = np.arange(y.size)
    tr, te = train_test_split(indices, train_size=config.train_fraction,
                              stratify=y, random_state=seed)
    scaler = StandardScaler().fit(x[tr])
    xtr = scaler.transform(x[tr])
    xte = scaler.transform(x[te])
    xtr = np.column_stack([xtr, np.ones(len(tr))])
    xte = np.column_stack([xte, np.ones(len(te))])
    return xtr, y[tr], xte, y[te], len(np.unique(y))


def partition_indices(labels: np.ndarray, seed: int, config: Config) -> tuple[np.ndarray, ...]:
    if config.partition == "iid":
        rng = np.random.default_rng(seed + 381)
        buckets = [[] for _ in range(config.clients)]
        for cls in np.unique(labels):
            idx = np.flatnonzero(labels == cls)
            rng.shuffle(idx)
            start = int(rng.integers(config.clients))
            for j, idx_value in enumerate(idx):
                buckets[(start + j) % config.clients].append(int(idx_value))
        return tuple(np.asarray(b, dtype=np.int64) for b in buckets)
    for trial in range(300):
        rng = np.random.default_rng(np.random.SeedSequence([seed, trial, 4401]))
        buckets = [[] for _ in range(config.clients)]
        for cls in np.unique(labels):
            idx = np.flatnonzero(labels == cls)
            rng.shuffle(idx)
            fractions = rng.dirichlet(np.repeat(config.alpha, config.clients))
            allocation = rng.multinomial(len(idx), fractions)
            pieces = np.split(idx, np.cumsum(allocation)[:-1])
            for i, part in enumerate(pieces):
                buckets[i].extend(part.tolist())
        if all(buckets):
            return tuple(np.asarray(b, dtype=np.int64) for b in buckets)
    raise ValueError("could not generate nonempty Dirichlet shards; adjust alpha/clients")


def epsilon_gaussian(noise_multiplier: float, releases: int, delta: float) -> float | None:
    if noise_multiplier <= 0:
        return None
    return min(releases*order/(2*noise_multiplier**2) + math.log(1/delta)/(order-1)
               for order in ORDERS)


def aggregate(updates: np.ndarray, method: str, config: Config) -> np.ndarray:
    n = updates.shape[0]
    if method == "mean":
        return updates.mean(axis=0)
    if method == "median":
        return np.median(updates, axis=0)
    if method == "trimmed_mean":
        k = config.trim_each_tail
        return np.sort(updates, axis=0)[k:n-k].mean(axis=0)
    if method == "multi_krum":
        f = config.malicious_clients
        if n < 2*f+3 or not 1 <= config.multi_krum_k <= n-f-2:
            raise ValueError("Multi-Krum fault bound not satisfied")
        squared = ((updates[:, None, :] - updates[None, :, :])**2).sum(axis=2)
        np.fill_diagonal(squared, np.inf)
        nearest_count = n-f-2
        scores = np.partition(squared, nearest_count-1, axis=1)[:, :nearest_count].sum(axis=1)
        return updates[np.argsort(scores, kind="stable")[:config.multi_krum_k]].mean(axis=0)
    raise ValueError(f"unknown aggregator {method}")


def alie_oracle_update(honest_updates: np.ndarray, *, factor: float = 1.5) -> np.ndarray:
    """Statistics-oracle ALIE attack from Baruch et al. (NeurIPS 2019).

    The attacker sees all exact honest pre-DP update vectors: this is an
    intentionally STRONG information oracle, not something supported by CKKS.
    """
    if honest_updates.ndim != 2 or honest_updates.shape[0] < 2:
        raise ValueError("ALIE requires at least two honest updates")
    if not np.isfinite(honest_updates).all() or not np.isfinite(factor) or factor < 0:
        raise ValueError("ALIE inputs must be finite and factor nonnegative")
    return honest_updates.mean(axis=0) - factor * honest_updates.std(axis=0)


def in_ball_oracle_update(honest_updates: np.ndarray, cap: float) -> np.ndarray:
    """Reversed mean-honest direction WITHIN cap; hypothetical oracle access.

    This malicious update evades any detector based solely on an upper bound
    on update magnitude. It is not a realistic CKKS-input verifier model.
    """
    updates = np.asarray(honest_updates, dtype=np.float64)
    if (updates.ndim != 2 or updates.shape[0] < 2 or updates.shape[1] < 1
            or not np.isfinite(updates).all() or not math.isfinite(cap) or cap <= 0):
        raise ValueError("finite honest-update matrix and positive norm cap needed")
    center = updates.mean(axis=0)
    norm = float(np.linalg.norm(center))
    if not math.isfinite(norm):
        raise ValueError("honest oracle vector norm invalid")
    if norm < 1e-14:
        return np.zeros(updates.shape[1], dtype=np.float64)
    return -0.5 * cap * center / norm


def multi_krum_selected_clients(updates: np.ndarray, config: Config) -> np.ndarray:
    """Return accepted client indices; inclusion is NOT proof of honesty.

    Used for supplementary Byzantine-inclusion experiments, without changing
    the submitted reference-grid aggregation or CSV schema.
    """
    if updates.ndim != 2 or not np.isfinite(updates).all():
        raise ValueError("finite [clients, dimensions] matrix required")
    n = len(updates)
    f = config.malicious_clients
    if n < 2 * f + 3 or not 1 <= config.multi_krum_k <= n - f - 2:
        raise ValueError("Multi-Krum fault bound not satisfied")
    distances = ((updates[:, None, :] - updates[None, :, :]) ** 2).sum(axis=2)
    np.fill_diagonal(distances, np.inf)
    scores = np.partition(distances, n - f - 3, axis=1)[:, :n - f - 2].sum(axis=1)
    return np.argsort(scores, kind="stable")[:config.multi_krum_k]


def _noise(seed: int, client: int, round_id: int, shape: tuple[int, ...], scale: float):
    # Common-random-number design between attacked and benign conditions.
    # This deterministic mode is NOT suitable for operational privacy claims.
    rng = np.random.default_rng(np.random.SeedSequence([seed, client, round_id, 83011]))
    return rng.normal(0, scale, size=shape)


def _accuracy_and_loss(x, y, weights):
    probs = softmax(x @ weights, axis=1)
    loss = -np.log(np.clip(probs[np.arange(len(y)), y], 1e-15, 1)).mean()
    return float(np.mean(probs.argmax(axis=1) == y)), float(loss)


def run_case(dataset: str, seed: int, aggregator: str, privacy_mode: str,
             threat: str, config: Config, *,
             external_task: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int] | None = None,
             include_classification_metrics: bool = False,
             include_selection_diagnostics: bool = False) -> dict:
    if aggregator not in AGGREGATORS + EXTENSION_AGGREGATORS + TRUSTED_ROOT_AGGREGATORS or privacy_mode not in PRIVACY_MODES or threat not in EXTENSION_THREATS:
        raise ValueError("invalid experimental condition")
    xtr, ytr, xte, yte, n_classes = (
        load_task(dataset, seed, config) if external_task is None else external_task
    )
    root_x = root_y = None
    root_n = 0
    if config.trusted_root_fraction > 0:
        # Root samples are TRAINING only and removed from ALL client shards.
        # This extra trust assumption is NOT part of the original 720-run study.
        root_n = max(n_classes, int(math.ceil(len(ytr)*config.trusted_root_fraction)))
        if len(ytr) - root_n < config.clients:
            raise ValueError("not enough data for disjoint trusted root and clients")
        row_indices = np.arange(len(ytr))
        client_idx, root_idx = train_test_split(
            row_indices, test_size=root_n, stratify=ytr,
            random_state=seed+6019,
        )
        root_x, root_y = xtr[root_idx], ytr[root_idx]
        if config.root_label_poison_fraction > 0:
            # Explicit assumed server-root integrity BREACH; deterministic
            # independent selection, not a network backdoor or active poisoning
            # of clients. The original experimental path is unchanged.
            root_y = root_y.copy()
            count = int(round(len(root_y)*config.root_label_poison_fraction))
            selected = np.random.default_rng(seed+20771).choice(
                len(root_y), size=count, replace=False)
            root_y[selected] = (root_y[selected]+1) % n_classes
        xtr, ytr = xtr[client_idx], ytr[client_idx]
    if aggregator == "fltrust" and root_x is None:
        raise ValueError("FLTrust needs a held-out trusted root set")
    if threat == "targeted_label_poison" and config.targeted_class >= n_classes:
        raise ValueError("targeted class outside label space")
    partitions = partition_indices(ytr, seed, config)
    if any(len(ids) == 0 for ids in partitions):
        raise ValueError("client shard cannot be empty")
    malicious = set(np.random.default_rng(seed+9271).choice(
        config.clients, size=config.malicious_clients, replace=False).tolist())
    client_x = [xtr[idx] for idx in partitions]
    client_y = [ytr[idx] for idx in partitions]
    weights = np.zeros((xtr.shape[1], n_classes), dtype=np.float64)
    sigma = float(privacy_mode[3:]) if privacy_mode.startswith("dp_") else 0.0
    clipping = privacy_mode != "none"
    noise_std = 2 * config.clip_norm * sigma
    if include_selection_diagnostics and aggregator != "multi_krum":
        raise ValueError("client-selection diagnostics require Multi-Krum")
    selection_counts = []
    for round_id in range(config.rounds):
        alie_vector = None
        if threat in ("alie_oracle", "in_ball_oracle") and malicious:
            # This branch is independent of the original 720-run matrix.
            # Oracle sees honest PRE-privacy vectors, a worst-case attacker.
            honest_unprotected = []
            for client in range(config.clients):
                if client in malicious:
                    continue
                x, y = client_x[client], client_y[client]
                probs = softmax(x @ weights, axis=1)
                diff = probs.copy()
                diff[np.arange(len(y)), y] -= 1
                grad = x.T @ diff / len(y)
                grad[:-1] += config.l2 * weights[:-1]
                honest_unprotected.append(-config.learning_rate * grad.reshape(-1))
            honest_matrix = np.stack(honest_unprotected)
            if threat == "alie_oracle":
                alie_vector = alie_oracle_update(honest_matrix)
            else:
                # Strong honest-statistics oracle: a colluding attacker
                # sets a directionally reversed update INSIDE the cap.
                # This tests a known limitation of server norm gates.
                alie_vector = in_ball_oracle_update(honest_matrix, config.clip_norm)
        deltas = []
        for client in range(config.clients):
            x = client_x[client]
            y = client_y[client]
            if threat == "label_flip" and client in malicious:
                y = (y+1) % n_classes
            if threat == "targeted_label_poison" and client in malicious:
                # Explicit malicious label-forgery: all poisoned targets map
                # to one chosen class. This is NOT a triggered backdoor.
                y = np.full_like(y, config.targeted_class)
            probs = softmax(x @ weights, axis=1)
            diff = probs.copy()
            diff[np.arange(len(y)), y] -= 1
            grad = x.T @ diff / len(y)
            grad[:-1] += config.l2 * weights[:-1]
            delta = -config.learning_rate * grad.reshape(-1)
            if threat == "sign_flip" and client in malicious:
                delta = -config.sign_scale * delta
            if threat in ("alie_oracle", "in_ball_oracle") and client in malicious:
                delta = alie_vector.copy()
            bypass = (config.attacker_compliance == "bypass" and
                      threat != "benign" and client in malicious)
            if clipping and not bypass:
                norm = float(np.linalg.norm(delta))
                delta = delta * min(1.0, config.clip_norm / max(norm, 1e-12))
                if sigma:
                    delta = delta + _noise(seed, client, round_id, delta.shape, noise_std)
            deltas.append(delta)
        all_updates = np.stack(deltas)
        if include_selection_diagnostics:
            selected = multi_krum_selected_clients(all_updates, config)
            selection_counts.append(sum(int(client) in malicious for client in selected))
        # The submitted design's 720 cases retain their existing aggregation
        # behavior. RFA and plaintext norm gates are research extensions only.
        if aggregator in EXTENSION_AGGREGATORS + TRUSTED_ROOT_AGGREGATORS:
            trusted_update = None
            if aggregator == "fltrust":
                # Client updates and clean-root gradient share the same
                # optimizer convention. Root is NOT client-private or encrypted.
                root_prob = softmax(root_x @ weights, axis=1)
                root_diff = root_prob.copy()
                root_diff[np.arange(len(root_y)), root_y] -= 1
                root_grad = root_x.T @ root_diff / len(root_y)
                root_grad[:-1] += config.l2 * weights[:-1]
                trusted_update = (-config.learning_rate * root_grad).reshape(-1)
            merged = aggregate_extended(
                all_updates, aggregator, cap=config.clip_norm,
                multi_krum_callback=lambda data: aggregate(data, "multi_krum", config),
                trusted_update=trusted_update,
            )
        else:
            merged = aggregate(all_updates, aggregator, config)
        weights += merged.reshape(weights.shape)
    acc, loss = _accuracy_and_loss(xte, yte, weights)
    result = dict(dataset=dataset, seed=seed, partition=config.partition,
                alpha=config.alpha if config.partition == "dirichlet" else "",
                aggregator=aggregator, privacy_mode=privacy_mode, threat=threat,
                attacker_compliance=config.attacker_compliance, rounds=config.rounds,
                n_clients=config.clients, malicious_clients=config.malicious_clients,
                final_accuracy=acc, final_loss=loss,
                epsilon=epsilon_gaussian(sigma, config.rounds, config.delta) if sigma else "",
                delta=config.delta if sigma else "", clip_norm=config.clip_norm if clipping else "",
                noise_std=noise_std)
    if include_classification_metrics:
        if config.trusted_root_fraction > 0:
            result["trusted_root_rows"] = root_n
            result["root_label_poison_fraction"] = config.root_label_poison_fraction
        # Only used by external cybersecurity benchmark experiments; adding
        # metrics must not change the original manuscript's CSV schema.
        from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score, recall_score

        predictions = np.argmax(xte @ weights, axis=1)
        labels = np.arange(n_classes)
        recalls = recall_score(
            yte, predictions, labels=labels, average=None, zero_division=0
        )
        result.update(
            macro_f1=float(
                f1_score(yte, predictions, labels=labels, average="macro", zero_division=0)
            ),
            balanced_accuracy=float(balanced_accuracy_score(yte, predictions)),
            per_class_recall_json=json.dumps(recalls.tolist()),
            confusion_matrix_json=json.dumps(
                confusion_matrix(yte, predictions, labels=labels).tolist()
            ),
        )
    if include_selection_diagnostics:
        # This requires experimental ground-truth attacker IDs. Multi-Krum
        # does NOT establish which selected clients are genuinely honest.
        result["selected_malicious_count_per_round_json"] = json.dumps(selection_counts)
        result["selected_malicious_fraction"] = sum(selection_counts) / (
            config.rounds * config.multi_krum_k
        )
    return result


def write_csv(path: Path, rows: list[dict], columns=FIELDS):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def paired_results(rows: list[dict]) -> list[dict]:
    key_fields = ("dataset", "seed", "partition", "alpha", "aggregator", "privacy_mode", "attacker_compliance")
    indexed = {tuple(row[key] for key in key_fields)+(row["threat"],): row for row in rows}
    paired = []
    for row in rows:
        if row["threat"] == "benign":
            continue
        key = tuple(row[key] for key in key_fields)
        clean = indexed.get(key+("benign",))
        if clean is None:
            raise ValueError("missing benign matched condition")
        paired.append({key_name:row[key_name] for key_name in key_fields} | {
            "threat":row["threat"], "clean_accuracy":clean["final_accuracy"],
            "attacked_accuracy":row["final_accuracy"],
            "accuracy_drop_pp":100*(clean["final_accuracy"]-row["final_accuracy"])})
    return paired


def generate(output: Path, datasets: tuple[str, ...], seeds: tuple[int, ...],
             aggregators: tuple[str, ...], privacy_modes: tuple[str, ...],
             threats: tuple[str, ...], config: Config) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    cases = itertools.product(datasets, seeds, aggregators, privacy_modes, threats)
    results = [run_case(*case, config) for case in cases]
    paired = paired_results(results) if "benign" in threats else []
    write_csv(output / "runs.csv", results)
    if paired:
        write_csv(output / "paired.csv", paired, columns=list(paired[0]))
    summary = {}
    for entry in paired:
        key = (entry["dataset"], entry["aggregator"], entry["privacy_mode"], entry["threat"])
        summary.setdefault(key, []).append(entry["accuracy_drop_pp"])
    summary_rows = [dict(dataset=k[0], aggregator=k[1], privacy_mode=k[2], threat=k[3],
                         observations=len(v), mean_accuracy_drop_pp=float(np.mean(v)))
                    for k, v in sorted(summary.items())]
    write_csv(output / "summary.csv", summary_rows,
              columns=("dataset", "aggregator", "privacy_mode", "threat", "observations", "mean_accuracy_drop_pp"))
    run_bytes = (output / "runs.csv").read_bytes()
    manifest = dict(study="CYSE-D-26-01608 controlled design reimplementation",
                    status="independent reimplementation; original 720-run results not yet matched",
                    config=asdict(config), datasets=datasets, seeds=seeds,
                    aggregators=aggregators, privacy_modes=privacy_modes, threats=threats,
                    run_count=len(results), total_rounds=len(results)*config.rounds,
                    run_sha256=hashlib.sha256(run_bytes).hexdigest(),
                    runner_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    python=platform.python_version(), numpy=np.__version__,
                    scipy=scipy.__version__, sklearn=sklearn.__version__,
                    privacy_warning="Fixed seeds invalidate production DP guarantees if exposed or known.",
                    ckks_warning="CKKS is not part of these aggregation experiments.")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/cyse_01608")
    parser.add_argument("--seeds", type=int, nargs="+", default=list(range(5)))
    parser.add_argument("--datasets", nargs="+", choices=DATASETS, default=list(DATASETS))
    parser.add_argument("--aggregators", nargs="+", choices=AGGREGATORS, default=list(AGGREGATORS))
    parser.add_argument("--privacy-modes", nargs="+", choices=PRIVACY_MODES, default=list(PRIVACY_MODES))
    parser.add_argument("--threats", nargs="+", choices=EXTENSION_THREATS, default=list(THREATS))
    parser.add_argument("--partition", choices=("iid", "dirichlet"), default="iid")
    parser.add_argument("--alpha", type=float, default=.3)
    parser.add_argument("--attacker-compliance", choices=("compliant", "bypass"), default="compliant")
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    cfg = Config(rounds=args.rounds, partition=args.partition,
                 alpha=args.alpha, attacker_compliance=args.attacker_compliance)
    manifest = generate(Path(args.output), tuple(args.datasets), tuple(args.seeds),
                        tuple(args.aggregators), tuple(args.privacy_modes),
                        tuple(args.threats), cfg)
    print(json.dumps({"run_count":manifest["run_count"], "total_rounds":manifest["total_rounds"],
                      "output":args.output, "sha256":manifest["run_sha256"]}, indent=2))


if __name__ == "__main__":
    main()
