"""Independent in-ball Byzantine oracle regression tests.

This is a deliberately strong threat information model. It does not
establish a practical encrypted attack or a new defense.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reproduce import Config, in_ball_oracle_update, run_case, THREATS
from robust_baselines import project_l2


def test_oracle_in_ball_magnitude_and_opposite_direction():
    honest = np.asarray([[.5, 0.0], [.4, 0.1], [.3, -0.1]])
    attack = in_ball_oracle_update(honest, cap=.1)
    assert np.linalg.norm(attack) == pytest.approx(.05, abs=1e-12)
    assert float(attack @ honest.mean(axis=0)) < 0
    submitted = np.concatenate([honest, attack[None, :]], axis=0)
    np.testing.assert_allclose(project_l2(submitted, .1)[-1], attack)


@pytest.mark.parametrize("bad,cap", [
    (np.asarray([[1, 2], [np.nan, 1]]), .1),
    (np.ones((1, 4)), .1),
    (np.ones((3, 4)), 0.),
    (np.ones((3, 4)), float("inf")),
])
def test_in_ball_invalid_oracle_inputs_fail_closed(bad, cap):
    with pytest.raises(ValueError):
        in_ball_oracle_update(bad, cap)


def test_original_manuscript_design_unchanged_and_bypass_pairing():
    assert "in_ball_oracle" not in THREATS
    cfg = Config(rounds=2, partition="iid")
    case = ("breast_cancer", 0, "multi_krum", "clip_only", "in_ball_oracle")
    good = run_case(*case, cfg)
    bad = run_case(*case, Config(rounds=2, attacker_compliance="bypass"))
    assert good["final_accuracy"] == pytest.approx(bad["final_accuracy"])
    # Without private noise, in-ball updates are not changed by clipping.
    assert 0 <= bad["final_accuracy"] <= 1


def test_fltrust_trusted_root_parity_with_capped_attack():
    cfg = Config(rounds=2, partition="iid", trusted_root_fraction=.05)
    for aggregator in ("fltrust", "multi_krum"):
        row = run_case("breast_cancer", 0, aggregator, "dp_1",
                       "in_ball_oracle", cfg,
                       include_classification_metrics=True)
        assert row["trusted_root_rows"] > 0
        assert 0 <= row["balanced_accuracy"] <= 1
        assert np.isfinite(row["final_loss"])
