"""Non-cryptographic sanity checks for claimed CKKS input-validity limits."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ckks_input_validity_audit import audit


def test_same_mean_does_not_prove_individual_norm_cap():
    honest=np.zeros((15,32))
    dishonest=honest.copy()
    dishonest[0,0]=1.
    dishonest[1,0]=-1.
    assert np.array_equal(honest.mean(axis=0),dishonest.mean(axis=0))
    assert np.all(np.linalg.norm(honest,axis=1)<=.1)
    assert np.count_nonzero(np.linalg.norm(dishonest,axis=1)>.1)==2


@pytest.mark.parametrize("kwargs",[
    {"clients":1},{"dimension":0},{"cap":0},{"perturbation":.1}
])
def test_invalid_claim_sanity_arguments_fail_early(tmp_path,kwargs):
    with pytest.raises(ValueError,match="invalid test parameters"):
        audit(tmp_path/"result.json",**kwargs)
