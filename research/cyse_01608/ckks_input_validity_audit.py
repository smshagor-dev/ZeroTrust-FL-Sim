"""Native CKKS additive-only indistinguishability sanity experiment.

This is a test of a deliberately *unsupported* input-validity claim.
It is not an attack against CKKS semantic security, a ZK verification
protocol, or proof of encrypted Byzantine filtering.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np


def audit(out: Path, *, clients: int = 15, dimension: int = 32,
          cap: float = .1, perturbation: float = 1.) -> dict:
    if clients < 3 or dimension < 1 or cap <= 0 or perturbation <= cap:
        raise ValueError("invalid test parameters")
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"fl"))
    from zerotrust_fl.privacy import (
        CKKSConfig, CKKSKeyMaterial, CKKSClientEncryptor,
        CKKSServerAggregator, CKKSDecryptor, native_ckks_available
    )
    if not native_ckks_available():
        raise RuntimeError("native Microsoft SEAL CKKS must be enabled")
    material=CKKSKeyMaterial.generate(CKKSConfig())
    encryptor=CKKSClientEncryptor(material.public_bundle())
    server=CKKSServerAggregator(material.parameters)
    decryptor=CKKSDecryptor(material)
    baseline=np.zeros((clients,dimension),dtype=float)
    malformed=baseline.copy()
    malformed[0,0]=perturbation
    malformed[1,0]=-perturbation
    assert np.linalg.norm(malformed[0])>cap and np.linalg.norm(malformed[1])>cap
    assert np.array_equal(baseline.sum(axis=0),malformed.sum(axis=0))
    def encrypted_sum(inputs):
        payloads=[encryptor.encrypt(row,weight=1.)
                  for row in inputs]
        aggregate=server.aggregate(payloads,
                                   expected_weights=np.ones(clients,dtype=float))
        return decryptor.decrypt_weighted_mean(aggregate)
    original=encrypted_sum(baseline)
    spoofed=encrypted_sum(malformed)
    expected=baseline.mean(axis=0)
    original_err=float(np.max(np.abs(original-expected)))
    spoofed_err=float(np.max(np.abs(spoofed-expected)))
    if original_err>1e-5 or spoofed_err>1e-5:
        raise AssertionError("additive CKKS numerical equality failed")
    result=dict(
        kind="native encrypted addition-only input-validity non-identifiability sanity test",
        clients=clients,dimension=dimension,cap=cap,
        violating_client_norm=perturbation,
        bounded_case_cap_violations=0,
        bad_case_cap_violations=2,
        baseline_plaintext_sum_equals_malicious_sum=True,
        expected_client_weight_metadata_is_same=True,
        unviolated_ckks_mean_max_error=original_err,
        violated_ckks_mean_max_error=spoofed_err,
        native_ciphertext_additive_correctness=True,
        byzantine_filtering_proven=False,
        client_plaintext_validity_proven=False,
        claim="The same additive mean is compatible with bounded and out-of-cap individual updates; this interface cannot certify each encrypted plaintext norm.",
        warning="Elementary algebra plus numerical sanity check, not a new cryptographic protocol, attack or formal soundness reduction.",
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.output),indent=2))


if __name__=="__main__":
    main()
