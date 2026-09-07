from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.validate_v1_release import (
    ROOT,
    ReleaseGateError,
    load_evidence,
    metadata_versions,
    validate_evidence_schema,
    validate_publish_gate,
    validate_repository_contract,
)


def test_repository_v1_release_contract_is_structurally_valid() -> None:
    validate_repository_contract(ROOT)


def test_pre_v1_metadata_remains_aligned_until_external_gates_close() -> None:
    versions = metadata_versions(ROOT)
    assert set(versions.values()) == {"0.9.0"}


def test_v1_publication_is_fail_closed_before_final_version_bump() -> None:
    with pytest.raises(ReleaseGateError, match="does not match release metadata"):
        validate_publish_gate("v1.0.0", "a" * 40, ROOT)


def test_release_workflow_uses_prepared_v1_release_notes() -> None:
    workflow = (ROOT / ".github/workflows/release-images.yml").read_text(encoding="utf-8")
    assert 'notes="docs/releases/${VERSION}.md"' in workflow


def test_canonical_external_gates_are_unsatisfied_in_current_manifest() -> None:
    evidence = load_evidence(ROOT)
    gates = evidence["hard_gates"]
    assert {name: gate["issue"] for name, gate in gates.items()} == {
        "branch_protection": 37,
        "independent_security_assessment": 70,
        "openssf_best_practices": 73,
    }
    assert all(gate["satisfied"] is False for gate in gates.values())


def test_satisfied_external_gate_requires_https_evidence() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["branch_protection"]
    gate["satisfied"] = True
    gate["evidence_url"] = None
    with pytest.raises(ReleaseGateError, match="requires an HTTPS evidence URL"):
        validate_evidence_schema(evidence)


def test_security_assessment_requires_reviewed_commit() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["independent_security_assessment"]
    gate["satisfied"] = True
    gate["evidence_url"] = "https://example.org/review"
    gate["reviewed_commit"] = "abc"
    with pytest.raises(ReleaseGateError, match="reviewed 40-character commit SHA"):
        validate_evidence_schema(evidence)


def test_cuda_cannot_be_marked_validated_without_real_device_evidence() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    profile = evidence["supported_profile"]
    profile["cuda_status"] = "validated-real-device"
    profile["cuda_evidence_url"] = None
    with pytest.raises(ReleaseGateError, match="real-device evidence URL"):
        validate_evidence_schema(evidence)
