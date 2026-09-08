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


def test_final_v1_metadata_is_aligned() -> None:
    versions = metadata_versions(ROOT)
    assert set(versions.values()) == {"1.0.0"}


def test_v1_publication_contract_accepts_current_explicit_dispositions() -> None:
    validate_publish_gate("v1.0.0", "a" * 40, ROOT)


def test_release_workflow_uses_prepared_v1_release_notes() -> None:
    workflow = (ROOT / ".github/workflows/release-images.yml").read_text(encoding="utf-8")
    assert 'notes="docs/releases/${VERSION}.md"' in workflow


def test_canonical_assurance_gates_are_explicitly_waived_not_falsely_satisfied() -> None:
    evidence = load_evidence(ROOT)
    gates = evidence["hard_gates"]
    assert {name: gate["issue"] for name, gate in gates.items()} == {
        "branch_protection": 37,
        "independent_security_assessment": 70,
        "openssf_best_practices": 73,
    }
    assert all(gate["satisfied"] is False for gate in gates.values())
    assert all(gate["waived"] is True for gate in gates.values())


def test_satisfied_external_gate_requires_https_evidence() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["branch_protection"]
    gate["satisfied"] = True
    gate["waived"] = False
    gate["waiver"] = None
    gate["evidence_url"] = None
    with pytest.raises(ReleaseGateError, match="requires an HTTPS evidence URL"):
        validate_evidence_schema(evidence)


def test_gate_cannot_be_both_satisfied_and_waived() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["branch_protection"]
    gate["satisfied"] = True
    with pytest.raises(ReleaseGateError, match="exactly one of satisfied or explicitly waived"):
        validate_evidence_schema(evidence)


def test_waived_gate_requires_owner_acceptance() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["openssf_best_practices"]
    gate["waiver"]["accepted_by"] = "someone-else"
    with pytest.raises(ReleaseGateError, match="must be accepted by repository owner"):
        validate_evidence_schema(evidence)


def test_waived_gate_requires_substantive_limitation_disclosure() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["branch_protection"]
    gate["waiver"]["limitations"] = "too short"
    with pytest.raises(ReleaseGateError, match="substantive limitations disclosure"):
        validate_evidence_schema(evidence)


def test_security_assessment_requires_reviewed_commit_when_satisfied() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["independent_security_assessment"]
    gate["satisfied"] = True
    gate["waived"] = False
    gate["waiver"] = None
    gate["evidence_url"] = "https://example.org/review"
    gate["reviewed_commit"] = "abc"
    with pytest.raises(ReleaseGateError, match="reviewed 40-character commit SHA"):
        validate_evidence_schema(evidence)


def test_waived_security_assessment_cannot_claim_reviewed_commit() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    gate = evidence["hard_gates"]["independent_security_assessment"]
    gate["reviewed_commit"] = "a" * 40
    with pytest.raises(ReleaseGateError, match="must not claim a reviewed commit"):
        validate_evidence_schema(evidence)


def test_cuda_cannot_be_marked_validated_without_real_device_evidence() -> None:
    evidence = deepcopy(load_evidence(ROOT))
    profile = evidence["supported_profile"]
    profile["cuda_status"] = "validated-real-device"
    profile["cuda_evidence_url"] = None
    with pytest.raises(ReleaseGateError, match="real-device evidence URL"):
        validate_evidence_schema(evidence)
