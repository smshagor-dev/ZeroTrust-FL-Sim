from __future__ import annotations

import hashlib
from types import SimpleNamespace

import numpy as np
import pytest

from zerotrust_fl.client.grpc_worker import (
    DEFAULT_MODEL_ID,
    MODEL_PROTOCOL_VERSION,
    NETWORK_WEIGHTS_FORMAT,
    TensorManifestSpec,
    manifest_for_payload,
    model_schema_sha256,
    serialize_update,
    validate_global_model_envelope,
)


def _entry(spec: TensorManifestSpec) -> SimpleNamespace:
    return SimpleNamespace(
        name=spec.name,
        dtype=spec.dtype,
        dimensions=list(spec.dimensions),
        element_count=spec.element_count,
    )


def _global_model(values: list[float]) -> SimpleNamespace:
    payload = serialize_update(np.asarray(values, dtype=np.float32))
    manifest = manifest_for_payload(payload)
    return SimpleNamespace(
        protocol_version=MODEL_PROTOCOL_VERSION,
        model_id=DEFAULT_MODEL_ID,
        weights_payload=payload,
        weights_format=NETWORK_WEIGHTS_FORMAT,
        sha256=hashlib.sha256(payload).digest(),
        schema_sha256=model_schema_sha256(manifest),
        tensor_manifest=[_entry(entry) for entry in manifest],
    )


def test_manifest_and_schema_digest_are_canonical() -> None:
    payload = serialize_update(np.asarray([1.0, 2.0, 3.0], dtype=np.float32))
    manifest = manifest_for_payload(payload)

    assert manifest == (
        TensorManifestSpec(
            name="flat_weights",
            dtype="float32",
            dimensions=(3,),
            element_count=3,
        ),
    )
    assert (
        model_schema_sha256(manifest).hex()
        == "cff606025d8af83f907bc6d4c6b82000e3c22b67d16bf8a3e9999f816c1c5e64"
    )


def test_valid_global_model_envelope_is_accepted() -> None:
    validate_global_model_envelope(_global_model([0.25, -0.5, 0.75]), DEFAULT_MODEL_ID)


def test_bootstrap_envelope_must_not_invent_schema() -> None:
    bootstrap = SimpleNamespace(
        protocol_version=MODEL_PROTOCOL_VERSION,
        model_id=DEFAULT_MODEL_ID,
        weights_payload=b"",
        weights_format=NETWORK_WEIGHTS_FORMAT,
        sha256=b"",
        schema_sha256=b"",
        tensor_manifest=[],
    )
    validate_global_model_envelope(bootstrap, DEFAULT_MODEL_ID)

    bootstrap.schema_sha256 = b"x" * 32
    with pytest.raises(ValueError, match="must not declare a schema"):
        validate_global_model_envelope(bootstrap, DEFAULT_MODEL_ID)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("protocol_version", 2, "unsupported model protocol version"),
        ("model_id", "different-model", "does not match"),
        ("sha256", b"x" * 32, "payload SHA-256 digest mismatch"),
        ("schema_sha256", b"x" * 32, "schema_sha256 does not match"),
    ],
)
def test_global_model_envelope_rejects_identity_and_digest_mismatch(
    field: str,
    value: object,
    message: str,
) -> None:
    model = _global_model([1.0, 2.0, 3.0])
    setattr(model, field, value)
    with pytest.raises(ValueError, match=message):
        validate_global_model_envelope(model, DEFAULT_MODEL_ID)


def test_global_model_envelope_rejects_manifest_dimension_mismatch() -> None:
    model = _global_model([1.0, 2.0, 3.0])
    model.tensor_manifest[0].dimensions = [4]
    with pytest.raises(ValueError, match="tensor_manifest does not match payload"):
        validate_global_model_envelope(model, DEFAULT_MODEL_ID)
