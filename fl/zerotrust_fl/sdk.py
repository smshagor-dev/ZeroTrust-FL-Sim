"""Stable Python SDK surface for ZeroTrust-FL-Sim protocol v1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import TracebackType
from typing import TypeAlias

import numpy as np
import torch
from typing_extensions import Self

from .client.grpc_worker import (
    MODEL_PROTOCOL_VERSION,
    GrpcWorkerClient,
    GrpcWorkerConfig,
    TensorManifestSpec,
    UpdateMetrics,
    deserialize_update,
    manifest_for_payload,
    model_schema_sha256,
    serialize_update,
    validate_global_model_envelope,
)

SDK_API_VERSION = "1"
WorkerConfig: TypeAlias = GrpcWorkerConfig
TensorManifest: TypeAlias = TensorManifestSpec


@dataclass(frozen=True, slots=True)
class Enrollment:
    registration_id: str
    assigned_role: str
    lease_expires_unix: int
    credential_generation: int


@dataclass(frozen=True, slots=True)
class HeartbeatStatus:
    accepted: bool
    server_time_unix: int
    current_model_version: str
    lease_expires_unix: int
    credential_generation: int


@dataclass(frozen=True, slots=True)
class ModelSnapshot:
    model_version: str
    round_id: int
    model_id: str
    protocol_version: int
    created_at_unix: int
    weights: np.ndarray | None
    payload_sha256: str
    schema_sha256: str
    tensor_manifest: tuple[TensorManifest, ...]


@dataclass(frozen=True, slots=True)
class UpdateSubmission:
    accepted: bool
    update_id: str
    reason: str
    current_model_version: str


class WorkerClient:
    """Stable typed facade over the strict mTLS gRPC worker transport."""

    def __init__(self, config: WorkerConfig) -> None:
        self.config = config
        self._client = GrpcWorkerClient(config)

    @property
    def registration_id(self) -> str | None:
        return self._client.registration_id

    def wait_ready(self, timeout: float | None = None) -> None:
        self._client.wait_ready(timeout=timeout)

    def enroll(self) -> Enrollment:
        response = self._client.register()
        return Enrollment(
            registration_id=str(response.registration_id),
            assigned_role=str(response.assigned_role),
            lease_expires_unix=int(response.lease_expires_unix),
            credential_generation=int(response.credential_generation),
        )

    def heartbeat(self, observed_model_version: str = "") -> HeartbeatStatus:
        response = self._client.heartbeat(observed_model_version)
        return HeartbeatStatus(
            accepted=bool(response.accepted),
            server_time_unix=int(response.server_time_unix),
            current_model_version=str(response.current_model_version),
            lease_expires_unix=int(response.lease_expires_unix),
            credential_generation=int(response.credential_generation),
        )

    def get_model(self, known_model_version: str = "") -> ModelSnapshot:
        response = self._client.get_global_model(known_model_version)
        payload = bytes(response.weights_payload)
        manifest = tuple(
            TensorManifest(
                name=str(entry.name),
                dtype=str(entry.dtype),
                dimensions=tuple(int(value) for value in entry.dimensions),
                element_count=int(entry.element_count),
            )
            for entry in response.tensor_manifest
        )
        return ModelSnapshot(
            model_version=str(response.model_version),
            round_id=int(response.round_id),
            model_id=str(response.model_id),
            protocol_version=int(response.protocol_version),
            created_at_unix=int(response.created_at_unix),
            weights=deserialize_update(payload) if payload else None,
            payload_sha256=hashlib.sha256(payload).hexdigest() if payload else "",
            schema_sha256=bytes(response.schema_sha256).hex(),
            tensor_manifest=manifest,
        )

    def submit_update(
        self,
        update: torch.Tensor | np.ndarray,
        *,
        round_id: int,
        base_model_version: str,
        metrics: UpdateMetrics,
    ) -> UpdateSubmission:
        response = self._client.submit_update(
            update,
            round_id=round_id,
            base_model_version=base_model_version,
            metrics=metrics,
        )
        return UpdateSubmission(
            accepted=bool(response.accepted),
            update_id=str(response.update_id),
            reason=str(response.reason),
            current_model_version=str(response.current_model_version),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "SDK_API_VERSION",
    "MODEL_PROTOCOL_VERSION",
    "Enrollment",
    "HeartbeatStatus",
    "ModelSnapshot",
    "TensorManifest",
    "UpdateMetrics",
    "UpdateSubmission",
    "WorkerClient",
    "WorkerConfig",
    "deserialize_update",
    "manifest_for_payload",
    "model_schema_sha256",
    "serialize_update",
    "validate_global_model_envelope",
]
