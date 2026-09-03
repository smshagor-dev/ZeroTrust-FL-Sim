"""Strict mTLS gRPC client for Python federated workers."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

import grpc
import numpy as np
import psutil
import torch
from typing_extensions import Self

TokenSource = Callable[[], str]


@dataclass(frozen=True, slots=True)
class GrpcWorkerConfig:
    address: str
    node_id: str
    certificate_common_name: str
    ca_certificate: str
    client_certificate: str
    client_private_key: str
    jwt_token: str | None = None
    jwt_token_file: str | None = None
    server_name_override: str | None = None
    timeout_seconds: float = 10.0
    max_message_bytes: int = 64 << 20

    def __post_init__(self) -> None:
        if not self.address.strip():
            raise ValueError("address is required")
        if not self.node_id.strip():
            raise ValueError("node_id is required")
        if not self.certificate_common_name.strip():
            raise ValueError("certificate_common_name is required")
        if bool(self.jwt_token) == bool(self.jwt_token_file):
            raise ValueError("configure exactly one of jwt_token or jwt_token_file")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")


@dataclass(frozen=True, slots=True)
class UpdateMetrics:
    dynamic_epochs: int
    loss: float
    gradient_norms: tuple[float, ...]
    sample_count: int
    training_duration_ms: int


class GrpcWorkerClient:
    """Python worker client bound to an mTLS identity and JWT credential."""

    def __init__(self, config: GrpcWorkerConfig) -> None:
        self.config = config
        pb2, pb2_grpc = _load_protocol_modules()
        self._pb2 = pb2
        self._pb2_grpc = pb2_grpc
        self._registration_id: str | None = None

        root_ca = Path(config.ca_certificate).read_bytes()
        client_cert = Path(config.client_certificate).read_bytes()
        client_key = Path(config.client_private_key).read_bytes()

        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_ca,
            private_key=client_key,
            certificate_chain=client_cert,
        )
        options: list[tuple[str, Any]] = [
            ("grpc.max_send_message_length", config.max_message_bytes),
            ("grpc.max_receive_message_length", config.max_message_bytes),
        ]
        if config.server_name_override:
            options.extend(
                [
                    ("grpc.ssl_target_name_override", config.server_name_override),
                    ("grpc.default_authority", config.server_name_override),
                ]
            )

        self.channel = grpc.secure_channel(
            config.address,
            credentials,
            options=options,
        )
        self.stub = pb2_grpc.CoordinatorServiceStub(self.channel)

    @property
    def registration_id(self) -> str | None:
        return self._registration_id

    def wait_ready(self, timeout: float | None = None) -> None:
        grpc.channel_ready_future(self.channel).result(
            timeout=timeout or self.config.timeout_seconds
        )

    def register(self) -> Any:
        pb2 = self._pb2
        request = pb2.RegisterNodeRequest(
            node_id=self.config.node_id,
            certificate_common_name=self.config.certificate_common_name,
            hardware=_hardware_profile(pb2),
            security=_security_metadata(pb2),
            requested_capabilities=["fl-train", "model-update-submit"],
        )
        response = self.stub.RegisterNode(
            request,
            timeout=self.config.timeout_seconds,
            metadata=self._metadata(),
        )
        if not response.accepted or not response.registration_id:
            raise RuntimeError("coordinator rejected worker registration")
        self._registration_id = response.registration_id
        return response

    def heartbeat(self, observed_model_version: str = "") -> Any:
        registration_id = self._require_registration()
        request = self._pb2.HeartbeatRequest(
            node_id=self.config.node_id,
            registration_id=registration_id,
            observed_model_version=observed_model_version,
            security=_security_metadata(self._pb2),
        )
        return self.stub.Heartbeat(
            request,
            timeout=self.config.timeout_seconds,
            metadata=self._metadata(),
        )

    def get_global_model(self, known_model_version: str = "") -> Any:
        registration_id = self._require_registration()
        request = self._pb2.GetGlobalModelRequest(
            node_id=self.config.node_id,
            registration_id=registration_id,
            known_model_version=known_model_version,
            security=_security_metadata(self._pb2),
        )
        return self.stub.GetGlobalModel(
            request,
            timeout=self.config.timeout_seconds,
            metadata=self._metadata(),
        )

    def submit_update(
        self,
        update: torch.Tensor | np.ndarray,
        *,
        round_id: int,
        base_model_version: str,
        metrics: UpdateMetrics,
    ) -> Any:
        registration_id = self._require_registration()
        payload = serialize_update(update)
        digest = hashlib.sha256(payload).digest()
        request = self._pb2.SubmitLocalUpdateRequest(
            node_id=self.config.node_id,
            registration_id=registration_id,
            round_id=int(round_id),
            base_model_version=base_model_version,
            weights_payload=payload,
            weights_format="application/x-npy-f32",
            update_sha256=digest,
            metrics=self._pb2.LocalUpdateMetrics(
                dynamic_epochs=int(metrics.dynamic_epochs),
                loss=float(metrics.loss),
                gradient_norms=[float(value) for value in metrics.gradient_norms],
                sample_count=int(metrics.sample_count),
                training_duration_ms=int(metrics.training_duration_ms),
            ),
            security=_security_metadata(self._pb2),
        )
        return self.stub.SubmitLocalUpdate(
            request,
            timeout=self.config.timeout_seconds,
            metadata=self._metadata(),
        )

    def close(self) -> None:
        self.channel.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _metadata(self) -> tuple[tuple[str, str], ...]:
        token = self._read_token()
        return (("authorization", f"Bearer {token}"),)

    def _read_token(self) -> str:
        if self.config.jwt_token is not None:
            token = self.config.jwt_token.strip()
        else:
            token = Path(str(self.config.jwt_token_file)).read_text(
                encoding="utf-8"
            ).strip()
        if not token:
            raise RuntimeError("JWT credential is empty")
        return token

    def _require_registration(self) -> str:
        if not self._registration_id:
            raise RuntimeError("worker must register before invoking this RPC")
        return self._registration_id


def serialize_update(update: torch.Tensor | np.ndarray) -> bytes:
    """Serialize a model delta as non-pickle NumPy ``.npy`` float32 bytes."""

    if isinstance(update, torch.Tensor):
        array = (
            update.detach()
            .to(device="cpu", dtype=torch.float32)
            .contiguous()
            .numpy()
        )
    else:
        array = np.ascontiguousarray(update, dtype=np.float32)

    if not np.isfinite(array).all():
        raise ValueError("model update contains non-finite values")

    buffer = io.BytesIO()
    np.save(buffer, array, allow_pickle=False)
    return buffer.getvalue()


def deserialize_update(payload: bytes) -> np.ndarray:
    """Deserialize an update produced by :func:`serialize_update`."""

    buffer = io.BytesIO(payload)
    array = np.load(buffer, allow_pickle=False)
    if array.dtype != np.float32:
        array = array.astype(np.float32, copy=False)
    return np.ascontiguousarray(array)


def _load_protocol_modules() -> tuple[Any, Any]:
    try:
        from zerotrust_fl.protocols import fl_service_pb2, fl_service_pb2_grpc
    except ImportError as exc:
        raise RuntimeError(
            "Python gRPC stubs are missing. Run "
            "`python scripts/generate_python_proto.py` from the repository root."
        ) from exc
    return fl_service_pb2, fl_service_pb2_grpc


def _hardware_profile(pb2: Any) -> Any:
    memory = psutil.virtual_memory()
    accelerator = "cpu"
    accelerator_memory = 0

    if torch.cuda.is_available():
        accelerator = torch.cuda.get_device_name(0)
        properties = torch.cuda.get_device_properties(0)
        accelerator_memory = int(properties.total_memory)

    capabilities = ["pytorch", "multiprocessing", "model-update-submit"]
    if torch.cuda.is_available():
        capabilities.append("cuda")

    return pb2.HardwareProfile(
        architecture=platform.machine(),
        operating_system=f"{platform.system()} {platform.release()}",
        logical_cpus=int(os.cpu_count() or 1),
        memory_bytes=int(memory.total),
        accelerator=accelerator,
        accelerator_memory_bytes=accelerator_memory,
        capabilities=capabilities,
    )


def _security_metadata(pb2: Any) -> Any:
    return pb2.SecurityMetadata(issued_at_unix=int(time.time()))
