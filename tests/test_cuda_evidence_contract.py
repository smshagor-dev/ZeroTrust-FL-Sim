from __future__ import annotations

import pytest
import torch

from scripts.capture_cuda_parity_evidence import capture


COMMIT = "b" * 40


def test_cuda_evidence_refuses_cpu_only_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)

    with pytest.raises(RuntimeError, match="real visible CUDA device"):
        capture(commit_sha=COMMIT, seed=42)


def test_cuda_evidence_requires_native_cuda_build(monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.capture_cuda_parity_evidence as evidence

    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(evidence, "cuda_extension_available", lambda: False)

    with pytest.raises(RuntimeError, match="ZTFL_ENABLE_CUDA=ON"):
        capture(commit_sha=COMMIT, seed=42)
