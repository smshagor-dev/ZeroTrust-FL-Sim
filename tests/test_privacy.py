from __future__ import annotations

import math

import numpy as np
import pytest
import torch
from zerotrust_fl.privacy import (
    CKKSClientEncryptor,
    CKKSConfig,
    CKKSDecryptor,
    CKKSKeyMaterial,
    CKKSServerAggregator,
    LocalDPConfig,
    RDPAccountant,
    native_ckks_available,
    protect_model_update,
)


def test_local_dp_clips_before_noise() -> None:
    config = LocalDPConfig(
        enabled=True,
        clip_norm=2.0,
        noise_multiplier=1.5,
        delta=1e-6,
        adjacency="replace",
    )
    update = torch.tensor([3.0, 4.0])
    protected = protect_model_update(update, config, seed=1234)

    assert protected.original_norm == pytest.approx(5.0)
    assert protected.clipped_norm == pytest.approx(2.0, rel=1e-5)
    assert protected.clipping_factor == pytest.approx(0.4)
    assert protected.noise_std == pytest.approx(6.0)
    assert torch.isfinite(protected.update).all()


def test_local_dp_is_reproducible_for_simulation_seed() -> None:
    config = LocalDPConfig(enabled=True, clip_norm=1.0, noise_multiplier=0.8)
    update = torch.arange(16, dtype=torch.float32)
    first = protect_model_update(update, config, seed=99).update
    second = protect_model_update(update, config, seed=99).update
    third = protect_model_update(update, config, seed=100).update

    assert torch.equal(first, second)
    assert not torch.equal(first, third)


def test_rdp_composition_matches_gaussian_q1_formula() -> None:
    config = LocalDPConfig(
        enabled=True,
        clip_norm=1.0,
        noise_multiplier=2.0,
        delta=1e-5,
        orders=(2.0, 4.0, 8.0),
    )
    accountant = RDPAccountant(config, releases=5)

    assert accountant.rdp(4.0) == pytest.approx(5 * 4 / (2 * 2.0**2))
    epsilon, alpha = accountant.epsilon()
    expected = min(
        5 * order / (2 * 2.0**2) + math.log(1 / config.delta) / (order - 1)
        for order in config.orders
    )
    assert epsilon == pytest.approx(expected)
    assert alpha in config.orders


@pytest.mark.skipif(not native_ckks_available(), reason="native CKKS backend not built")
def test_ckks_server_aggregates_without_secret_key() -> None:
    config = CKKSConfig(
        poly_modulus_degree=8192,
        coeff_modulus_bits=(60, 40, 40, 60),
        scale_bits=40,
    )
    key_material = CKKSKeyMaterial.generate(config)
    public = key_material.public_bundle()

    client = CKKSClientEncryptor(public)
    server = CKKSServerAggregator(public.parameters)
    decryptor = CKKSDecryptor(key_material)

    first = client.encrypt(np.array([1.0, 2.0, 3.0]), weight=2.0)
    second = client.encrypt(np.array([4.0, 5.0, 6.0]), weight=1.0)
    encrypted_mean_numerator = server.aggregate([first, second])

    assert not hasattr(server, "secret_key")
    assert encrypted_mean_numerator.weight == pytest.approx(3.0)
    mean = decryptor.decrypt_weighted_mean(encrypted_mean_numerator)
    np.testing.assert_allclose(mean, np.array([2.0, 3.0, 4.0]), rtol=1e-5, atol=1e-5)


@pytest.mark.skipif(not native_ckks_available(), reason="native CKKS backend not built")
def test_ckks_chunks_vectors_larger_than_one_ciphertext() -> None:
    key_material = CKKSKeyMaterial.generate(CKKSConfig())
    client = CKKSClientEncryptor(key_material.public_bundle())
    server = CKKSServerAggregator(key_material.parameters)
    decryptor = CKKSDecryptor(key_material)

    values = np.linspace(-1.0, 1.0, key_material.slot_count + 17)
    encrypted = client.encrypt(values)
    assert len(encrypted.chunks) == 2

    aggregated = server.aggregate([encrypted, encrypted])
    recovered = decryptor.decrypt_weighted_mean(aggregated)
    np.testing.assert_allclose(recovered, values, rtol=1e-5, atol=1e-5)
