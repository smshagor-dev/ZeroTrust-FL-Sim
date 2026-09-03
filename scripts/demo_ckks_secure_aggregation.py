"""Demonstrate client encryption, server ciphertext aggregation, and separate decryption."""

from __future__ import annotations

import argparse

import numpy as np

from zerotrust_fl.privacy import (
    CKKSClientEncryptor,
    CKKSConfig,
    CKKSDecryptor,
    CKKSKeyMaterial,
    CKKSServerAggregator,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dimension", type=int, default=10_000)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.dimension <= 0 or args.clients <= 0:
        raise SystemExit("--dimension and --clients must be positive")

    rng = np.random.default_rng(args.seed)
    keys = CKKSKeyMaterial.generate(CKKSConfig())
    public = keys.public_bundle()

    client_encryptor = CKKSClientEncryptor(public)
    server = CKKSServerAggregator(public.parameters)
    decryptor = CKKSDecryptor(keys)

    plaintext_updates: list[np.ndarray] = []
    weights: list[float] = []
    encrypted_updates = []
    for index in range(args.clients):
        update = rng.normal(0.0, 0.1, size=args.dimension)
        weight = float(index + 1)
        plaintext_updates.append(update)
        weights.append(weight)
        encrypted_updates.append(client_encryptor.encrypt(update, weight=weight))

    encrypted_aggregate = server.aggregate(encrypted_updates)
    recovered = decryptor.decrypt_weighted_mean(encrypted_aggregate)
    expected = np.average(np.stack(plaintext_updates), axis=0, weights=np.asarray(weights))

    error = np.abs(recovered - expected)
    print(f"clients={args.clients}")
    print(f"dimension={args.dimension}")
    print(f"slots_per_ciphertext={public.slot_count}")
    print(f"ciphertext_chunks={len(encrypted_aggregate.chunks)}")
    print(f"max_abs_error={float(error.max()):.12g}")
    print(f"mean_abs_error={float(error.mean()):.12g}")
    print("server_secret_key_present=false")


if __name__ == "__main__":
    main()
