# Differential Privacy and CKKS Secure Aggregation

ZeroTrust-FL-Sim protects model-update confidentiality in two complementary layers:

- **Local Differential Privacy (LDP):** each client clips its outgoing model-update vector and adds calibrated Gaussian noise before release.
- **CKKS Homomorphic Encryption:** clients encrypt weighted model updates with a public key; the aggregation server adds ciphertexts without receiving the secret key; a separate decryptor/key authority decrypts only the aggregate.

These mechanisms address different threats. LDP reduces information leakage even if an authorized recipient sees the released update. CKKS hides individual updates from the aggregation server while it combines them. They can be composed.

## 1. Local Rényi Differential Privacy

Let the raw client update be `u` and let the clipping radius be `C`.

```math
\bar{u}=u\cdot\min\left(1,\frac{C}{\lVert u\rVert_2}\right)
```

For replacement adjacency, any two clipped updates lie inside the same radius-`C` ball, so the release-level L2 sensitivity is bounded by:

```math
\Delta_2 \le 2C
```

For add/remove adjacency the configured bound is:

```math
\Delta_2 \le C
```

The client releases:

```math
\tilde{u}=\bar{u}+\mathcal{N}\left(0,\sigma^2\Delta_2^2 I\right)
```

where `sigma` is the noise multiplier. The implementation therefore uses:

```math
\sigma_{noise}=\sigma\Delta_2
```

For the full-participation Gaussian mechanism (`q=1`), one release satisfies order-`alpha` Rényi DP with:

```math
\varepsilon_{RDP}(\alpha)=\frac{\alpha}{2\sigma^2}
```

After `T` releases, RDP composes additively:

```math
\varepsilon_{RDP}^{(T)}(\alpha)=T\frac{\alpha}{2\sigma^2}
```

The implementation converts the composed RDP guarantee to an `(epsilon, delta)` upper bound by searching configured RDP orders:

```math
\varepsilon(\delta)=\min_{\alpha>1}\left[\varepsilon_{RDP}^{(T)}(\alpha)+\frac{\ln(1/\delta)}{\alpha-1}\right]
```

### Example calculation

For replacement adjacency with `C=1`, `sigma=2`, `T=10`, and `delta=10^{-5}`:

- sensitivity: `Delta_2 = 2`
- Gaussian standard deviation: `sigma_noise = 2 x 2 = 4`
- at `alpha=8`, composed RDP is `10 x 8 / (2 x 2^2) = 10`
- converted epsilon at that order is approximately `10 + ln(10^5)/7 = 11.6447`

The accountant evaluates all configured orders and selects the smallest epsilon, so this single-order calculation is an illustration, not necessarily the final optimal privacy budget.

### Simulator and network-worker enforcement

The multiprocessing worker applies LDP after any configured poisoning transform and immediately before the update leaves the client process. The long-lived gRPC worker does the same immediately before `SubmitLocalUpdate`.

Simulator CLI example:

```bash
python scripts/run_fl_sim.py \
  --dataset synthetic \
  --clients 10 \
  --rounds 10 \
  --aggregator mean \
  --dp \
  --dp-clip-norm 1.0 \
  --dp-noise-multiplier 2.0 \
  --dp-delta 1e-5 \
  --dp-adjacency replace
```

The simulator prints a conservative per-client budget that assumes the client participates in every configured round.

Networked worker environment variables:

```text
ZTFL_DP_ENABLED=true
ZTFL_DP_CLIP_NORM=1.0
ZTFL_DP_NOISE_MULTIPLIER=2.0
ZTFL_DP_DELTA=1e-5
ZTFL_DP_ADJACENCY=replace
```

The network worker advances its RDP accountant only after the coordinator accepts the release.

### Important scope

This is **release-level local DP for a whole model-update vector**, not per-example DP-SGD. The sensitivity statement depends on clipping the released update. If sample-level privacy inside local training is required, use a per-sample-gradient mechanism such as DP-SGD in addition to or instead of this release-level mechanism.

The simulator uses deterministic seeds for reproducibility. Production clients must use a cryptographically appropriate random source rather than deterministic experiment seeds.

A fully compromised client can bypass local privacy code. LDP protects honest clients that execute the configured release mechanism; it is not a remote attestation mechanism.

## 2. CKKS Homomorphic Secure Aggregation

The native C++20 extension uses Microsoft SEAL CKKS. The default parameter profile is:

- polynomial modulus degree: `8192`
- coefficient modulus bit sizes: `[60, 40, 40, 60]`
- CKKS scale: `2^40`
- slots per ciphertext: `8192 / 2 = 4096`

For a flattened model dimension `d`, the number of ciphertext chunks is:

```math
N_{chunks}=\left\lceil\frac{d}{4096}\right\rceil
```

For `d=10^7` parameters:

```math
N_{chunks}=\left\lceil\frac{10,000,000}{4096}\right\rceil=2442
```

This is a chunk-count calculation only. Ciphertext byte size depends on the SEAL parameter set, serialization mode, and ciphertext level and must be measured rather than inferred from plaintext size.

### Key separation

The API deliberately separates roles:

1. `CKKSKeyMaterial.generate()` creates parameters, public key, and secret key.
2. `CKKSClientEncryptor` receives only public material and encrypts model updates.
3. `CKKSServerAggregator` receives only encryption parameters and ciphertexts. It does **not** receive a secret key.
4. `CKKSDecryptor` remains with a key authority or other trusted decryptor and decrypts only the aggregate.

For client `i` with sample weight `w_i` and update `u_i`, the client encrypts the weighted update:

```math
c_i=Enc_{pk}(w_i u_i)
```

The server computes only ciphertext addition:

```math
c_{sum}=\sum_i c_i=Enc_{pk}\left(\sum_i w_i u_i\right)
```

The decryptor recovers the weighted mean:

```math
u_{avg}=\frac{Dec_{sk}(c_{sum})}{\sum_i w_i}
```

The aggregation server can therefore execute the addition without the secret key and without seeing any individual plaintext update.

### Why encrypted aggregation is limited to additive FedAvg-style operations

CKKS efficiently supports approximate arithmetic, but the existing Byzantine-robust methods in this repository—Krum, Multi-Krum, coordinate median, and trimmed mean—require comparisons, ordering, nearest-neighbor selection, or coordinate sorting. Those operations are not equivalent to simple ciphertext addition and are not enabled by this CKKS path.

Encrypted aggregation currently supports **sum / weighted FedAvg-style aggregation**. Combining fully encrypted computation with Krum/median/trimmed-mean requires a substantially different protocol such as MPC, comparison circuits, trusted execution, or specialized approximate comparison schemes.

## 3. C++ backend and TenSEAL

TenSEAL is a high-level tensor homomorphic-encryption library built on Microsoft SEAL. The project keeps `tenseal==0.3.17` as an optional package extra for interoperability and experimentation. The live native extension is pinned directly to Microsoft SEAL `v4.4.3`.

The reason for using direct SEAL in the live path is version/security control: current TenSEAL 0.3.17 reports SEAL 4.3.3, while Microsoft SEAL 4.4.0 introduced a critical security update and later 4.4.x releases contain subsequent fixes. Direct pinning lets the native core consume the current 4.4.x security line without waiting for a TenSEAL release.

Build with CKKS enabled (default):

```bash
ZTFL_ENABLE_CKKS=ON python -m pip install -e .
```

Disable CKKS when a minimal/offline native aggregation build is required:

```bash
ZTFL_ENABLE_CKKS=OFF python -m pip install -e .
```

Optional TenSEAL experimentation:

```bash
python -m pip install -e '.[tenseal]'
```

Run the end-to-end native CKKS role-separation demo:

```bash
python scripts/demo_ckks_secure_aggregation.py --dimension 10000 --clients 4
```

## 4. Minimal usage

```python
import torch

from zerotrust_fl.privacy import (
    CKKSClientEncryptor,
    CKKSDecryptor,
    CKKSKeyMaterial,
    CKKSServerAggregator,
    LocalDPConfig,
    protect_model_update,
)

# Client-side release protection.
dp = LocalDPConfig(
    enabled=True,
    clip_norm=1.0,
    noise_multiplier=2.0,
    delta=1e-5,
    adjacency="replace",
)
protected = protect_model_update(torch.tensor([0.2, -0.4]), dp, seed=123)

# Key authority creates the CKKS material.
keys = CKKSKeyMaterial.generate()
public = keys.public_bundle()

# Clients receive public material only.
client = CKKSClientEncryptor(public)
c1 = client.encrypt(protected.update, weight=100)
c2 = client.encrypt(torch.tensor([0.1, 0.3]), weight=50)

# Server receives no secret key.
server = CKKSServerAggregator(public.parameters)
encrypted_aggregate = server.aggregate([c1, c2])

# Separate decryptor/key authority recovers only the aggregate.
decryptor = CKKSDecryptor(keys)
weighted_mean = decryptor.decrypt_weighted_mean(encrypted_aggregate)
```

## 5. Current integration boundary

The native CKKS API implements the encrypted-computation primitive and tests key separation. The Go coordinator in this repository currently validates/accepts FL updates but is not the component that performs model aggregation or advances the global model. Therefore this change does **not** falsely reinterpret the existing Go RPC service as an FHE aggregator.

A future encrypted wire protocol can carry CKKS ciphertext chunks through the gRPC contract to a dedicated encrypted-aggregation service. That protocol will also need ciphertext-size limits, replay binding, model/round metadata authentication, key IDs, key rotation, and aggregate-decryption authorization.

## 6. Security boundaries

- LDP protects the released update only to the degree justified by the clipping sensitivity, noise multiplier, adjacency definition, and composed privacy budget.
- CKKS is approximate arithmetic, so decrypted results include small numerical approximation error.
- The server-side CKKS API intentionally has no secret-key field, but process isolation is a deployment responsibility. Do not instantiate the decryptor inside the aggregation-server process in a real deployment.
- Key rotation, threshold decryption, distributed key generation, ciphertext replay protection, malicious-ciphertext validation, and proof of correct encryption are separate controls and are not implied by additive CKKS aggregation.
- FHE confidentiality does not replace mTLS, PQC transport, RBAC, authentication, or Byzantine-resilience controls.
