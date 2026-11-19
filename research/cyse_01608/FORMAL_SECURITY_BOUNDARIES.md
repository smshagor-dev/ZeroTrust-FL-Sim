# Formal security limits: local Gaussian releases, Byzantine clipping and additive CKKS

These are **claim-boundary arguments**, not a new Byzantine-tolerant cryptographic protocol or a first-of-kind formal theorem. They limit which conclusions are defensible for CYSE-D-26-01608. FLTrust is a prior-art plaintext/noisy-plaintext comparator with an extra clean-root assumption.

## Threat model

Consider n >= 2 clients transmitting updates in R^d, d >= 1. An adversary may submit arbitrary finite updates in up to f client positions. The server receives only an additive aggregate (optionally CKKS-encrypted before the key holder decrypts), individual identity/weights metadata, and no per-client zero-knowledge range proof, signed output attestation, trusted execution or authenticated verifiable client-side DP evidence. Assume a claimed client norm cap C > 0. A metadata check on an expected client weight is NOT a proof that the ciphertext contains a correctly clipped and randomized input.

### Proposition 1: per-client cap compliance is not decidable from an aggregate sum alone

Let P(U) mean *every* client update has Euclidean norm at most C. For a vector v with norm greater than C, construct U=(0,0,...,0) and V=(v,-v,0,...,0). Both have exactly the same aggregate sum 0, yet P(U)=true and P(V)=false.

Any decision rule that receives only that sum (even exact plaintext, hence also an encryption of the same sum) must produce the same result for U and V. It cannot correctly certify P for both. Authenticated per-client proofs, trusted enforcement or additional revealed information are necessary to certify such a property. This is elementary algebra, not a cryptographic hardness theorem.

The same additive-only interface cannot directly calculate coordinate-wise order statistics or client-pairwise distances on hidden individual updates. Encrypted nonlinear circuits, MPC, ZK protocols or a trusted decrypting verifier may change that interface and are outside this evaluation.

### Proposition 2: known deterministic Gaussian draws are not a deployment local-DP mechanism

A deterministic, publicly known noise sequence makes a release y=g(x)+z invertible to its clipped update g(x) by subtracting z. The statistical privacy inequality of a Gaussian mechanism requires fresh, secret, suitably sampled randomness and a bounded neighboring-input sensitivity. The study's fixed known random seeds are appropriate for matched utility measurements but do not establish operational local differential privacy. Any epsilon/delta values from the RDP accountant are **conditional reference upper bounds** for the idealized random Gaussian mechanism, not empirical privacy protection provided by this deterministic testbed.

A compromised Byzantine client can bypass its locally prescribed clipping/noise, so an honest-client privacy accountant says nothing about that malicious input's compliance.

### Proposition 3: server plaintext norm projection changes the trust interface

For a trusted plaintext gate P_C(x) projecting each vector to norm <= C, and n-client arithmetic mean with at most f malicious positions, if the honest updates are identical between two executions, the aggregate difference satisfies norm <= 2*f*C/n by triangle inequality. This elementary per-round perturbation bound is not a test-accuracy/convergence bound and does not apply to unprotected opaque CKKS ciphertext. Direction-preserving in-ball adversaries remain possible.

## What experiments establish

- Internal consistency/reconstruction of the original 720-case layout and supplementary numerical tables; no automatic provenance claim.
- Fixed benchmark results for UNSW-NB15, NSL-KDD and a known 2023 CICIoT2023 derivative; trial data provenance and explicit random split limitations.
- FLTrust as an established clean-server-root reference algorithm, compared on matched client data (source training split minus trusted root).
- Sign-flip, ALIE with perfect honest-update statistics oracle, and single-class targeted label forgery. A class-targeted label forgery is **not** a trigger-based backdoor, clean-label attack, deployment attacker or encrypted adaptive adversary.
- Native Microsoft SEAL CKKS correctness and additive-average latency/bytes. Not encrypted Multi-Krum, authenticated per-client content validity, secure DP attestation, key compromise or a formal security reduction.

## Publication claim restrictions

Do NOT claim:
- Any generally secure CKKS+Byzantine private aggregator exists in this repository.
- FLTrust under unknown/malicious server-root data retains the observed properties.
- Deterministic simulator Gaussian noise provides operational local DP guarantees.
- Results from five or thirty seeds generalize to a global population of security deployments.
- Two-/three-source pilot tests establish previously unknown, uniquely original cryptographic methods.
- Identical aggregate averages under different malicious inputs can reveal per-client clipping compliance.

A defensible research framing is a **comparative, hypothesis-driven experimental characterization of the mismatch between client compliance, local DP noise and server trust assumptions**, with fully disclosed negative findings, exact source-specific inference and explicit scope limitations. Scientific originality versus existing work must still be independently assessed by a scholarly review.

## Selected established prior work

- Cao et al., FLTrust, NDSS 2021, https://www.ndss-symposium.org/ndss-paper/fltrust-byzantine-robust-federated-learning-via-trust-bootstrapping/
- Pillutla et al., Robust Aggregation for Federated Learning, IEEE Transactions on Signal Processing 2022, https://arxiv.org/abs/1912.13445
- Bonawitz et al., Practical Secure Aggregation, ACM CCS 2017, DOI 10.1145/3133956.3133982
- Mironov, Rényi Differential Privacy, IEEE CSF 2017, https://arxiv.org/abs/1702.07476
