# Pre-specified confirmatory protocol — CYSE-D-26-01608

**Protocol identity:** CYSE-01608-P1-root-trust-vs-distance-selection.

This hypothesis and protocol are recorded before the dedicated thirty-seed confirmatory workflow. Earlier five-seed exploratory reports are pilot data, NOT confirmatory replicates. This study is not the originally submitted 720-run dataset and does NOT implement encrypted Byzantine filtering.

## Pre-specified primary contrast

Under Byzantine sign-flip with client-side clipping/noise protocol bypass, the additional DP-mediated bypass penalty may be larger for Multi-Krum than for FLTrust (which requires a clean server-owned trusted root set).

Define L(A,p,q,s) as benign-matched held-out accuracy loss in percentage points for aggregator A, privacy mode p, attacker compliance q and seed s. Define E(A,p,s)=L(A,p,bypass,s)-L(A,p,compliant,s). The primary contrast is:

J(s)=[E(Multi-Krum,DP-1,s)-E(Multi-Krum,clip-only,s)] - [E(FLTrust,DP-1,s)-E(FLTrust,clip-only,s)].

Test one-sided H0: the probability that J is positive is <=0.5; H1: the probability is >0.5. All null findings are reported.

## Three fixed and pre-specified source datasets

1. UNSW-NB15, validated original official train/test split from pinned repository mirror.
2. NSL-KDD, validated original KDDTrain+/KDDTest+ train/test split from pinned repository mirror.
3. CICIoT2023 2023 **derivative subsample**, pinned Hugging Face revision ae15e9328977307f6259592f175c91d31ed95cc0. Balanced binary 6,000 training / 3,000 source validation with exact numeric feature-duplicate screening.

The third dataset uses a randomized source split, not independent device/site or temporal holdout. All datasets are fixed, not random draws from world security datasets.

## Fixed design, no post-hoc model selection

- Confirmatory seeds: integers 101 through 130 inclusive, excluding pilot seeds 0–4.
- 6,000 training and 3,000 heldout rows; 15 clients, 3 Byzantine, Dirichlet alpha=0.3, 20 rounds.
- Both aggregators use identical 5% root TRAINING-row exclusion from client shards. FLTrust alone uses the clean trusted reference, a strictly stronger trust assumption.
- Exactly two methods: Multi-Krum and FLTrust; two privacy modes: clip-only and Gaussian sigma=1; two attacker compliance policies: compliant and bypass; benign and sign-flip states.
- 2 methods x 2 privacy x 2 policies x 2 states x 30 seeds = 480 executions per dataset / 9,600 FL rounds. Across three datasets: 1,440 executions / 28,800 rounds.
- No hyperparameters chosen on confirmatory holdout. Deterministic PRNG noise is for reproducible utility simulations, not operational local differential privacy.
- Updates are plaintext/noisy plaintext; no claim of CKKS-verifiable Byzantine filtering.

## Statistical decisions

Per dataset: report 30 paired J values, mean/median, 10,000 seed-resampled percentile bootstrap descriptive 95% interval, and exact one-sided binomial sign test on positive versus negative J. Zero observations are excluded from sign-test n and reported explicitly. Apply Holm correction over three source-specific tests, family-wise alpha=0.05. Do not pool source results into a population inference.

Validate each CSV source hash, original 480-grid completeness, exact 240 paired adversarial/benign rows, and all metrics against raw records. Retain seed-level values and immutable source commit. Never suppress unsuccessful runs or invent missing data.

## Scope of possible scientific claim

Statistical evidence for the hypothesis shows an assumption-dependent effect: access to a clean trusted root can change DP/Byzantine sensitivity. It cannot by itself show the FLTrust algorithm is novel, that its trust assumptions are practical, that cryptographic CKKS filtering is sound, that local DP is operational, or that the result transfers to deployment conditions. Original submission provenance and independent peer review remain separate requirements.
