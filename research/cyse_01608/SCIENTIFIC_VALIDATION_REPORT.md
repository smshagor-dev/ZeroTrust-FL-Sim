# CYSE-D-26-01608 — Scientific evidence and claim-gate report

**Scope:** Investigating privacy-noise × Byzantine-client protocol bypass × aggregator trust assumptions in simulated FL-based binary network intrusion detection. This is a **new hypothesis-driven experimental extension**, not authenticated replication of the original journal-uploaded 720-run raw environment, a novel cryptographic defense, or certification of deployment privacy.

**Candidate scientific finding:** A clean-server-root trust assumption changes the measured utility consequences of Gaussian client noise and malicious protocol noncompliance relative to distance-only Multi-Krum. The contrast is consistent across three fixed IDS sources under the stated model. FLTrust and Multi-Krum are established algorithms; the contribution, if independently judged original, is the **conditional interaction characterization and reproducible, paired cross-source empirical evidence**, not invention of a new aggregator.

## 1. Rejected manuscript and correction of research identity

Original Cybersecurity manuscript CYSE-D-26-01608, rejected at editorial screening in September 2026 because the work read more like a technical report than a scholarly research article. The paper originally combined clipping, Gaussian local-DP accounting, Byzantine aggregators and separate CKKS additive averaging in 720 simulation conditions on Breast Cancer and Digits. The primary original protocol used IID-style client partitions.

This research branch is about **privacy/Byzantine/CKKS**, not Zero Trust authorization even though the software repository has ZeroTrust in its name.

## 2. Original-design supplementary numeric audit

Three matching manuscript-associated Additional Files 1–3 were recovered from the author's Library (dated September 23, 2026). They are **not published in this repository**, because their exact original Editorial Manager submission identity is not independently authenticated.

- Original 720-run factorial table complete (2 datasets × 5 seeds × 4 aggregation rules × 6 privacy modes × 3 threats), no duplicate/missing grid cells.
- All 72 summary group rows recalculated from run file and matched accuracy, cross-entropy loss, mean attack loss and loss inflation.
- Nineteen published Wilcoxon comparisons had consistent mean effect estimates; independently recomputing exact two-sided Wilcoxon yielded 10 differing p-values without tie-rounding, seven after 10-decimal tie-normalization. Apply a consistent new analysis convention instead of silently copying original p-values. With a 19-family Holm correction, four contrasts remain under 0.05 in the rechecked data.
- Manuscript headline sign-flip loss from raw file: approximately 87.05 percentage points for unprotected Mean, 1.16 for clipping-only Mean. These are **exploratory and manuscript-associated** numbers, not reconstructed historical executable provenance.
- [Fail-closed source integrity script](original_supplement_audit.py) checks the grid, per-group metrics, paired statistical unit and corrected Holm-19 report for authentic user-provided CSV inputs. Synthetic fixtures validate refusal of altered or incomplete data.

**Nonresolvable from available evidence alone:** immutable date-stamped original execution logs, exact original program and original file receipt/hashes from Editorial Manager. Source metadata and a postdated upload cannot prove these facts. Do not call the original manuscript a verified exact replication.

## 3. New datasets and matched experimental units

| Source | Data provenance | Training and held-out samples | Caveat |
| --- | --- | --- | --- |
| UNSW-NB15 | Hash-verified archived original-split files, pinned upstream Git blobs | 6,000 / 3,000, per seed | Older IDS benchmark; sampled source split |
| NSL-KDD | Hash-verified archived KDDTrain+/KDDTest+ from pinned repository mirror | 6,000 / 3,000, per seed | Older source with known dataset shifts |
| CICIoT2023 | 2023 1.34M-row derivative, HF revision ae15e9328977307f6259592f175c91d31ed95cc0, random_3way train/validation | 6,000 / 3,000 fixed balanced-binary sample | Not original full corpus; no temporal/device/group holdout; exact numeric-feature-duplicate screening only |

Source handlers never train on holdout rows; numerical scaler/imputer is trained on sampled training rows only. Original 720-run toy datasets and new IDS source datasets are never pooled as identical sampling frames. The 2023 derivative's intentionally balanced classes do not represent natural attack prevalence.

The comparison's **simulation randomization seed**, not one algorithm/attack cell or one FL round, is the within-source inferential unit. Separate datasets are three fixed sources, not iid draws from the population of cybersecurity environments.

## 4. Existing controlled exploratory stress validation

- 12-scenario (2 datasets × three Byzantine counts f=1,3,6 × two heterogeneity α=0.3,1.0), full 5-seed paired study with Mean, Multi-Krum, RFA, server-clipped RFA, sign-flip and ALIE statistics-oracle attacks, two privacy modes and two client compliance policies: **2,880 executions / 57,600 rounds**, 312 exploratory seed-based contrasts.
- Dedicated experiment matrix: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42622401485 (passed all jobs, archived hashed raw and paired artifacts).
- Additional known-prior-art FLTrust implementation: cosine trust score weighted by clean root gradient, trusted norm-matching, fail-closed no-positive-trust condition. Uses 5% of the training partition as a server-held clean reference, removed from the client shards for **both** compared methods. It does **not** operate on encrypted CKKS updates and is NOT a new algorithm.
- Real-source five-seed pilot across three IDS sources included sign-flip, perfect honest-pre-noise-statistics-oracle ALIE and targeted forged-label poisoning. The targeted-label experiment is **not** an image-trigger/activation backdoor.
- Baseline/sensitivity reproducibility workflows for the 2023 derivative and historical sources passed, including raw hashes, per-class recalls, macro-F1, balanced accuracy, source manifests, paired sign comparisons and modification refusal.

## 5. Confirmatory study: prospective NEW 30 seeds

**Protocol was frozen before the distinct new-seed experiment** (pilot seeds 0–4 were previously observed and informed the design). See [CONFIRMATORY_PROTOCOL.md](CONFIRMATORY_PROTOCOL.md), [confirmatory_analysis.py](confirmatory_analysis.py), and successful all-jobs [workflow 42689973202](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42689973202).

The pre-specified primary contrast:
- Let L(A,p,q,s) = benign-matched heldout percentage-point accuracy loss, for aggregator A, privacy mode p, client compliance q, and seed s.
- Define E(A,p,s)=L(A,p,bypass,s)−L(A,p,compliant,s).
- Define **J(s)=[E(Multi-Krum,DP-1,s)−E(Multi-Krum,clip-only,s)]−[E(FLTrust,DP-1,s)−E(FLTrust,clip-only,s)]**.
- One-sided pre-specified source-specific sign tests H0: P[J>0] ≤ 0.5 versus H1 P[J>0] > 0.5, exact binomial, Holm adjustment across all three sources at familywise α=.05.

Fixed 30 **new** seeds (101–130), 15 clients, three malicious, 20 rounds, Dirichlet α=.3, both clients pools exclude identically selected clean 5% server root; all 2 methods × 2 privacy modes × 2 compliance policies × 2 states × 30 seeds. **480 executions / 9,600 FL rounds per source; 1,440 / 28,800 total**, not 1,440 independent source-level observations.

| Source | Mean J (pp) | Descriptive seed-bootstrap 95% interval (pp) | Positive/negative/ties | One-sided exact sign test p | Holm-3 adjusted p |
| --- | ---: | --- | --- | ---: | ---: |
| UNSW-NB15 | +36.4889 | [33.4753,39.2813] | 30/0/0 | 9.31323e-10 | 2.79397e-9 |
| NSL-KDD | +44.5767 | [41.5477,47.1822] | 30/0/0 | 9.31323e-10 | 2.79397e-9 |
| CICIoT2023 | +54.4411 | [50.7478,57.8658] | 30/0/0 | 9.31323e-10 | 2.79397e-9 |

The analysis script independently verifies exact 480-cell grids, 240 benign-matched attack pairs per source, CSV SHA-256 hashes, 30 complete observations, fixed factors, seed disjointness from pilot, and source-specific sign-test/Holm computation. The CI release stores raw input-matched CSVs and final per-seed J with independent manifest checksums.

**Interpretation:** On these fixed sources, model, attack and privacy-release settings, distance-only Multi-Krum has a larger DP-mediated malicious bypass penalty than trusted-root FLTrust. The **extra trusted clean root is part of the treatment**, not controlled away, and cannot be inferred available in untrusted deployments. The three source-specific p-values are NOT evidence of population-level generalization or a new cryptographic protocol. Preregistration followed exploratory pilot analysis, not blind hypothesis discovery.

## 6. CKKS native correctness, throughput, confidentiality and impossibility boundary

[FORMAL_SECURITY_BOUNDARIES.md](FORMAL_SECURITY_BOUNDARIES.md) records an elementary counterexample: U=(0,0,…), V=(v,−v,0,…), |v|>C yield the same plaintext sum, but U satisfies every individual clip bound and V violates two. Thus sum-only access cannot certify each client obeyed local clipping; CKKS-encrypted additive-only aggregation does not add per-client plaintext validity.

[ckks_input_validity_audit.py](ckks_input_validity_audit.py) tests the same with the actual native Microsoft SEAL CKKS engine, with 15 clients, 32 coordinates and C=.1; two clients send ±1.0 and the encrypted average has numerical error under 1e-8 in both bounded and violating cases. This is **a negative functional demonstration of missing input proof, not a break of CKKS encryption**.

Successful [60-trial native workflow 42690823857](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42690823857): 20 measurements each for 1,024, 4,096 and 8,192 model-update dimensions (15 encrypted client updates, actual C++/SEAL implementation).

| Dimension | Median encrypt 15 clients (ms) | Median aggregate (ms) | Median decrypt (ms) | Serialized ciphertext bytes | Maximum observed absolute error |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 649.00 | 41.23 | 42.55 | 5,899,935 | 1.78e-9 |
| 4,096 | 650.62 | 41.41 | 42.24 | 5,899,935 | 2.18e-9 |
| 8,192 | 694.48 | 42.40 | 42.06 | 11,799,870 | 2.15e-9 |

Measurements depend on the CI CPU/runtime and SEAL parameters; no separate encrypted client validity checks, authentic weight binding, key compromise resistance, production latencies or Byzantine-resistant encrypted selection was established. The correct label is **additive encryption correctness plus an explicitly missing protocol security property**.

## 7. Local-DP accounting and explicit privacy limitations

The original RDP accountant uses theoretical Gaussian mechanism release-level accounting and the stated L2 sensitivity. Experimental noise is deterministically seeded, a requirement for matched comparisons but unsuitable for operational local differential privacy when seeds or draws are known. A malicious client can bypass local clipping/noise altogether. CKKS encryption of sums is not identical to individual differential privacy, and encrypted addition without proofs does not establish input compliance.

There is **no auditable deployment privacy/δ guarantee** in this branch. All reported epsilon values must be labeled *idealized analytical reference bounds under fresh secret random sampling, specified adjacency and sensitivity*, not demonstrated production privacy. Do not conflate confidentiality of ciphertexts with robustness to forged encrypted updates.

## 8. Prior-art and originality boundary

Verified relevant literature constraining novelty:

- Cao et al., **FLTrust: Byzantine-robust Federated Learning via Trust Bootstrapping**, NDSS 2021: https://www.ndss-symposium.org/ndss-paper/fltrust-byzantine-robust-federated-learning-via-trust-bootstrapping/
- Pillutla et al., **Robust Aggregation for Federated Learning**, IEEE TSP 2022: https://arxiv.org/abs/1912.13445
- **Enhancing Byzantine robustness of federated learning via tripartite adaptive authentication**, Journal of Big Data 2025: https://doi.org/10.1186/s40537-025-01165-y (already compares RFA, Multi-Krum and FLTrust)
- **FORTRESS-FL: Byzantine-robust and privacy-preserving federated orchestration**, Array 2026: https://doi.org/10.1016/j.array.2026.100680 (co-considers poisoning and DP)
- **Byzantine-resilient federated edge intrusion detection for heterogeneous IoT networks under non-IID conditions**, 2026: https://doi.org/10.1007/s44163-026-02405-7

It is not novel to combine existing algorithms or to say privacy and robustness can conflict. The **narrow candidate contribution** is the controlled source-specific *compliance-bypass × privacy × server-root trust* contrast, with clean-root data partition parity, separate original-data provenance audit, new-seed confirmatory evidence and CKKS input-validity counterexample. Its scientific originality still needs a carefully documented, complete literature distinction and independent scholarly assessment; acceptance cannot be promised.

## 9. Claim-by-claim outcome

| Claimed question | Empirical/scientific status | Evidence limit |
| --- | --- | --- |
| Original 720-case numerical table self-consistency | **Verified** on recovered files | Historic Editorial Manager provenance not authenticated; statistics require reanalysis |
| Byzantine protocol-bypass effects | **Measured** with source-hashed pilot studies and exploratory stress | Fixed threat/model; deterministic noise |
| New 30-seed trust-root interaction | **Confirmatory H1 supported in 3 fixed source-specific tests** | Not population inference; trusted clean server data |
| Non-IID and varying Byzantine population | **Exploratory sensitivity measured** | Limited α/f/attack coverage |
| Real independent intrusion tasks | **Three sources benchmarked**, third is 2023 derivative | Only two historical original splits + one random-split derivative |
| Native CKKS addition fidelity/overhead | **Verified** 60 native trials + nonidentifiability counterexample | Not encrypted Byzantine input-validity protocol |
| Operational local DP | **NOT VERIFIED** | Public/deterministic seeds; no deployable proof |
| CKKS-encrypted robust Byzantine filtering | **NOT IMPLEMENTED/PROVEN** | No ZK/MPC input validity or encrypted nonlinear robust selection |
| First-ever algorithm/security theorem | **NOT CLAIMED** | FLTrust, RFA, Krum, DP+Byzantine prior art |
| Submission-ready new Cybersecurity original research article | **NOT CERTIFIED** | Novelty positioning, independent sources and full methods/manuscript rewrite still required |

## 10. Manuscript reconstruction recommendation

Avoid trying to present the original architecture description as a new algorithm. A defensible revised paper can focus on **a preregistered source-specific trust-assumption interaction under noncompliant Byzantine updates**, with explicit RQ and statistical hypotheses, negative results, caveats and independently downloadable evidence.

Suggested accurate working title: **“How Trusted Server Data Changes Privacy–Byzantine Robustness Interactions in Federated Intrusion Detection: A Three-Source Confirmatory Simulation Study.”** This title does not promise an unimplemented secure encrypted Byzantine method or deployment-grade local DP.

Do not silently substitute recovered 2026-09-23 supplementary files for authenticated 2026-09-09/15 Editorial Manager attachments; instead clearly describe their provenance and compute replacement tables from the independently rerunnable research workflow.

**Current branch**: research/cyse-01608-reproducibility; **PR #121 remains DRAFT**. Benchmarks passing does not justify merging into main or declaring the rejected manuscript ready for resubmission.


## 11. Supplementary in-ball honest-statistics-oracle stress (2026-11-09)

**Research branch extension, not a prospectively pre-specified confirmatory test.** Added `in_ball_oracle` attack to the separate supplemental threat set, leaving the original 720-run design untouched. The attacker is given the true mean of honest *pre-noise* gradients each round, deliberately reverses its direction and sends a vector with Euclidean norm `C/2`. This is a strong, artificial oracle-information scenario, not an ordinary observed attacker or an encrypted CKKS adversary. Its magnitude lies inside the server clipping bound, so clipping alone cannot reject it. Reference: `in_ball_oracle_update()` and `test_in_ball_oracle.py`.

The source-pinned matched 5-seed evaluation compares Multi-Krum and existing FLTrust with the SAME 5% disjoint server-root training-row removal, local `clip_only` vs `dp_1`, compliant vs malicious-client bypass, and benign vs in-ball-oracle records. Both UNSW-NB15 and NSL-KDD use 6,000 sampled training and 3,000 held-out rows; n=15, f=3, alpha=0.3, 20 rounds. Each source has 80 cases/1,600 rounds, 40 accuracy-drop matched pairs, 20 per-seed effects and 6 exploratory statistical contrasts.

| Source | Multi-Krum bypass attack accuracy, clip only | Multi-Krum bypass attack accuracy, DP σ=1 | FLTrust bypass attack accuracy, clip only | FLTrust bypass attack accuracy, DP σ=1 | Exploratory mean interaction J (pp) |
|---|---:|---:|---:|---:|---:|
| UNSW-NB15 | 69.53% | 45.11% | 74.48% | 69.31% | +14.17 |
| NSL-KDD | 74.22% | 52.13% | 74.95% | 73.93% | +16.43 |

These are five-seed averages under the in-ball-oracle condition. Raw data and per-seed interactions were independently recomputed from the Actions archives, and missing/modified artifact hashes are rejected by the workflow. In both studies all five seed-level `J` contrasts were positive; **there is no post-hoc population-level hypothesis claim**. This counterexample shows an L2 norm check cannot establish update honesty. It gives further *conditional* sensitivity evidence for the trusted-root setting, not a new robust defense or encrypted secure protocol.

- [Successful GitHub experimental workflow](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42694848140).
- Test and implementation: `research/cyse_01608/tests/test_in_ball_oracle.py`, `research/cyse_01608/reproduce.py`, `.github/workflows/cyse-inball-oracle.yml`.

**Conclusion is unchanged:** the limited, pre-specified 30-seed empirical RQ is reproducible. Full Cybersecurity submission readiness for the *original privacy + Byzantine + CKKS secure aggregation paper* is NOT certified because original pre-submission provenance, deployed LDP, encrypted malicious-input validity, generalizable external validity and independent novelty review are missing. The rewritten narrow empirical paper must not claim these unsupported capabilities.


## 12. Scientific stability hardening: raw result integrity, secondary endpoints and reproducible tolerance

The frozen P1 pre-specified contrast is unchanged. A **separate, non-inferential validation gate** (`scientific_stability_gate.py`) now recomputes study results from the raw `baseline_runs.csv` and independently checks:

1. Exactly three fixed source identities, seed IDs 101–130, 480 conditions per source, and disjoint 5% trusted root metadata. The first two source mirrors must have their pinned commits; the 2023 derivative must retain its sampled-source manifest and non-grouped-holdout disclosure.
2. All 1,440 trial classification confusion matrices (2×2, 3,000 held-out labels each) algebraically reproduce accuracy, per-class recall, macro-F1 and balanced accuracy. Invalid loss/metrics and incorrect noise/clip factors fail.
3. All 240 clean/attacked pairs per source recompute accuracy/F1/balanced-accuracy changes, exactly eight summary rows per source recompute from the 30 paired seeds, benign/no-attack runs are invariant to the nominal malicious compliance flag.
4. All P1 per-seed Multi-Krum and FLTrust privacy-by-bypass contrasts, one-sided binomial sign-test p-values, 10,000 fixed-seed bootstrap intervals and the published three-source Holm adjustment match raw records.
5. `P1_EVIDENCE_FREEZE.json` pins canonical scientific outputs to the independently archived source run, refusing silent changes in pair/summary/J effects, input split metadata, report conclusions or substantive loss values. The true historic author manuscript raw file provenance is NOT part of this freeze.

**Numerical reproducibility edge case discovered and resolved transparently:** Two independently re-executed UNSW-NB15 runs generated identical accuracy, F1, balanced accuracy, attack pairs, summary and primary J values; however, 102 of 480 `final_loss` decimals differed in the last serialized digit (differences on the order of 1e−16). A naive whole-file checksum therefore incorrectly blocked an otherwise numerically identical experiment. The evidence gate now preserves the exact original archive digests, checks all raw-file internal hashes against each manifest, and anchors a **canonical scientific digest with `final_loss` formatted to 12 decimal places**. A substantive difference exceeding the declared precision will not match the freeze. Upstream source metadata and all report/source hashes *other than those mechanically dependent on the raw-byte loss field* are checked. It is not permissible to replace the freeze silently after changing data, methods, or protocol.

### Secondary metric stability (descriptive, NOT newly preregistered significance tests)

The same P1 interaction applied independently to raw macro-F1 and balanced accuracy:

| Fixed source | Macro-F1 mean J (pp) | Positive seeds | Balanced accuracy mean J (pp) | Positive seeds |
| --- | ---: | ---: | ---: | ---: |
| UNSW-NB15 | +35.999 | 30/30 | +36.118 | 30/30 |
| NSL-KDD | +48.018 | 30/30 | +49.208 | 30/30 |
| CICIoT2023 derivative | +54.299 | 30/30 | +54.441 | 30/30 |

These **post-hoc descriptive triangulations** reduce concern that the primary pattern is merely an overall-accuracy metric artifact. They do not supply a new inferential test family, solve correlated sampling, or validate the original unimplemented CKKS Byzantine security claims.

**Scientific status:** The conditional, fixed-source numerical P1 study has strong reproducibility and fail-closed audit controls. It is not an unconditional original algorithm, an authenticated historical manuscript reproduction, a deployed LDP system or a fully proven private Byzantine-resistant CKKS protocol. No journal-level originality or submission decision is claimed.
