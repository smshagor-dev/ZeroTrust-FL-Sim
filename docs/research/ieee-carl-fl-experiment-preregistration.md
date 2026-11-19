# CARL-FL IEEE research: preregistration draft and experiment matrix

**Created:** 2026-11-19  
**Status:** DRAFT FOR SCIENTIFIC REVIEW; **no experiments claimed executed**  
**Depends on:** ieee-carl-fl-p0-originality-audit.md. Final protocol is blocked pending full-source novelty audit and choice of *faithful* published method comparators.

## Research objectives and estimands

The scientific unit is a **model-changing transition and its durable acknowledgment**, not merely an RPC response label. Rejected, crashed, timeout, and unknown-outcome transitions must be classified separately. Any statement about a successful grant/revoke/update assumes the response became an acknowledged completed operation; overlapping actions must be analyzed by an explicit serialization order.

Primary estimands:
- **Illicit durable commit count:** number of committed model versions containing a contribution from a credential generation whose revocation was acknowledged **before that contribution's serialization point**, over eligible violating attempts. Exact state verification is mandatory.
- **Ack/durability contradiction count:** a successful acknowledgment without the corresponding recoverable durable state, confirmed by a restart/independent recovery observer.
- **Recovery fencing violations:** operations acknowledged after persistence uncertainty but before verified recovery.
- **False rejection rate on legitimate scheduled contributions:** report separately from security decisions and include reasons.
- **Latency, throughput and resource cost:** measure by operation class and offered load; report p50/p95/p99 only where sample counts justify them.
- **Training outcomes:** rounds completed, lost work, final test accuracy and loss measured with *identical data partitions and training steps*, and reported separately from permission safety.

Do not calculate an 'attack success percentage' without stating the number, selection and origin of attempts. Deterministic test traces are **not** population-frequency estimates.

## Protocol A — Precisely matched ordering experiment

Define credential generations g and model versions v. Hold identity scheme, transport, model, storage hardware and traffic generator constant. Use pre-specified happens-before histories:

| ID | Schedule | Expected observable under candidate policy | Observation needed |
| --- | --- | --- | --- |
| O01 | Update admitted, revoke acknowledged, delayed update reaches transition point | Denied if generation g obsolete | Status + persisted model version and accepted-contributor IDs |
| O02 | Update commits and is acknowledged, then revoke acknowledged | Prior committed contribution remains valid | Both durable transitions and order |
| O03 | Revoke and update overlap without a total order visible to client | Either serialization order allowed; not an automatic violation | Reconstructed linearization witness |
| O04 | Same nonce retried after *known* committed update | No duplicate model contribution | Nonce and contribution identity after restart |
| O05 | Transport loses acknowledgment after a durable commit; client retries | Must not silently duplicate; classify unknown outcome and idempotent resolution | Log, retry response and recovered state |
| O06 | Credential rotation, pending contribution and new generation submission | Generation-specific validity/queuing rule consistently enforced | Before/after queue and model snapshots |
| O07 | Revocation during quorum formation | Revoked pending contribution does not satisfy later quorum | Distinct contributor set and model version |

Test the **strongest faithful published comparator** when possible. B1/B2 test variants remain negative controls. Never weaken a published baseline just to produce a positive CARL-FL result.

## Protocol B — Storage failures and recovery

Instrument fault boundaries independently: before staging, after staging/before store, during atomic store write, after durable store/before acknowledgment, during compensating restore, during restart/load, and after recoverable storage migration. Include injected I/O error, process termination, ambiguous timeout, and crash-stop. For every case record:

- Whether disk state was genuinely changed, unchanged or unknown;
- Whether a client received success, error, timeout or no response;
- Whether coordinator is fenced;
- State hash / model version / credentials / nonce history before, immediately after and after independent restart;
- Model updates observed by other participants and time to verified recovery.

**Fault-injection accuracy:** A mock exception alone is insufficient for claims about fsync or power-loss durability. StateStore implementations, filesystem, transaction isolation and disk guarantees must be specified. File-backed, PostgreSQL-backed, and other state stores are separate strata, never pooled without reporting.

**Formal analysis scope:** A new TLA+ (or comparably explicit) specification shall model independently scheduled operations, crash and ambiguous outcomes. State exactly what the model abstracts; check important invariant-preserving and intentionally broken variants. A bounded check is never described as proof of unbounded security or Go implementation refinement.

## Protocol C — Systems-scale benchmark

Proposed design levels, subject to feasibility: 10, 50 and 100 enrolled clients; at least two host placements (loopback versus independent hosts) if available; multiple offered-load levels; steady state and revoke/recovery phases. Keep identical:

- Model dimensionality and aggregation strategy;
- Token/certificate issuance and cryptographic configuration;
- Model vector payload, quorum size and data partition;
- Storage implementation and resource limits;
- Network conditions, warm-up, repetitions and seed schedule.

Measure accepted and rejected operations separately; record queue/lock waiting, persistence wall time, CPU, RSS, disk write amplification, average and tail RPC latency, accepted update throughput, and availability during fencing. Use 10+ independent seeds for stochastic training experiments and repeated independent benchmark trials; determine actual run counts through pilot precision analysis, not an arbitrary promise of statistical power.

## Protocol D — Real FL train/commit integration

Candidate public datasets: **FEMNIST and CIFAR-10**, subject to reproducible licensing/source and comparable model choices. No downloaded dataset or result is implied. Train through the real client RPC + coordinator commit path, not a separate simulation.

Keep deterministic partitions (IID and a disclosed Dirichlet alpha sweep), train/test definitions and aggregation fixed across conditions. Hold attack times independent of model outcomes where possible. Compare:

1. No revocation, fully authorized baseline;
2. Revocation without replacement, unchanged quorum;
3. Revocation with authenticated replacement;
4. Delayed post-revocation submission;
5. Storage ambiguity and verified recovery.

Use paired seeds, disclose negative/neutral findings, report accuracy and loss versus **completed legitimate rounds**, versus wall time, and versus offered scheduling slots. This prevents false conclusions when a security mechanism stalls a fixed quorum but the model has already converged.

## Protocol E — Independent comparators and attribution

Candidate independent methods for investigation:
- DA³4FL (DOI 10.1038/s41598-025-33685-1) — dynamic membership, MAC/epoch authenticity.
- RDFL (DOI 10.1109/TCSS.2025.3622952) — revocable ABE and robust aggregation.
- TGSFL (DOI 10.1007/s44443-026-01237-w) — revocable authenticated updates bound to round/epoch.

**Not yet reproduced.** Before selecting any comparator, document implementation access, source and version, faithful security semantics, whether update payload is visible and compatible, protocol feature differences, and failure mode coverage. An incompatibility must be disclosed; do not treat a missing feature in a public abstract as an experimentally verified vulnerability.

A more defensible study may assess CARL-FL as an **orthogonal composable transition layer** on top of an independently implemented published method, using a paired 2×2 factorial design:
- published security method without commit-state coupling;
- same published method with exact transition coupling;
- same method with durable recovery omitted;
- complete candidate implementation.

But this remains a **proposal**, and may fail novelty review if the combination is trivial.

## Required artifact contract

Each experiment is bound to an immutable source commit and saved in a versioned run directory containing:
- run_manifest.json: study ID, UTC start/end, immutable source SHA, clean/dirty state, workload SHA256, dataset license+checksum, environment, CPU/GPU/RAM, OS versions, toolchain, storage type/transaction mode, TLS/protocol mode, clients, quorum, seeds, fault schedule, warm-up and issued commands.
- requests.csv or requests.jsonl: request ID, client ID (pseudonymous), credential generation, round/version, nonce hash (not raw credentials), operation kind, issue/receive/serialize/commit/ack timestamps, outcome class, durable state hash and classification reason.
- state_checkpoints.jsonl: independent verifiable hashes of enrollment, generations, consumed nonces, pending contributions, model version and durable log.
- learning_metrics.csv: dataset, partition ID, seed, model, optimizer, round, wall time, available clients, accuracy, loss, accepted update count and quorum stalls.
- experiment_analysis.py: complete deterministic reproduction of all figures/tables from the raw records, including confidence intervals and precision notes.

Never commit private keys, user identity secrets, raw authentication tokens or personally identifiable participant information.

## Preliminary acceptance gates (all mandatory)

1. Full-text prior-art comparison and explicit scientifically distinct hypothesis complete.
2. At least one independent published comparator integrated faithfully, or methodological impossibility documented and research contribution re-evaluated.
3. A legitimate-success control and intentionally unsafe mutant are both demonstrated under the same instrumentation.
4. Post-restart verification of every claimed durable safety property.
5. Statistical methods and enough independent runs for meaningful confidence intervals; full logs archived.
6. Dataset license/checksum, source SHA, commands and environment published.
7. At least one full end-to-end local-training-to-durable-commit experiment, distinct from synthetic or loopback-only tests.
8. Independent scientific review addresses competing explanations, negative results and limitations.
9. The selected IEEE journal's Traditional (non-OA) option and all mandatory page fees checked; format fits its zero-charge threshold.
10. All three authors verify manuscript and affiliations, contributions, funding and conflicts.

**Decision rule:** Any unresolved critical scientific gate => do not label the paper IEEE submission-ready. Do not convert this preregistration into fabricated results.
