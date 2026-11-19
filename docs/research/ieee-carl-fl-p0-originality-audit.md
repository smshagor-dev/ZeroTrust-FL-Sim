# CARL-FL for IEEE: P0 originality and evidence audit

**Audit date:** 2026-11-19  
**Status:** RESEARCH IN PROGRESS — NOT SUBMISSION-READY  
**Candidate venue:** IEEE Transactions on Dependable and Secure Computing (TDSC), conditional on novelty, empirical and venue checks. This document does not imply IEEE approval, external review, or acceptance.

## 1. Scope and provenance

This is a scientific gap audit, **not a new experiment** or manuscript draft. Primary research object: *CARL-FL: Commit-Aware Authorization and Recoverable Revocation in Federated Learning*, rejected at editorial screening as CYSE-D-26-02077 on 2026-11-18. The editor considered the work closer to a technical report than a sufficiently scholarly article. The decision did not supply external reviewer reports.

Inspected local source: the submitted 35-page Editorial Manager PDF (especially manuscript §§2–7), and repository files:

- docs/research/carl-fl-theory-comparison.md
- docs/research/cyse-ztfl-evaluation.md
- docs/research/cyse-measured-results.md
- pkg/coordinator/service.go
- pkg/coordinator/durable_service.go
- pkg/coordinator/research_authorization_ablation_test.go
- scripts/research/check_authorization_model.py
- scripts/research/fl_churn_study.py

Repository main reference at audit start: 2f3c0c39fae720c70b04a13d389f5fb68474596a. Source review does **not** mean experiments were rerun in this audit.

## 2. Initial editorial-level verdict

**NO-GO for immediate IEEE submission. CONDITIONAL-GO for original research development.**

CARL-FL already includes a coherent *conditional* authorization rule: serialize credential/revocation/replay/model-state mutations; authenticate against current state; acknowledge only after durable commit; fence operation after indeterminate persistence and rollback. Those elements are plausible and useful, but individually draw heavily on established authorization, replay, transaction and linearizability concepts. Merely packaging them for federated learning is **not by itself evidence of a high-impact original contribution**.

The present manuscript provides controlled mechanism ablations and selected implementation traces; it does not establish a matched advantage over an independently published baseline, a new formal algorithmic result, or broad practical performance. The paper itself acknowledges this limitation. A stronger title or rewrite without new research cannot repair it.

### Claims that must NOT be presented as novelty

- Inventing continuous authorization, certificate binding, nonces, replay prevention, revocation, serializability, linearization points, crash recovery, or a new cryptographic primitive.
- Proving security of unbounded distributed execution from a finite checker.
- Proving the deployed Go program correct from a specification-only checker.
- Presenting test-built B1/B2 controls as independent published methods.
- Presenting the 12-seed two-dimensional synthetic FL simulator as authenticated network training.
- Claiming that earlier published systems are susceptible to this specific race without inspecting their full protocol and implementing comparable, faithful variants.
- Claiming 0% failure, 100% prevention, or statistically estimated attack resistance from fixed scripted traces.

## 3. Prior-art map — verified sources and open questions

The rows are literature **threats to the novelty claim**, not proofs of inadequacy of any cited system. Abstract-only coverage is explicitly labelled.

| Work | Verified source and prior capability | Novelty pressure on CARL-FL | Unresolved comparison task |
| --- | --- | --- | --- |
| Herlihy and Wing (1990), *Linearizability: A Correctness Condition for Concurrent Objects*, DOI [10.1145/78969.78972](https://doi.org/10.1145/78969.78972) | Standard foundation for ordering concurrent object operations | A common transition/linearization point is established theory | Precisely identify an FL-specific theorem, counterexample, abstraction or empirical result beyond ordinary transactional rechecking |
| Li et al., DA³4FL (published Dec 28, 2025), DOI [10.1038/s41598-025-33685-1](https://doi.org/10.1038/s41598-025-33685-1) | Primary article explicitly covers dynamic accumulator membership, participant addition/removal, authenticated updates, timestamp/MAC checks and replay resistance | Dynamic membership/revocation and freshness are **not unique** to CARL-FL | Read implementation/security steps for exact validation-versus-aggregation timing and durable model-state semantics; do not assert a gap from absence of an abstract claim |
| Zhou et al., RDFL (IEEE TCSS, published Nov 25, 2025), DOI [10.1109/TCSS.2025.3622952](https://doi.org/10.1109/TCSS.2025.3622952) | IEEE abstract describes revocable ABE, dynamic user updates, a revocation list, secure aggregation and evaluation on EMNIST/CIFAR-100 | Prior IEEE FL mechanism explicitly combines authorization revocation with model contribution management | Inspect full algorithm and supplementary code; determine whether admission precedes or coincides with model-version commit; no implementation comparison performed yet |
| Liu et al., TGSFL (published Aug 26, 2026), DOI [10.1007/s44443-026-01237-w](https://doi.org/10.1007/s44443-026-01237-w) | Primary text §§6.3–7 describes current group membership, revocation, round/epoch binding, replay rejection, and federated training benchmarks | Directly undermines any claim that round-bound post-revocation rejection is unprecedented | Analyze scope of their accepted-transcript guarantee versus durable acknowledgment and crash uncertainty; assess feasible adapter or common workload |
| Chang and Xu (2026), *Session Lifecycle*, DOI [10.1109/ACCESS.2026.3669103](https://doi.org/10.1109/ACCESS.2026.3669103) | Related lifecycle-based network permission and revocation design, already cited in rejected paper | Revocation timing itself is established beyond FL | Isolate only versioned FL model mutation and recovery-specific aspects; obtain full paper |
| Zhang et al. (2025), zero-trust robust FL, DOI [10.1109/TMC.2025.3591632](https://doi.org/10.1109/TMC.2025.3591632) | Betrayal-aware trust and client-selection research, already cited in rejected paper | Contextual FL security baseline, *not* a direct replacement for a transaction protocol | Do not compare unrelated accuracy numbers; determine whether an orthogonal security-layer integration is feasible |

**Secondary alert:** 2026 Internet-Drafts on finality-bound revocation and execution-time authorization discuss closely analogous authorization/effectuation races, rollback and replay fencing. They are **not peer-reviewed FL baselines** and should not be counted as such; nevertheless they increase the burden to demonstrate field-specific originality. Example: [draft-das-finality-bound-revocation-00](https://datatracker.ietf.org/doc/draft-das-finality-bound-revocation/).

Primary source checks as of this audit:
- https://www.nature.com/articles/s41598-025-33685-1
- https://ieeexplore.ieee.org/abstract/document/11267258
- https://link.springer.com/article/10.1007/s44443-026-01237-w
- https://www.computer.org/publications/author-resources

**Verification limits:** RDFL details above rely on IEEE's indexed abstract/metadata; its complete article was not accessible to this audit. Full-source coverage and faithful implementation reproduction are P0 blocking tasks.

## 4. What the submitted evidence actually supports

| Evidence in CYSE-D-26-02077 | Supported claim | What it cannot support |
| --- | --- | --- |
| Five selected adverse decision scenarios per B1/B2/P; four, two, zero accepted respectively | Selected policy ablations distinguish enrollment and freshness checks | Superiority over peer-reviewed published baselines |
| Three matched policy variants with small model-round mutations | Certain weakened policies permit specific unauthorized state changes | General vulnerability prevalence or scalability |
| Bounded abstract exploration: 285 states, 695 transitions, two worker identities, two nonces each, up to three model commits and nine steps | No invariant counterexample found in the defined finite model; mutant replay rule detected | Unbounded theorem or implementation refinement |
| One-host gRPC / mutual-TLS integration: three scripted repeats, 24 update RPC attempts | Selected replay/revocation/quorum traces work through authenticated transport | Cross-host distributed FL, live client training or statistically generalizable security rate |
| 180 synthetic train + 60 test examples, 12 seeds, logistic model, non-IID churn simulation | Quorum availability and limited model-utility observations | Generalization to real datasets or the actual authenticated coordinator |
| File-durable versus in-memory in-process microbenchmark | Local snapshot persistence has substantial measured cost | Isolating cost of authorization logic or production p99/network throughput |

The repository's docs/research/cyse-measured-results.md contains **earlier CYSE-D-26-01599** measurements and a different persistence ratio. Do not mix those numbers with the submitted **CYSE-D-26-02077** manuscript unless independently reconciled to exact scripts/commits. The present audit has **not rerun** the numbers.

## 5. Candidate falsifiable hypotheses (NOT established contributions)

**H1: Post-revocation safety under acknowledged ordering.** Under verified identities, a single linearizable coordination point, and a correctly durable state store: if Revoke(g) is acknowledged before a model update of credential generation g is *serialized*, that update will not be durably acknowledged. Compare with receipt-time authorization and faithful selected published baselines. State which event is actually ordered; network arrival is not enough.

**H2: Ambiguous-write containment.** When primary state write and restoration outcomes are both uncertain, no subsequent request is acknowledged until an authoritative state is recovered. Measure acknowledged-state inconsistency under controlled fault schedules, and recovery availability/cost.

**H3: Cost of stronger coupling.** Under matched workloads and security factors, atomic authorization + nonce + revocation + model commit has a measurable additional latency, throughput and availability cost relative to separated decisions; optimized logging may lower overhead without weakening invariant H1/H2. Do not assume better latency.

**H4: FL-specific model-state consequences.** Under an identical training algorithm, dataset, client schedule and attacker timings, a delayed revoked contribution is excluded from the committed round. Measure illicit commits, rejected legitimate updates, provenance, accuracy and round availability; this is an FL-level effect, not a claim that CARL-FL detects poisoned values.

Null and negative results must be retained. These hypotheses do not establish that no earlier protocol provides equivalent guarantees.

## 6. Immediate scientific action items, in blocking order

1. **Full-text novelty check:** Read DA³4FL and TGSFL end-to-end, obtain RDFL's full algorithm and its reproducibility artifacts, and systematically search 2024–2026 IEEE/ACM work covering revocation, exactly-once effects, distributed commit, secure aggregation, FL rounds and state-machine replication. Log exact passages, assumptions and threat-model differences. An absence of a sentence from an abstract cannot establish absence of a capability.
2. **Counterexample notebook:** Construct one interleaving for receipt-time authorization -> acknowledged revoke -> late update commit. Try the **same interleaving** on the strongest faithful alternatives, and record whether their design *already* excludes it.
3. **Mechanism decomposition:** Separate transport authentication, mutable enrollment/generation, request nonce, authorization-at-version, serializable mutation, persistence, recovery fencing. Determine which coupling adds a measurable and publishable finding.
4. **Protocol contract:** Define accepted-versus-committed update, server acknowledgment, lost response/retry and idempotency, timed revoke order, recovery, pending-update invalidation, single-authority scope, and precise storage durability contract.
5. **Feasibility and precision:** Obtain baselines/code or a scientifically defensible independent reproduction. Define measurement instruments and pre-register exact expected outcomes **before** broad experiments.
6. **Submission go/no-go:** Advance only if the research shows a nontrivial validated FL-specific contribution not already resolved by published mechanisms. Otherwise pivot the scientific question and do not market a minor implementation combination as an IEEE TDSC innovation.

## 7. IEEE route and cost gate

TDSC is a **candidate**, not an eligibility decision. IEEE Computer Society identifies a hybrid Traditional route and a regular Transactions length threshold of 12 formatted pages including references/biographies. Verify submission-specific limits, 2026 policies, mandatory overlength charges, optional services and the non-OA route immediately before submission. A $0 target requires no mandatory charges, not just the absence of an APC.

Source: https://www.computer.org/publications/author-resources

## 8. Author and submission integrity gate

- CYSE PDF first page maps corresponding affiliation to **Voronezh State University**, whereas separate title page identifies **Voronezh State University of Forestry and Technologies**. Verify correct institution entry in IEEE metadata and manuscript.
- Finalize funding, competing-interest and specific author-contribution declarations with **all three authors**. Original title page still has placeholder language requiring confirmation.
- Cite correct prior rejected submission status where requested, disclose relevant preprints/overlap and use only genuine obtained results.
- No journal transfer, submission or acceptance is asserted by creating this document.

**P0 completion condition:** (a) complete systematic closest-prior-art table with full texts, (b) at least one reproducible discriminating counterexample/baseline comparison, (c) a defensible contribution statement not contradicted by earlier work, and (d) an approved pre-registered experimental protocol. Until then: **NO-GO**.
