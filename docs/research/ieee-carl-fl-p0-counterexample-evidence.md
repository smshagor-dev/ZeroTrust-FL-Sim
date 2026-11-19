# P0 executable ordering counterexample (2026-11-19)

## Status

**Executed locally as a minimal abstract counterexample only.** Not evidence of implementation correctness, an IEEE-ready novelty claim, or a faithful comparison with DA³4FL, RDFL, TGSFL, or any other published method.

Run:

    python scripts/research/check_commit_boundary_interleavings.py --output p0-interleavings.json

### Model and scope

One trusted coordinator, one participant credential generation, three atomic abstract events:

1. update_admission_check: initial identity/authorization decision
2. durable_revocation_ack: revocation is both durable and acknowledged
3. update_commit: proposed model mutation is applied or rejected

Require initial check to precede update commit, but allow revocation acknowledgment anywhere. Exhaustively enumerate three admissible total orders.

- **cached_admission:** uses the result of the initial authorization decision even after revocation;
- **recheck_at_commit:** re-evaluates live revocation state at the actual update commit event.

### Locally executed result

| Abstract policy | Admissible interleavings | Post-acknowledged-revocation illicit commit histories |
| --- | ---: | ---: |
| Cached earlier admission | 3 | 1 |
| Recheck at commit | 3 | 0 |

The discriminating history is:

    update_admission_check -> durable_revocation_ack -> update_commit

This is a trivial *three-event state machine demonstration*, not a new security proof. It makes the proposed falsifiable condition precise: an operation authorized at reception must not later mutate the model using stale permissions after an acknowledged revocation.

### Critical methodological limitations

- No network, real training, cryptography, nonce cache, persistence implementation, actual crash or multiple coordinators.
- Revocation durability is an **assumption** in this model, not an observed fsync/database guarantee.
- Policies are constructed controls rather than reproduced peer-reviewed implementations.
- The result does not establish CARL-FL's priority, novelty, efficacy, or correct implementation in the real Go coordinator.
- The output cannot be converted to a security-rate percentage for real deployments.

### Follow-on falsification tasks

1. Inspect the strongest comparable independently published protocol step by step. If its commit authorization already rechecks active revocation, acknowledge equivalence and abandon any false uniqueness claim.
2. Instrument real durable Go state transitions with deterministic barriers at decision, revoke, store commit and acknowledgment boundaries.
3. Repeat ordering tests with lost acknowledgment, retries, pending quorum updates and uncertain rollback using independent persistent-state recovery.
4. Connect to real local training and matched published baselines only when direct comparison is methodologically valid.

See ieee-carl-fl-p0-originality-audit.md and ieee-carl-fl-experiment-preregistration.md.
