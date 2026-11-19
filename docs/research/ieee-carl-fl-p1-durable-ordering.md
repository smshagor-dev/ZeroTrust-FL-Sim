# IEEE CARL-FL P1: Real durable coordinator ordering validation

**Stage:** P1, controlled integration experiment, under review (2026-11-19)  
**Repository reference:** `main` after #134 (merge `029d16490b15350c86c7820c106440244e610ce6`)  
**Status:** Code and CI instrumentation prepared; results must be read from the PR's actual workflow logs. Do not cite the outcomes as successful until CI completes.

## Scientific question

Does the actual Go `DurableService`, using a file-backed `StateStore`, honor a credential revocation's acknowledgment ordering and remove a contributor's previously accepted but still-pending update from both model aggregation and the persisted recovery state?

This tests two concrete implementation properties, not the general correctness of linearizable federated learning.

- **I1 — pending-update exclusion:** If worker A has an acknowledged, persisted pending update, and its revocation is subsequently durably acknowledged while A has not yet entered an aggregate model round, the persisted queue no longer contains A. Completing the quorum with B and C must not incorporate A's vector.
- **I2 — operation ordering:** If an update holds the durable serialization point first, an overlapping revocation cannot retroactively invalidate an already acknowledged model round. Conversely, if the revocation's durable transition obtains the lock first, a competing request with that credential must not subsequently commit.
- **I3 — restart consistency:** An independent `NewDurableService` instance initialized from the same file-backed persisted state must reconstruct the post-operation model round and revocation tombstone. This test does not simulate physical power loss.

## Implemented test cases

| Test/subcase | Mechanism exercised | Mandatory observation |
| --- | --- | --- |
| `TestIEEEPendingRevocationDurabilityAndRecovery` | Four identities, 2-of-N quorum, accepted A contribution, durable admin revocation, replacement B and C, fresh file restart | A pending update removed on disk; A denied; B/C median vector committed; recovered A still revoked |
| `TestIEEEDurableUpdateRevocationOrdering/update_first` | Actual `DurableService`, real file store, intercepted *commit call* to force update then revoke | Update is durably acknowledged prior to completed revoke; no further authorization granted |
| `TestIEEEDurableUpdateRevocationOrdering/revoke_first` | Actual `DurableService`, same instrumented file store, intercepted revocation commit before competing update | Revocation is durably acknowledged; update denied; model round unchanged |

The commit barrier wraps the real state store and holds an operation at the call boundary. It is explicitly **not** a simulated power failure or proof of disk-level atomicity. Tests use the existing authenticated peer/interceptor harness, actual source `DurableService`, persistent snapshot storage and restart path.

## Commands

```bash
go test -race -count=3 ./pkg/coordinator \
  -run '^TestIEEE(PendingRevocationDurabilityAndRecovery|DurableUpdateRevocationOrdering)$' \
  -v
```

The GitHub workflow `.github/workflows/research-security-evidence.yml` runs the same selected tests with `-json` and uploads `research-artifacts/ieee-p1-durable-ordering-events.jsonl` with `research-artifacts/provenance.txt`. A passing CI is needed to report observed properties. A failed test is a falsifying result to investigate, not a reason to suppress the run.

## Important interpretation limits

1. This is *implementation-level, single-host test coverage* of a selected Go code path, not a peer-reviewed published baseline comparison or an FL end-to-end accuracy experiment.
2. File-based durable acknowledgment is a `StateStore` contract: the tests do not inject kernel crash, broken fsync, disk corruption or non-atomic cross-host storage.
3. The barrier constrains one write order, not every possible concurrent schedule. The existing bounded abstract checker and nondeterministic race tests are different evidence tiers.
4. The B/C median model vector is an artificial local update, not measured learning performance or real dataset training.
5. The trusted coordinator and credential issuer remain assumed; model poisoning by a correctly authorized worker is not prevented by authorization.
6. Neither successful tests nor the current mechanism establish a new formal algorithmic theorem or novelty relative to DA³4FL, RDFL, TGSFL, or standard transaction/linearizability theory.

## Next P1 decision gate

After race tests run green, prioritize a deterministic crash/uncertain-acknowledgment test with a truly independent state observer and a faithful published protocol comparison. If published protocols already provide the same guarantee and costs, revise the research hypothesis rather than imply new functionality from the test results.
