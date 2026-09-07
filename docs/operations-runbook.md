# Operations objectives and recovery runbooks

ZeroTrust-FL-Sim v0.9 is a research and simulation release candidate, not a production SLA or certification. The objectives below define measurable operator targets for the supported deployment profile and the evidence expected when diagnosing failures.

## Operating objectives

The following targets apply only when the configured durable backend, host, network, certificates, and dependencies are healthy enough to provide their documented service:

- coordinator readiness target: at least 99.5% over a 30-day observation window;
- authenticated coordinator RPC server latency target: p95 below 500 ms for control-plane operations, excluding client training time and intentionally injected network delay;
- durable container-restart recovery target: return to Ready within 5 minutes with the last acknowledged model/policy state intact;
- acknowledged-state-loss objective: zero acknowledged coordinator state transitions after a durable commit failure; failed commits must roll back in memory and remain unacknowledged;
- model-identity integrity objective: zero successful durable restarts when the configured model ID differs from schema-v3 persisted state;
- round-liveness objective: a supported simulation round either reaches its configured quorum before the round timeout or reports failed/straggler clients without leaking worker processes;
- supported-image vulnerability gate: zero configured HIGH or CRITICAL findings in coordinator, worker, and recovery runtime images at the release evidence commit.

These are release operating objectives. They are not claims that every external environment will meet the targets.

## Signals to collect first

For every incident capture:

- exact 40-character Git commit SHA and release version;
- coordinator state backend and experiment/model IDs;
- coordinator and worker logs;
- pod/container restart counts and readiness state;
- current model version and round ID;
- update acceptance/rejection codes;
- Prometheus RPC, update, aggregation, churn, and memory metrics when telemetry is enabled;
- durable backend health and available storage capacity;
- certificate validity, certificate identity, JWT issuer/audience, and registration lease state.

Do not replace evidence with a successful health probe alone. A healthy TCP/gRPC listener does not prove model progress, durable recovery, or worker authorization.

## Coordinator not Ready

1. Inspect container/pod termination reason and coordinator logs.
2. Confirm server certificate, private key, client CA, and JWT verification key are mounted and readable by the non-root runtime user.
3. Confirm `ZTFL_MODEL_ID`, `ZTFL_EXPERIMENT_ID`, aggregation policy, quorum, and durable backend configuration match the persisted state.
4. If the error reports durable model or experiment identity drift, do not delete state to force startup. Restore the intended runtime configuration or intentionally start a new state backend/experiment.
5. If the error reports unsupported/corrupt state schema, preserve the state artifact and use a compatible binary or a reviewed migration. Do not edit `schema_version` by hand.
6. If PostgreSQL/S3 is configured, verify database connectivity and referenced model artifacts before restarting repeatedly.

## Durable write failure

The coordinator must not acknowledge a transition whose durable commit failed.

1. Capture the original commit error and backend logs.
2. Verify the in-memory model/version did not advance beyond the persisted snapshot.
3. Restore filesystem permissions/capacity, PostgreSQL availability, or S3 availability as applicable.
4. Retry through a normal client request only after the backend is healthy.
5. If rollback persistence also fails, stop the coordinator and recover from the last known-good durable backup rather than continuing with uncertain state.

The regression suite injects a durable write failure and verifies in-memory rollback plus persistence of the previous state.

## Model identity or schema mismatch

A schema-v3 durable state binds `policy.model_id` independently of the network envelope.

- A changed `ZTFL_MODEL_ID` must fail before state is normalized or advanced.
- Schema-v1/v2 state may adopt the configured model ID exactly once during migration and is then rewritten as schema v3.
- A schema-v3 state missing `model_id` is corrupt and must fail closed.
- Network updates with the wrong model ID, protocol version, tensor schema digest, round, model version, vector dimension, or non-finite values must be rejected rather than coerced.

Do not work around these failures by renaming a model while reusing its durable state.

## Quorum starvation and worker churn

1. Compare configured `min_updates` with active authorized workers.
2. Inspect worker registration/lease expiry and update rejection codes.
3. Check for stale base model versions after a worker recovered from a delay.
4. Confirm the configured Byzantine algorithm has a population large enough for its `f` and `k` bounds.
5. For simulations, inspect failed and straggler client sets and verify worker processes terminate after the round timeout.
6. Scale or recover workers only after determining whether the loss is expected fault injection or an infrastructure failure.

Do not lower Byzantine safety bounds merely to make an unsafe population pass.

## Certificate, JWT, or registration failures

1. Confirm certificate SAN identity matches the node ID and configured trust domain.
2. Confirm the worker certificate chains to the configured client CA.
3. Confirm JWT issuer, audience, expiry, and node identity are correct.
4. Re-register after an expired/revoked lease using newly issued credentials when required.
5. Never copy the CA private key or JWT signing private key into worker/coordinator runtime secrets.

CI development PKI is ephemeral test material and must not be reused as deployment PKI.

## Network disruption

For packet loss/jitter experiments, measure observed gRPC failures/latency rather than treating configured fault percentages as observed transport behavior. TCP, HTTP/2, retries, deadlines, and correlated faults change the effective result.

If the environment does not provide a NetworkPolicy/chaos implementation, record the limitation instead of claiming enforcement or fault evidence.

## Recovery verification

After any coordinator recovery:

1. verify the persisted schema and `model_id`;
2. verify the recovered model version/round is the last acknowledged version;
3. verify pending updates and replay/rate-limit state are consistent;
4. verify the same credentials/PKI trust root remain active unless rotation was intentional;
5. perform an authenticated worker registration/model fetch/update cycle;
6. confirm a new round can advance and the resulting state can be committed.

The Docker and Kubernetes release evidence workflows exercise restart recovery separately so a successful container runtime does not substitute for durable-state correctness.
