# Chaos Engineering Profiles

ZeroTrust-FL-Sim ships Chaos Mesh interfaces for Kubernetes failure injection. Chaos Mesh must be installed in the target cluster before applying these manifests.

## Required target labels

Worker pods must carry:

```yaml
metadata:
  labels:
    app.kubernetes.io/component: worker
```

The provided profiles target namespace `zerotrust-fl`.

## Profiles

- `chaos-mesh/network-loss-50.yaml`: bidirectional 50% packet loss for worker pods for 60 seconds.
- `chaos-mesh/network-jitter.yaml`: 150 ms base network delay with 100 ms jitter and 50% correlation for 60 seconds.
- `chaos-mesh/node-churn.yaml`: temporary pod failure for a random set of at most 50% of worker pods for 30 seconds.

Apply one profile at a time:

```bash
kubectl apply -f deploy/chaos/chaos-mesh/network-loss-50.yaml
kubectl apply -f deploy/chaos/chaos-mesh/network-jitter.yaml
kubectl apply -f deploy/chaos/chaos-mesh/node-churn.yaml
```

Remove the experiments:

```bash
kubectl delete -f deploy/chaos/chaos-mesh/network-loss-50.yaml --ignore-not-found
kubectl delete -f deploy/chaos/chaos-mesh/network-jitter.yaml --ignore-not-found
kubectl delete -f deploy/chaos/chaos-mesh/node-churn.yaml --ignore-not-found
```

## Coordinated Byzantine stress profile

Network/pod faults are independent of the application-level collusion model. To exercise a 50% coordinated Byzantine population locally:

```bash
python scripts/run_fl_sim.py \
  --clients 20 \
  --clients-per-round 20 \
  --min-results 20 \
  --malicious-fraction 0.50 \
  --attack collusion \
  --collusion-scale 8 \
  --aggregator median \
  --rounds 10
```

The secure four-worker gRPC Docker testbed can also be switched to 2-of-4 coordinated attackers with the provided override:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.chaos.yml \
  up -d --build --wait
```

`benign-worker-3` and `malicious-worker-1` deliberately share `ZTFL_COLLUSION_SEED=20271` and `ZTFL_COLLUSION_SCALE=8`, producing the same malicious direction for a given federated round. The service name `benign-worker-3` is retained only to reuse the existing development certificate identity; in this override it is intentionally adversarial.

This intentionally exceeds classical Krum's fault assumption. If `f=n/2`, then the Krum requirement `n >= 2f + 3` becomes `n >= n + 3`, which cannot hold. Use the 50% profile to observe failure modes and recovery behavior, not to claim a Byzantine-resilience theorem in that regime.

Never apply chaos profiles to an unrelated production namespace. Verify selectors and namespace isolation before every experiment.
