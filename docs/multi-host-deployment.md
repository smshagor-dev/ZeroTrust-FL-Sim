# Multi-host production reference deployment

The supported v0.7 production reference profile remains a **single coordinator** with PostgreSQL durable metadata/audit state, an S3-compatible object store for model artifacts, and independently credentialed workers distributed across Kubernetes nodes or hosts. Multi-coordinator consensus/HA is not claimed.

## Required external services

Use production PostgreSQL with TLS, backups, restricted network access, and a dedicated database identity. Use an S3-compatible object store over TLS with a dedicated bucket/prefix and least-privilege credentials. Do not use the development PKI generator for production.

Provision one coordinator PKI secret containing only the server identity, CA certificate, and JWT verification public key. Provision a distinct Secret for every worker containing only that worker's certificate, private key, JWT credential, and CA certificate. Never mount the CA signing key or JWT signing private key into the coordinator or workers.

The coordinator runtime Secret is supplied separately and should contain environment-variable keys such as `ZTFL_POSTGRES_DSN`, `ZTFL_S3_ENDPOINT`, `ZTFL_S3_BUCKET`, `ZTFL_S3_ACCESS_KEY_ID`, `ZTFL_S3_SECRET_ACCESS_KEY`, and the experiment configuration digest where used.

## Immutable images

Release workflows publish coordinator, worker, and recovery images and record their content digests. Production Helm values must use the recorded `sha256:` digests. A mutable tag alone is not accepted by the chart.

Example values fragment:

```yaml
coordinator:
  image:
    repository: ghcr.io/smshagor-dev/zerotrust-fl-sim-coordinator
    digest: sha256:<release-digest>
workers:
  - name: worker-01
    image:
      repository: ghcr.io/smshagor-dev/zerotrust-fl-sim-worker
      digest: sha256:<release-digest>
    secretName: ztfl-worker-01-pki
```

## Network topology

Expose the coordinator gRPC service only to authorized worker networks. The Helm chart defaults to deny-all for project pods and then permits worker-to-coordinator TCP/50051, DNS, coordinator metrics, and configured external service ports. Restrict the broad external egress rule further with cluster-specific CIDRs when the PostgreSQL/S3 endpoints are known.

TLS 1.3 mutual authentication remains mandatory at the application layer even inside the cluster. NetworkPolicy is defense in depth, not a replacement for workload authentication.

## Install

Create the external Secrets first, then install with digest-pinned values:

```bash
helm upgrade --install ztfl deploy/helm/zerotrust-fl \
  --namespace zerotrust-fl --create-namespace \
  -f production-values.yaml
```

The coordinator uses a single replica because durable state currently provides restart recovery, not distributed consensus. Its PodDisruptionBudget intentionally blocks voluntary disruption when it is the only serving coordinator. Each worker identity is rendered as a separate one-replica Deployment so credentials are not shared across replicas.

## Rollout and rollback

Change image digests through reviewed configuration. Before coordinator upgrades, create and verify a PostgreSQL/S3 recovery bundle using the documented recovery tooling. Roll back by restoring the previous immutable digest and, if a state migration requires it, following the explicit migration/recovery compatibility documentation rather than downgrading state blindly.

## Diagnostics

Use `ztfl validate --profile coordinator --production` before coordinator startup. From an appropriately credentialed operator/worker identity, `ztfl diagnostics` verifies TLS identity and reachability, while `ztfl experiment-status` reports the live model version, round, registration lease generation, and protocol version.
