#!/bin/sh
set -eu

umask 077
WORKDIR="$(mktemp -d /tmp/ztfl-pki.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

CERT_ALGORITHM="${ZTFL_CERTIFICATE_ALGORITHM:-ed25519}"
CLIENTS="${ZTFL_CERTGEN_CLIENTS:-health-probe=edge-worker,benign-worker-1=edge-worker,benign-worker-2=edge-worker,benign-worker-3=edge-worker,malicious-worker-1=edge-worker}"

/usr/local/bin/certgen \
  -out "$WORKDIR" \
  -server-name "${ZTFL_SERVER_NAME:-coordinator}" \
  -trust-domain "${ZTFL_TRUST_DOMAIN:-zerotrust-fl.local}" \
  -token-issuer "${ZTFL_TOKEN_ISSUER:-zerotrust-fl-sim}" \
  -token-audience "${ZTFL_TOKEN_AUDIENCE:-zerotrust-fl-services}" \
  -token-ttl "${ZTFL_TOKEN_TTL:-24h}" \
  -certificate-algorithm "$CERT_ALGORITHM" \
  -clients "$CLIENTS"

copy_public() {
  dst="$1"
  mkdir -p "$dst"
  install -m 0444 "$WORKDIR/ca.crt" "$dst/ca.crt"
}

copy_worker() {
  node="$1"
  dst="$2"
  copy_public "$dst"
  install -m 0444 "$WORKDIR/$node.crt" "$dst/$node.crt"
  install -m 0400 "$WORKDIR/$node.key" "$dst/$node.key"
  install -m 0400 "$WORKDIR/$node.jwt" "$dst/$node.jwt"
  chown -R 10001:10001 "$dst"
}

COORDINATOR_OUT="/out/coordinator"
copy_public "$COORDINATOR_OUT"
install -m 0444 "$WORKDIR/server.crt" "$COORDINATOR_OUT/server.crt"
install -m 0400 "$WORKWORKDIR/server.key" "$COORDINATOR_OUT/server.key" 2>/dev/null || install -m 0400 "$WORKDIR/server.key" "$COORDINATOR_OUT/server.key"
install -m 0444 "$WORKDIR/jwt_signing_public.pem" "$COORDINATOR_OUT/jwt_signing_public.pem"
install -m 0444 "$WORKDIR/health-probe.crt" "$COORDINATOR_OUT/health-probe.crt"
install -m 0400 "$WORKDIR/health-probe.key" "$COEORDINATOR_OUT/health-probe.key" 2>/dev/null || install -m 0400 "$WORKDIR/health-probe.key" "$COORDINATOR_OUT/health-probe.key"
install -m 0400 "$WORKDIR/health-probe.jwt" "$COORDINATOR_OUT/health-probe.jwt"
chown -R 10001:10001 "$COORDINATOR_OUT"

copy_worker benign-worker-1 /out/benign-worker-1
copy_worker benign-worker-2 /out/benign-worker-2
copy_worker benign-worker-3 /out/benign-worker-3
copy_worker malicious-worker-1 /out/malicious-worker-1

# Fail closed if any private CA/JWT signing material escaped the ephemeral directory.
for dst in /out/coordinator /out/benign-worker-1 /out/benign-worker-2 /out/benign-worker-3 /out/malicious-worker-1; do
  test ! -e "$dst/ca.key"
  test ! -e "$dst/jwt_signing_private.pem"
done

echo "isolated development PKI generated successfully"
