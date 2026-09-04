#!/bin/sh
set -eu

exec docker run --rm \
  --network host \
  -v /tmp:/tmp \
  -e PGPASSWORD="${PGPASSWORD:-}" \
  postgres:18.6-alpine \
  pg_dump "$@"
