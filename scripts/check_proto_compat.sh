#!/usr/bin/env bash
set -euo pipefail

baseline_ref="${1:-main}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cd "$repo_root"

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required for protobuf compatibility checks" >&2
  exit 2
fi

if ! git cat-file -e "${baseline_ref}:proto/fl_service.proto" 2>/dev/null; then
  echo "baseline ref ${baseline_ref} does not contain proto/fl_service.proto" >&2
  exit 2
fi

git show "${baseline_ref}:proto/fl_service.proto" > "$tmp_dir/fl_service.proto"

(
  cd "$tmp_dir"
  protoc --proto_path=. --descriptor_set_out=baseline.pb fl_service.proto
)
(
  cd "$repo_root/proto"
  protoc --proto_path=. --descriptor_set_out="$tmp_dir/current.pb" fl_service.proto
)

go run ./cmd/protocompat \
  --baseline "$tmp_dir/baseline.pb" \
  --current "$tmp_dir/current.pb"
