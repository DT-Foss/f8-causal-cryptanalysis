#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
PROTOCOL="$ROOT/research/configs/chacha20_round20_signed_channel_ablation_v1.json"

if [[ "${1:-}" == "--freeze" ]]; then
  exec "$PYTHON" "$ROOT/research/experiments/chacha20_round20_signed_channel_ablation_preflight.py" --freeze
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 --freeze | EXPECTED_PROTOCOL_SHA256" >&2
  exit 2
fi

exec "$PYTHON" \
  "$ROOT/research/experiments/chacha20_round20_signed_channel_ablation.py" \
  --protocol "$PROTOCOL" \
  --expected-protocol-sha256 "$1"
