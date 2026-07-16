#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
exec "$PYTHON" research/experiments/chacha20_round20_w46_coarse_carry_forward_a339.py "$@"
