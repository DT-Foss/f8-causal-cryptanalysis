#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-quick}"

if [[ "$PROFILE" != "quick" && "$PROFILE" != "full" ]]; then
  echo "usage: $0 [quick|full]" >&2
  exit 2
fi

cd "$ROOT"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m pytest
python -m arx_carry_leak verify-vectors
python -m arx_carry_leak run --profile "$PROFILE" \
  --output "results/generated/${PROFILE}.json"
python -m build
