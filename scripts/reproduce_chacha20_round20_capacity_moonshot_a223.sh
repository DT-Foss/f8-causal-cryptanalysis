#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RUNNER="research/experiments/chacha20_round20_capacity_moonshot_a223.py"
TEST="tests/test_chacha20_round20_capacity_moonshot_a223.py"
PREFLIGHT="research/results/v1/chacha20_round20_capacity_moonshot_a223_preflight_v1.json"

python3 "$RUNNER" --analyze-only
python3 -m pytest -q "$TEST"

case "${1:-}" in
  "")
    ;;
  --preflight)
    python3 "$RUNNER" --preflight-only --preflight-output "$PREFLIGHT"
    shasum -a 256 "$PREFLIGHT"
    ;;
  --run)
    if [ "$#" -ne 2 ]; then
      echo "usage: $0 --run REVIEWED_PREFLIGHT_SHA256" >&2
      exit 2
    fi
    python3 "$RUNNER" \
      --run \
      --preflight "$PREFLIGHT" \
      --expected-preflight-sha256 "$2"
    ;;
  *)
    echo "usage: $0 [--preflight | --run REVIEWED_PREFLIGHT_SHA256]" >&2
    exit 2
    ;;
esac
