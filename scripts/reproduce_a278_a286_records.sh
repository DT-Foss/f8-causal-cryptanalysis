#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
  else
    echo "missing Python interpreter" >&2
    exit 2
  fi
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON" scripts/verify_hash_manifest.py \
  research/results/v1/A278_A286_RECORDS_SHA256SUMS

TEST_LIST="research/results/v1/A278_A286_RECORDS_TESTS.txt"
TESTS="$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$TEST_LIST")"
if [[ -z "$TESTS" ]]; then
  echo "empty focused test list: $TEST_LIST" >&2
  exit 2
fi

# Every listed test path is repository-relative and contains no whitespace.
# shellcheck disable=SC2086
"$PYTHON" -m pytest -q $TESTS

AUDIT="$(mktemp)"
trap 'rm -f "$AUDIT"' EXIT
"$PYTHON" scripts/validate_causal_artifacts.py research/results/v1 > "$AUDIT"
"$PYTHON" - "$AUDIT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    audit = json.load(handle)

by_name = {row["path"].rsplit("/", 1)[-1]: row for row in audit["artifacts"]}
root = by_name["chacha20_round20_multitarget_panel_root_confirmation_a286_v1.causal"]
if root["api_id"] != "a286pan" or root["triplets"] != 5 or root["gaps"] != 1:
    raise SystemExit("A286 authentic Causal readback differs")
for required in (
    "chacha20_round20_cross_material_composite_recovery_canonical_v1.causal",
    "present128_metal_width38_recovery_v1.causal",
    "aes256_fips197_metal_width41_recovery_v1.causal",
):
    if required not in by_name:
        raise SystemExit(f"missing Causal artifact: {required}")
print(f"causal artifacts: OK ({audit['validated']} validated)")
PY

echo "A278--A286 and complete-domain record tier: OK"
