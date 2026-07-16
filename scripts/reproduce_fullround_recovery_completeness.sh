#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3)"
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON" scripts/verify_hash_manifest.py \
  research/results/v1/FULLROUND_RECOVERY_COMPLETENESS_SHA256SUMS

tests=()
while IFS= read -r path; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  tests+=("$path")
done < research/results/v1/FULLROUND_RECOVERY_COMPLETENESS_TESTS.txt
"$PYTHON" -m pytest -q "${tests[@]}"

audit="$(mktemp)"
trap 'rm -f "$audit"' EXIT
"$PYTHON" scripts/validate_causal_artifacts.py research/results/v1 > "$audit"
"$PYTHON" - "$audit" <<'PY'
import json
import sys

required = {
    "blake3_keyed_metal_recovery_v1.causal",
    "blake3_keyed_official_b3sum_root_confirmation_v1.causal",
    "siphash24_metal_recovery_v1.causal",
    "tea_metal_recovery_v1.causal",
    "xtea_metal_recovery_v1.causal",
    "threefish1024_metal_record_v1.causal",
    "chacha20_round20_holdout_selected_w45_recovery_a322_v1.causal",
    "chacha20_round20_holdout_selected_w46_recovery_a325_v1.causal",
    "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.causal",
    "chacha20_round20_w48_target_conditioned_recovery_a374_v1.causal",
}
with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
by_name = {row["path"].rsplit("/", 1)[-1]: row for row in payload["artifacts"]}
missing = sorted(required - by_name.keys())
if missing:
    raise SystemExit(f"missing recovery Causal artifacts: {missing}")
empty = sorted(name for name in required if by_name[name]["triplets"] < 1)
if empty:
    raise SystemExit(f"empty recovery Causal graphs: {empty}")
print(f"recovery Causal artifacts: OK ({len(required)} opened)")
PY

echo "full-round recovery completeness tier: OK"
