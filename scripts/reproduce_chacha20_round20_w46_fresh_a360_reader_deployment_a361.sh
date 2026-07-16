#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_fresh_a360_reader_deployment_a361_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
PREFLIGHT="research/results/v1/chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
MEASUREMENT="research/results/v1/chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
ORDER="research/results/v1/chacha20_round20_w46_fresh_a360_reader_deployment_a361_order_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_fresh_a360_reader_deployment_a361_v1.json"
A360_RESULT="research/results/v1/chacha20_round20_w46_within_slice_reader_selection_a360_v1.json"
QUALIFICATION_SHA256="996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_fresh_a360_reader_deployment_a361.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi
IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ ! -f "$PROTOCOL" ]]; then
  .venv/bin/python "$RUNNER" \
    --materialize-target \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-a324-qualification-sha256 "$QUALIFICATION_SHA256"
fi
PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"

if [[ ! -f "$PREFLIGHT" ]]; then
  .venv/bin/python "$RUNNER" \
    --preflight \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-protocol-sha256 "$PROTOCOL_SHA256"
fi
PREFLIGHT_SHA256="$(shasum -a 256 "$PREFLIGHT" | awk '{print $1}')"

if [[ ! -f "$MEASUREMENT" ]]; then
  .venv/bin/python "$RUNNER" \
    --measure \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --expected-preflight-sha256 "$PREFLIGHT_SHA256"
fi
MEASUREMENT_SHA256="$(shasum -a 256 "$MEASUREMENT" | awk '{print $1}')"

if [[ ! -f "$A360_RESULT" ]]; then
  .venv/bin/python "$RUNNER" --analyze
  exit 0
fi
if [[ "$(jq -r '.retention_gate.passed' "$A360_RESULT")" != "true" ]]; then
  .venv/bin/python "$RUNNER" --analyze
  exit 0
fi
A360_RESULT_SHA256="$(shasum -a 256 "$A360_RESULT" | awk '{print $1}')"

if [[ ! -f "$ORDER" ]]; then
  .venv/bin/python "$RUNNER" \
    --freeze-order \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --expected-measurement-sha256 "$MEASUREMENT_SHA256" \
    --expected-a360-result-sha256 "$A360_RESULT_SHA256"
fi
ORDER_SHA256="$(shasum -a 256 "$ORDER" | awk '{print $1}')"

if [[ -f "$RESULT" ]]; then
  .venv/bin/python "$RUNNER" --analyze
else
  .venv/bin/python "$RUNNER" \
    --recover \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --expected-order-sha256 "$ORDER_SHA256" \
    --expected-a324-qualification-sha256 "$QUALIFICATION_SHA256"
fi
