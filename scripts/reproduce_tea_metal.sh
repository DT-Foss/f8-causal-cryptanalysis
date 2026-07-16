#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
RUNNER="$ROOT/research/experiments/tea_metal_record.py"

usage() {
    echo "usage: $0 --qualify | --freeze QUALIFICATION_SHA256 | --analyze PROTOCOL_SHA256 | --run PROTOCOL_SHA256" >&2
    exit 2
}

test "$#" -ge 1 || usage
mode=$1
shift

case "$mode" in
    --qualify)
        test "$#" -eq 0 || usage
        exec "$PYTHON" "$RUNNER" --qualify
        ;;
    --freeze)
        test "$#" -eq 1 || usage
        exec "$PYTHON" "$RUNNER" --freeze --expected-qualification-sha256 "$1"
        ;;
    --analyze)
        test "$#" -eq 1 || usage
        exec "$PYTHON" "$RUNNER" --analyze --expected-protocol-sha256 "$1"
        ;;
    --run)
        test "$#" -eq 1 || usage
        exec "$PYTHON" "$RUNNER" --run --resume --expected-protocol-sha256 "$1"
        ;;
    *)
        usage
        ;;
esac
