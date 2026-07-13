#!/usr/bin/env python3
"""Apply the dual RFC 8439 confirmation gate to an existing A219 result."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
A219_SOURCE = ROOT / "research/experiments/chacha20_round20_ranked_target_recovery.py"
DEFAULT_SOURCE = ROOT / "research/results/v1/chacha20_round20_ranked_target_recovery_v1.json"
DEFAULT_OUTPUT = (
    ROOT / "research/results/v1/chacha20_round20_ranked_target_cross_confirmation_v1.json"
)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A219 = _import_path(A219_SOURCE, "a219_cross_confirmation_runner")


def _resolve_anchor(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else ROOT / candidate


def run(*, source: Path, output: Path, protocol_path: Path = A219.PROTOCOL) -> dict[str, Any]:
    result = json.loads(source.read_bytes())
    if (
        result.get("schema") != "chacha20-round20-ranked-target-recovery-result-v1"
        or result.get("attempt_id") != "A219"
        or result.get("target_secret_or_salt_read") is not False
    ):
        raise RuntimeError("source is not a target-blind A219 result")
    protocol_sha256 = A219._file_sha256(protocol_path)
    if result.get("protocol_sha256") != protocol_sha256:
        raise RuntimeError("A219 result and protocol hash differ")

    base = {
        "schema": "chacha20-round20-ranked-target-cross-confirmation-v1",
        "attempt_id": "A219-CROSS-GATE",
        "source_result_path": str(source),
        "source_result_sha256": A219._file_sha256(source),
        "source_measurement_sha256": result.get("measurement_sha256"),
        "protocol_sha256": protocol_sha256,
        "target_secret_or_salt_read": False,
    }
    if result["execution"]["sat_found"] is not True:
        payload = {
            **base,
            "status": "NOT_APPLICABLE_NO_SAT_MODEL",
            "confirmation": None,
        }
        A219._atomic_json(output, payload)
        return payload

    sat_row = result["execution"].get("sat_row")
    if not isinstance(sat_row, dict):
        raise RuntimeError("A219 SAT result has no SAT row")
    low20 = A219._decode_model(sat_row["model_bits_bit0_through_bit19"])
    if sat_row.get("prefix8") != f"{low20 >> 12:08b}":
        raise RuntimeError("A219 SAT row prefix differs from its model")

    protocol = json.loads(protocol_path.read_bytes())
    anchors = protocol["anchors"]
    public_path = _resolve_anchor(anchors["public_target_path"])
    r20_path = _resolve_anchor(anchors["R20_runner_path"])
    expected_hashes = result["anchor_hashes"]
    if (
        A219._file_sha256(public_path) != expected_hashes["public_target"]
        or A219._file_sha256(r20_path) != expected_hashes["r20"]
    ):
        raise RuntimeError("A219 public confirmation anchors drifted")

    public = json.loads(public_path.read_bytes())
    r20 = _import_path(r20_path, "a219_cross_confirmation_r20")
    confirmation = A219._confirm(r20, public["public_challenge"], low20)
    if (
        confirmation["all_blocks_match"] is not True
        or confirmation["all_cross_implementation_blocks_match"] is not True
        or confirmation["claim_gate_rfc8439_section_2_3_2_kat"] is not True
        or confirmation["control_first_block_match"] is not False
        or confirmation["output_bits_checked"] != 4096
    ):
        raise RuntimeError("A219 recovered model failed the standalone cross gate")

    payload = {
        **base,
        "status": "DUAL_INDEPENDENT_EIGHT_BLOCK_CONFIRMATION_PASSED",
        "confirmation": confirmation,
    }
    payload["measurement_sha256"] = A219._canonical_sha256(
        {
            "source_result_sha256": payload["source_result_sha256"],
            "source_measurement_sha256": payload["source_measurement_sha256"],
            "protocol_sha256": payload["protocol_sha256"],
            "target_secret_or_salt_read": False,
            "status": payload["status"],
            "confirmation": confirmation,
        }
    )
    A219._atomic_json(output, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    payload = run(source=arguments.source, output=arguments.output)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": A219._file_sha256(arguments.output),
                "status": payload["status"],
                "target_secret_or_salt_read": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
