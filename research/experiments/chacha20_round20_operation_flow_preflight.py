#!/usr/bin/env python3
"""Build the target-blind public preflight for the A261 flow reader.

This stage replays A260's frozen operation-tap preparation, captures the exact
signed DIMACS mapping produced by A260's own decoder, and computes only public
operation-flow geometry.  It never opens an A251 measurement shard or a known
prefix label.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.chacha20_operation_flow import (  # noqa: E402
    flow_graph_manifest,
    nearest_manifest,
    nearest_operation_taps,
    operation_flow_graph,
)

A260_RUNNER = (
    ROOT / "research/experiments/chacha20_round20_fresh_clause_operation_reader.py"
)
A260_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_fresh_clause_operation_reader_v1.json"
)
FLOW_MODULE = ROOT / "src/arx_carry_leak/chacha20_operation_flow.py"
OUTPUT = (
    ROOT
    / "research/provenance/chacha20_round20_a261_operation_flow_preflight_v1.json"
)
SCHEMA = "chacha20-round20-operation-flow-preflight-v1"
ATTEMPT_ID = "A261"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import preflight dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _prepare_with_exact_mapping(
    a260: Any,
    protocol: dict[str, Any],
    a259: Any,
    a242: Any,
    directory: Path,
) -> tuple[Any, tuple[tuple[int, ...], ...], dict[str, Any], dict[str, Any]]:
    """Replay A260 and retain the output of its already-frozen decoder."""

    captured: dict[str, tuple[tuple[int, ...], ...]] = {}
    original_decoder = a260.decode_vectorized_mapping

    def capture(exports: Any) -> tuple[tuple[int, ...], ...]:
        mapping = tuple(tuple(int(value) for value in row) for row in original_decoder(exports))
        captured["mapping"] = mapping
        return mapping

    a260.decode_vectorized_mapping = capture
    try:
        topology, topology_manifest, mapping_manifest = (
            a260._prepare_operation_topology(
                protocol,
                a259,
                a242,
                directory,
            )
        )
    finally:
        a260.decode_vectorized_mapping = original_decoder
    mapping = captured.get("mapping")
    if mapping is None:
        raise RuntimeError("A261 exact operation mapping was not captured")
    expected = protocol["operation_tap_preflight"]
    mapping_sha256 = _sha256(np.asarray(mapping, dtype="<i4").tobytes())
    if (
        mapping_sha256 != expected["signed_one_literal_matrix_sha256"]
        or mapping_sha256 != mapping_manifest["signed_one_literal_matrix_sha256"]
    ):
        raise RuntimeError("A261 captured operation mapping identity differs")
    return topology, mapping, topology_manifest, mapping_manifest


def build_preflight() -> dict[str, Any]:
    a260 = _import_path(A260_RUNNER, "a261_preflight_a260")
    protocol, a259, _a251, a242 = a260._load_protocol()
    result = json.loads(A260_RESULT.read_bytes())
    if (
        result.get("attempt_id") != "A260"
        or result.get("evidence_stage")
        != "FULLROUND_R20_EXACT_OPERATION_CLAUSE_TOPOLOGY_BOUNDARY"
        or result.get("retention_gate", {}).get("passed") is not False
    ):
        raise RuntimeError("A261 requires the completed A260 boundary")
    with tempfile.TemporaryDirectory(prefix="a261_operation_flow_preflight_") as temporary:
        topology, mapping, topology_manifest, mapping_manifest = (
            _prepare_with_exact_mapping(
                a260,
                protocol,
                a259,
                a242,
                Path(temporary),
            )
        )
        graph = operation_flow_graph()
        nearest = nearest_operation_taps(topology, mapping)
        nearest_geometry = nearest_manifest(
            nearest,
            original_variable_count=int(
                protocol["operation_tap_preflight"]["original_variable_count"]
            ),
        )
        graph_geometry = flow_graph_manifest(graph)
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "target_blind_public_preflight_complete_before_any_A251_clause_flow_projection_or_model_fit",
        "source": {
            "A260_protocol_sha256": a260.PROTOCOL_SHA256,
            "A260_runner_sha256": _file_sha256(A260_RUNNER),
            "A260_result_sha256": _file_sha256(A260_RESULT),
            "flow_module_sha256": _file_sha256(FLOW_MODULE),
        },
        "operation_flow_graph": graph_geometry,
        "nearest_operation_taps": nearest_geometry,
        "operation_mapping_manifest": mapping_manifest,
        "operation_topology_manifest": topology_manifest,
        "information_boundary": {
            "A251_measurement_shard_opened": False,
            "A251_learned_clause_projected": False,
            "known_prefix_label_opened_or_used": False,
            "target_output_bit_value_used": False,
            "candidate_identity_feature_used": False,
            "operation_flow_model_fit": False,
            "public_formula_and_target_blind_operation_mapping_only": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "output": str(OUTPUT),
                    "information_boundary": "public_formula_only",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = build_preflight()
    _atomic_json(OUTPUT, payload)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "sha256": _file_sha256(OUTPUT),
                "flow_graph": payload["operation_flow_graph"],
                "nearest_operation_taps": payload["nearest_operation_taps"],
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
