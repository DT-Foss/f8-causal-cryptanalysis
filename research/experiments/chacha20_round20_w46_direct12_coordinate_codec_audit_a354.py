#!/usr/bin/env python3
"""A354: bind A348/A349 cell coordinates to the actual Metal W46 group codec."""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.md"

A223_RUNNER = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A296_RUNNER = RESEARCH / "experiments/chacha20_round20_causal_search_gain_panel_a296.py"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A340_PREFLIGHT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_preflight_v1.json"
A344_RESULT = RESULTS / "chacha20_round20_w46_a343_corrected_evaluation_a344_v1.json"
A348_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_sliced_reader_a348.py"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A349_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_prospective_a345_validation_a349.py"
A349_ORDER = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
A351_ORDER = RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_order_v1.json"

ATTEMPT_ID = "A354"
DESIGN_SHA256 = "5c25cb81f03ee613ce70bc5bd1fb2c18cc11efadc545a0ad9d07ef34be3d2dde"
CELLS = 4096
METAL_LOW4_COORDINATES = (23, 22, 21, 20)
METAL_HIGH8_COORDINATES = (31, 30, 29, 28, 27, 26, 25, 24)
A348_LOW4_COORDINATES = (37, 36, 35, 34)
A348_HIGH8_COORDINATES = (45, 44, 43, 42, 41, 40, 39, 38)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_bytes(value))


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def anchor(path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    digest = file_sha256(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError(f"A354 anchor differs: {relative(path)}")
    return {"path": relative(path), "sha256": digest, "bytes": path.stat().st_size}


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A354 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-coordinate-codec-audit-a354-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_coordinate_discovery_before_corrected_successor_measurement"
        or value.get("next_gate", {}).get("correct_low4_fixed_unit_coordinates")
        != list(METAL_LOW4_COORDINATES)
        or value.get("next_gate", {}).get("correct_high8_assumption_coordinates")
        != list(METAL_HIGH8_COORDINATES)
    ):
        raise RuntimeError("A354 design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    return value


def _literal_coordinates_from_function(path: Path, function_name: str) -> tuple[int, ...]:
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != function_name:
            continue
        for descendant in ast.walk(node):
            if (
                isinstance(descendant, ast.Call)
                and isinstance(descendant.func, ast.Name)
                and descendant.func.id == "enumerate"
                and descendant.args
                and isinstance(descendant.args[0], ast.Tuple)
            ):
                values = tuple(
                    int(item.value)
                    for item in descendant.args[0].elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, int)
                )
                if len(values) == 4:
                    return values
    raise RuntimeError(f"A354 cannot derive {function_name} coordinates")


def metal_group_cell(assignment: int) -> int:
    if not 0 <= assignment < (1 << 46):
        raise ValueError("A354 assignment is outside W46")
    return ((assignment & 0xFFFFFFFF) >> 20) & 0xFFF


def a348_measured_cell(assignment: int) -> int:
    if not 0 <= assignment < (1 << 46):
        raise ValueError("A354 assignment is outside W46")
    return (assignment >> 34) & 0xFFF


def rank_metrics(order: Sequence[int], cell: int) -> dict[str, Any]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise RuntimeError("A354 order is not a complete 4096-cell permutation")
    rank = values.index(cell) + 1
    return {
        "cell": cell,
        "cell_hex": f"{cell:03x}",
        "rank_one_based": rank,
        "gain_bits_vs_uniform_complete_4096_cover": math.log2(CELLS / rank),
        "domain_reduction_factor_at_rank": CELLS / rank,
    }


def corrected_synthetic_mapping(source_mapping: Sequence[int]) -> list[int]:
    source = [int(value) for value in source_mapping]
    if len(source) != 46 or len({abs(value) for value in source}) != 46:
        raise ValueError("A354 source mapping differs")
    result = [*source[:12], *source[24:32]]
    if len(result) != 20 or len({abs(value) for value in result}) != 20:
        raise RuntimeError("A354 corrected synthetic mapping aliases")
    return result


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A354:corrected_word0_bits20_through31_reader_contract"
    writer = CausalWriter(api_id="a354map")
    writer._rules = []
    writer.add_rule(
        name="source_coordinate_to_direct12_cell",
        description="The fixed low4 and assumed high8 source coordinates define the exact assignment-bit interval represented by one direct12 cell.",
        pattern=["A348_low4_source_coordinates", "A348_high8_source_coordinates"],
        conclusion="A354_A348_measured_bits34_through45",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="metal_codec_to_required_reader_coordinates",
        description="The A324/A325 Metal dispatch codec consumes word0 bits20 through31, fixing the corrected low4 and high8 coordinate sets.",
        pattern=["A324_Metal_group_codec", "A354_A348_measured_bits34_through45"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A348:complete_direct12_measurement",
        mechanism="fixed_coordinates_37_to34_plus_assumed_coordinates_45_to38",
        outcome="A354:A348_cells_equal_assignment_bits34_through45",
        confidence=1.0,
        source=payload["anchors"]["A348_result"]["sha256"],
        quantification=json.dumps(payload["coordinate_derivation"], sort_keys=True),
        evidence="source-level literal map and decoded candidate",
        domain="ChaCha20 W46 representation audit",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:confirmed_assignment",
        mechanism="compare_assignment_bits34_to45_with_word0_bits20_to31",
        outcome="A354:distinct_measured_and_Metal_group_cells",
        confidence=1.0,
        source=payload["anchors"]["A325_result"]["sha256"],
        quantification=json.dumps(payload["candidate_codec_witness"], sort_keys=True),
        evidence="0x77c differs from 0xbae on the independently confirmed assignment",
        domain="ChaCha20 W46 codec witness",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A354:distinct_measured_and_Metal_group_cells",
        mechanism="replace_width_last8_with_coordinates24_through31_and_low4_with20_through23",
        outcome=terminal,
        confidence=1.0,
        source=payload["result_sha256"],
        quantification=json.dumps(payload["corrected_successor_contract"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="corrected direct12 reader construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A348:complete_direct12_measurement",
        mechanism="materialized_coordinate_audit_and_codec_correction",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A354_coordinate_codec_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A354 direct12 coordinate correction",
        entities=[
            "A348:complete_direct12_measurement",
            "A354:A348_cells_equal_assignment_bits34_through45",
            "A354:distinct_measured_and_Metal_group_cells",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="complete_corrected_W46_direct12_measurement",
        confidence=1.0,
        suggested_queries=["Measure all word0 bits20-through31 cells and score 0xbae only after closure."],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a354map"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A354 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "first_explicit_relation": explicit[0],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def audit() -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A354 audit artifacts already exist")
    design = load_design()
    a325 = json.loads(A325_RESULT.read_bytes())
    a344 = json.loads(A344_RESULT.read_bytes())
    a348 = json.loads(A348_RESULT.read_bytes())
    a349 = json.loads(A349_ORDER.read_bytes())
    a351 = json.loads(A351_ORDER.read_bytes())
    preflight = json.loads(A340_PREFLIGHT.read_bytes())

    candidate = int(a325["discovery"]["candidate"])
    metal_cell = metal_group_cell(candidate)
    measured_cell = a348_measured_cell(candidate)
    if (
        metal_cell != int(a325["discovery"]["prefix12"])
        or metal_cell != int(a344["confirmed_prefix"]["prefix12"])
        or measured_cell == metal_cell
        or _literal_coordinates_from_function(A348_RUNNER, "low4_unit_literals")
        != A348_LOW4_COORDINATES
    ):
        raise RuntimeError("A354 codec witness gate failed")

    source_mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    legacy_synthetic = [int(value) for value in preflight["synthetic_reader_mapping"]]
    expected_legacy = [*source_mapping[:12], *source_mapping[38:46]]
    corrected_synthetic = corrected_synthetic_mapping(source_mapping)
    if legacy_synthetic != expected_legacy or corrected_synthetic == legacy_synthetic:
        raise RuntimeError("A354 synthetic Reader mapping gate failed")
    a349_source = A349_RUNNER.read_text()
    if "A348.render_slice_cnf" not in a349_source or "A348.low4_unit_literals" not in a349_source:
        raise RuntimeError("A354 A349 coordinate inheritance gate failed")

    corrected_rank_panel: dict[str, Any] = {}
    for name, order in a348["orders"].items():
        declared = rank_metrics(order, metal_cell)
        if declared["rank_one_based"] != int(a348["rank_panel"][name]["rank_one_based"]):
            raise RuntimeError(f"A354 cannot reproduce A348 declared rank: {name}")
        corrected_rank_panel[name] = {
            "rank_at_declared_but_unmeasured_Metal_cell": declared,
            "rank_at_actual_A348_measured_cell": rank_metrics(order, measured_cell),
        }

    proof = a351["pointwise_factor2_proof"]
    if proof.get("violations") != 0 or proof.get("cells_checked") != CELLS:
        raise RuntimeError("A354 A351 exact permutation proof gate failed")

    anchors = {
        "design": anchor(DESIGN, DESIGN_SHA256),
        "A223_runner": anchor(A223_RUNNER, design["source_anchors"]["A223_runner_sha256"]),
        "A296_runner": anchor(A296_RUNNER, design["source_anchors"]["A296_runner_sha256"]),
        "A325_result": anchor(A325_RESULT, design["source_anchors"]["A325_result_sha256"]),
        "A340_preflight": anchor(
            A340_PREFLIGHT, design["source_anchors"]["A340_preflight_sha256"]
        ),
        "A344_result": anchor(A344_RESULT, design["source_anchors"]["A344_result_sha256"]),
        "A348_runner": anchor(A348_RUNNER, design["source_anchors"]["A348_runner_sha256"]),
        "A348_result": anchor(A348_RESULT, design["source_anchors"]["A348_result_sha256"]),
        "A349_runner": anchor(A349_RUNNER, design["source_anchors"]["A349_runner_sha256"]),
        "A349_order": anchor(A349_ORDER, design["source_anchors"]["A349_order_sha256"]),
        "A351_order": anchor(A351_ORDER, design["source_anchors"]["A351_order_sha256"]),
        "runner": anchor(Path(__file__)),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-coordinate-codec-audit-a354-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SOURCE_LEVEL_COORDINATE_CODEC_CORRECTION_RETAINED_BEFORE_SUCCESSOR_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "coordinate_derivation": {
            "A348_low4_fixed_unit_coordinates_high_to_low": list(A348_LOW4_COORDINATES),
            "A348_high8_assumption_coordinates_high_to_low": list(A348_HIGH8_COORDINATES),
            "A348_cell_assignment_interval_low_to_high": [34, 45],
            "Metal_low4_fixed_unit_coordinates_high_to_low": list(METAL_LOW4_COORDINATES),
            "Metal_high8_assumption_coordinates_high_to_low": list(METAL_HIGH8_COORDINATES),
            "Metal_group_assignment_interval_low_to_high": [20, 31],
            "coordinate_mapping_definition": "A223 _decode_mapping returns assignment coordinate i at source_mapping[i]",
        },
        "candidate_codec_witness": {
            "A325_confirmed_assignment": candidate,
            "A325_confirmed_assignment_hex": f"{candidate:012x}",
            "A348_actual_measured_cell_bits34_through45": measured_cell,
            "A348_actual_measured_cell_hex": f"{measured_cell:03x}",
            "Metal_group_cell_word0_bits20_through31": metal_cell,
            "Metal_group_cell_hex": f"{metal_cell:03x}",
            "cells_are_distinct": measured_cell != metal_cell,
        },
        "corrected_A348_rank_panel": corrected_rank_panel,
        "A349_scope_after_correction": {
            "selected_view": a349["selected_view"],
            "selected_order_uint16be_sha256": a349["selected_order_uint16be_sha256"],
            "complete_target_label_free_permutation": True,
            "same_coordinate_Metal_prefix_map": False,
            "valid_as_public_output_derived_permutation_execution": True,
            "reader_refits": a349["reader_refits"],
            "target_labels_used": a349["target_labels_used"],
        },
        "A351_scope_after_correction": {
            "pointwise_factor2_proof": proof,
            "permutation_theorem_preserved": True,
            "same_coordinate_two_reader_interpretation": False,
        },
        "corrected_successor_contract": {
            "low4_fixed_unit_coordinates_high_to_low": list(METAL_LOW4_COORDINATES),
            "high8_assumption_coordinates_high_to_low": list(METAL_HIGH8_COORDINATES),
            "synthetic_reader_mapping_source_indices": [*range(12), *range(24, 32)],
            "synthetic_reader_mapping_sha256": canonical_sha256(corrected_synthetic),
            "complete_cells_required": CELLS,
            "target_labels_during_measurement": 0,
        },
        "frozen_artifact_policy": design["correction_scope"],
        "candidate_assignments_executed": 0,
        "anchors": anchors,
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "coordinate_derivation": payload["coordinate_derivation"],
            "candidate_codec_witness": payload["candidate_codec_witness"],
            "corrected_A348_rank_panel": corrected_rank_panel,
            "A349_scope_after_correction": payload["A349_scope_after_correction"],
            "A351_scope_after_correction": payload["A351_scope_after_correction"],
            "corrected_successor_contract": payload["corrected_successor_contract"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    best = min(
        corrected_rank_panel.items(),
        key=lambda item: (item[1]["rank_at_actual_A348_measured_cell"]["rank_one_based"], item[0]),
    )
    atomic_bytes(
        REPORT,
        (
            "# A354 — direct12 coordinate-codec correction\n\n"
            f"- Confirmed A325 assignment: **0x{candidate:012x}**\n"
            f"- A348 actually measured assignment bits 34–45: **0x{measured_cell:03x}**\n"
            f"- Metal dispatches word0 bits 20–31: **0x{metal_cell:03x}**\n"
            f"- Best A348 view at its actual measured cell: **{best[0]}**, rank "
            f"**{best[1]['rank_at_actual_A348_measured_cell']['rank_one_based']} / {CELLS}**\n"
            "- A345/A325 recoveries: **unaffected**\n"
            "- A349/A350: **retained as a label-free public-output-derived permutation**, not a same-coordinate prefix map\n"
            "- A351: **exact factor-2 permutation theorem retained**\n"
            "- Correct successor coordinates: **low4 23..20; high8 31..24**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def verify() -> dict[str, Any]:
    load_design()
    payload = json.loads(RESULT.read_bytes())
    if payload.get("schema") != "chacha20-round20-w46-direct12-coordinate-codec-audit-a354-v1":
        raise RuntimeError("A354 result schema differs")
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    return {
        "attempt_id": ATTEMPT_ID,
        "result": anchor(RESULT),
        "causal": anchor(CAUSAL),
        "result_sha256": payload["result_sha256"],
        "explicit_triplets": len(reader.get_all_triplets(include_inferred=False)),
        "all_triplets": len(reader.get_all_triplets(include_inferred=True)),
        "next_gap": reader._gaps[0],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--audit", action="store_true")
    action.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    payload = audit() if args.audit else verify()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
