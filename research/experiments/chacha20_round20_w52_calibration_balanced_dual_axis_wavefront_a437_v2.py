#!/usr/bin/env python3
"""A437 V2: immutable packaging repair for the frozen anisotropic schedule."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

V1_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437.py"
)
V1_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_implementation_v1.json"
)
V1_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v1.json"
)
V1_RESULT = (
    RESULTS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v1.json"
)
V1_CAUSAL = V1_RESULT.with_suffix(".causal")
V1_REPORT = V1_RESULT.with_suffix(".md")

IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_implementation_v2.json"
)
PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.json"
)
RESULT = (
    RESULTS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = (
    ROOT
    / "tests/test_chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.py"
)
REPRO = (
    ROOT
    / "scripts/reproduce_chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.sh"
)

ATTEMPT_ID = "A437"
V1_RUNNER_SHA256 = "57a2889bb3dcdd2592e19b20fbb626fac706982ddf6bcc99e6a58fb8e83bdad7"
V1_IMPLEMENTATION_SHA256 = "d92adf76cee3360d35a15dba243590ccc32dbcdbb8b7e11e25bea4d19f0e143c"
V1_PROTOCOL_SHA256 = "30652dc6a24838568b22ebe01bca367264c9b65f2cf20d3b3281994936b89685"
V1_SCHEDULE_COMMITMENT_SHA256 = (
    "79b3e2c0fe0a7aecc4f18e505ab6454cba96923033df319df7ca3ff8ed5ff401"
)
V1_PAIR_STREAM_SHA256 = "6fec353dd64c98d3956c5308995e4cea1ee50cbd5a96436c67bbd426091d12aa"


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A437 V2 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A437 = load_module(V1_RUNNER, "a437_v2_v1")
file_sha256 = A437.file_sha256
canonical_sha256 = A437.canonical_sha256
atomic_json = A437.atomic_json
anchor = A437.anchor
path_from_ref = A437.path_from_ref
relative = A437.relative


def assert_v1_immutable_and_unassembled() -> None:
    anchor(V1_RUNNER, V1_RUNNER_SHA256)
    anchor(V1_IMPLEMENTATION, V1_IMPLEMENTATION_SHA256)
    anchor(V1_PROTOCOL, V1_PROTOCOL_SHA256)
    if any(path.exists() for path in (V1_RESULT, V1_CAUSAL, V1_REPORT)):
        raise RuntimeError("A437 V1 failed assembly must remain absent and immutable")


def load_v1_protocol() -> dict[str, Any]:
    assert_v1_immutable_and_unassembled()
    value = A437.load_protocol(V1_PROTOCOL_SHA256)
    if (
        value.get("schedule_commitment_sha256") != V1_SCHEDULE_COMMITMENT_SHA256
        or value.get("schedule", {}).get("pair_stream_uint16be_uint16be_sha256")
        != V1_PAIR_STREAM_SHA256
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A437 V1 frozen schedule semantics differ")
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 V2 implementation, protocol or result already exists")
    A437.assert_no_a426_outcome()
    v1 = load_v1_protocol()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A437 V2 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-implementation-v2",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "packaging_only_repair_frozen_after_V1_KeyError_before_A426_outcome_or_any_candidate",
        "repair_scope": {
            "defect": "V1 Causal builder requested payload.schedule although the assembled result exposes the frozen stream hash at payload.pair_stream_uint16be_uint16be_sha256",
            "schedule_recomputed": False,
            "schedule_changed": False,
            "axis_orders_changed": False,
            "calibration_changed": False,
            "candidate_assignments_executed": 0,
        },
        "V1_schedule_commitment_sha256": v1["schedule_commitment_sha256"],
        "V1_pair_stream_sha256": v1["schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "A426_outcome_available_at_V2_freeze": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(A437.DESIGN, A437.DESIGN_SHA256),
            "V1_runner": anchor(V1_RUNNER, V1_RUNNER_SHA256),
            "V1_implementation": anchor(V1_IMPLEMENTATION, V1_IMPLEMENTATION_SHA256),
            "V1_protocol": anchor(V1_PROTOCOL, V1_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    A437.assert_no_a426_outcome()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A437 V2 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    repair = value.get("repair_scope", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-implementation-v2"
        or repair.get("schedule_recomputed") is not False
        or repair.get("schedule_changed") is not False
        or repair.get("candidate_assignments_executed") != 0
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A437 V2 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A437 V2 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 V2 protocol or result already exists")
    A437.assert_no_a426_outcome()
    implementation = load_implementation(expected_implementation_sha256)
    v1 = load_v1_protocol()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-protocol-v2",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "packaging_repair_bound_to_unchanged_V1_schedule_before_A426_outcome_or_any_candidate",
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "V1_protocol_sha256": V1_PROTOCOL_SHA256,
        "schedule_commitment_sha256": v1["schedule_commitment_sha256"],
        "pair_stream_uint16be_uint16be_sha256": v1["schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "schedule_summary": {
            "algorithm": v1["schedule"]["algorithm"],
            "growth_events": v1["schedule"]["growth_events"],
            "cells": v1["schedule"]["cells"],
            "assignments_per_cell": v1["schedule"]["assignments_per_cell"],
            "complete_domain_assignments": v1["schedule"][
                "complete_domain_assignments"
            ],
            "workers": v1["schedule"]["workers"],
            "worker_tasks_each": v1["schedule"]["worker_tasks_each"],
        },
        "calibration_comparison": v1["calibration_comparison"],
        "repair_scope": implementation["repair_scope"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "production_execution_enabled": False,
        "anchors": {
            "design": anchor(A437.DESIGN, A437.DESIGN_SHA256),
            "V1_runner": anchor(V1_RUNNER, V1_RUNNER_SHA256),
            "V1_implementation": anchor(V1_IMPLEMENTATION, V1_IMPLEMENTATION_SHA256),
            "V1_protocol": anchor(V1_PROTOCOL, V1_PROTOCOL_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    A437.assert_no_a426_outcome()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A437 V2 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-protocol-v2"
        or value.get("V1_protocol_sha256") != V1_PROTOCOL_SHA256
        or value.get("schedule_commitment_sha256") != V1_SCHEDULE_COMMITMENT_SHA256
        or value.get("pair_stream_uint16be_uint16be_sha256") != V1_PAIR_STREAM_SHA256
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
    ):
        raise RuntimeError("A437 V2 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A437 V2 protocol commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(A437.DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(A437.DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a437an2")
    writer._rules = []
    writer.add_rule(
        name="frozen_schedule_to_packaging_repair",
        description="Bind the unchanged A437 V1 stream commitment while correcting only the result-to-Causal field lookup.",
        pattern=["A437_V1_frozen_schedule", "A437_V1_packaging_KeyError"],
        conclusion="A437_V2_packaging_repair",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="calibration_geometry_to_anisotropic_wavefront",
        description="Retain the frozen 418:561 integer rectangle-growth rule and exact 2^24 pair cover.",
        pattern=["A437_V2_packaging_repair"],
        conclusion="A437_anisotropic_exact_cover",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="exact_cover_to_A438_executor",
        description="Expose the validated stream hash and codec contract to the restart-safe A438 production executor.",
        pattern=["A437_anisotropic_exact_cover"],
        conclusion="A438_production_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A437:V1_schedule_commitment",
        mechanism="immutable_packaging_only_repair",
        outcome="A437:V2_serializable_result_contract",
        confidence=1.0,
        source=payload["protocol_commitment_sha256"],
        quantification=json.dumps(payload["repair_scope"], sort_keys=True),
        evidence=payload["schedule_commitment_sha256"],
        domain="artifact serialization without schedule mutation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:V2_serializable_result_contract",
        mechanism="retained_418_to_561_rectangle_growth",
        outcome="A437:exact_2pow24_cover_rank_234498",
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(payload["calibration_comparison"], sort_keys=True),
        evidence=payload["pair_stream_uint16be_uint16be_sha256"],
        domain="prospective W52 schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:exact_2pow24_cover_rank_234498",
        mechanism="reuse_A435_qualified_filter_progress_and_confirmation",
        outcome="A438:restart_safe_anisotropic_executor",
        confidence=1.0,
        source=canonical_sha256(payload["anchors"]),
        quantification=json.dumps(payload["schedule_summary"], sort_keys=True),
        evidence="zero target labels, refits, candidates, or A426 outcomes",
        domain="next production object",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:V1_schedule_commitment",
        mechanism="materialized_packaging_schedule_executor_chain",
        outcome="A438:restart_safe_anisotropic_executor",
        confidence=1.0,
        source="materialized:A437_V2_chain",
        quantification="exact retained closure",
        evidence="A437_V2_CAUSAL_PACKAGING_REPAIRED_WITHOUT_SCHEDULE_CHANGE",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A437 V2 immutable packaging repair",
        entities=[
            "A437:V1_schedule_commitment",
            "A437:V2_serializable_result_contract",
            "A437:exact_2pow24_cover_rank_234498",
            "A438:restart_safe_anisotropic_executor",
        ],
    )
    writer.add_gap(
        subject="A437:exact_2pow24_cover_rank_234498",
        predicate="next_required_object",
        expected_object_type="restart_safe_A438_production_executor",
        confidence=1.0,
        suggested_queries=[
            "Reuse A435's qualified Metal subcell execution and confirmation path with A437 V1's immutable anisotropic pair codec and V2's result contract."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a437an2"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A437 V2 authentic Causal reopen gate failed")
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
            "repair": explicit[0],
            "schedule": explicit[1],
            "next_executor": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def assemble_result(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 V2 result already exists")
    A437.assert_no_a426_outcome()
    protocol = load_protocol(expected_protocol_sha256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-result-v2",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CALIBRATION_BALANCED_COMPLETE_TARGET_BLIND_W52_WAVEFRONT_PACKAGED",
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "V1_protocol_sha256": V1_PROTOCOL_SHA256,
        "schedule_commitment_sha256": protocol["schedule_commitment_sha256"],
        "pair_stream_uint16be_uint16be_sha256": protocol[
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "schedule_summary": protocol["schedule_summary"],
        "calibration_comparison": protocol["calibration_comparison"],
        "repair_scope": protocol["repair_scope"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "production_execution_enabled": False,
        "next_executor": "A438",
        "anchors": {
            "design": anchor(A437.DESIGN, A437.DESIGN_SHA256),
            "V1_runner": anchor(V1_RUNNER, V1_RUNNER_SHA256),
            "V1_implementation": anchor(V1_IMPLEMENTATION, V1_IMPLEMENTATION_SHA256),
            "V1_protocol": anchor(V1_PROTOCOL, V1_PROTOCOL_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, protocol["implementation_sha256"]
            ),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["causal"] = build_causal(payload)
    payload["result_sha256"] = canonical_sha256(payload)
    atomic_json(RESULT, payload)
    comparison = payload["calibration_comparison"]
    REPORT.write_text(
        "# A437 V2 — calibration-balanced dual-axis W52 wavefront\n\n"
        "- V1 schedule mutation: **none**\n"
        f"- Pair-stream SHA-256: **`{V1_PAIR_STREAM_SHA256}`**\n"
        f"- Exact pair cover: **{A437.PAIR_CELLS:,} cells**\n"
        f"- W46 calibration benchmark: **{comparison['anisotropic_pair_rank_one_based']:,} vs {comparison['neutral_square_pair_rank_one_based']:,} cells**\n"
        f"- Earlier by: **{comparison['cells_removed_before_calibration_pair_vs_neutral']:,} cells / {comparison['additional_gain_bits_vs_neutral_square']:.6f} bits**\n"
        "- Target labels / refits / candidates / A426 outcomes: **0 / 0 / 0 / 0**\n"
        "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n",
        encoding="utf-8",
    )
    A437.assert_no_a426_outcome()
    return payload


def analyze() -> dict[str, Any]:
    value: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "V1_protocol": anchor(V1_PROTOCOL, V1_PROTOCOL_SHA256),
        "implementation_exists": IMPLEMENTATION.exists(),
        "protocol_exists": PROTOCOL.exists(),
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        value["result"] = json.loads(RESULT.read_bytes())
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--freeze-implementation", action="store_true")
    mode.add_argument("--freeze-protocol", action="store_true")
    mode.add_argument("--assemble", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.freeze_implementation:
        value = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            raise SystemExit("--expected-implementation-sha256 is required")
        value = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.assemble:
        if not args.expected_protocol_sha256:
            raise SystemExit("--expected-protocol-sha256 is required")
        value = assemble_result(expected_protocol_sha256=args.expected_protocol_sha256)
    else:
        value = analyze()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
