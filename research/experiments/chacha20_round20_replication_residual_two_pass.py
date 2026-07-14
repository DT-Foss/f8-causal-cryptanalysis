#!/usr/bin/env python3
"""Execute A277's frozen residual-global and retained two-pass R20 solve."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

ATTEMPT_ID = "A277"
DEFAULT_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_replication_residual_two_pass_v1.json"
)
DEFAULT_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_replication_residual_two_pass_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_REPLICATION_RESIDUAL_TWO_PASS_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A277 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[dict[str, Any], Any, Any, dict[str, Any], Any, Any, Any, Any]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A277 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    solver = protocol.get("solver_protocol", {})
    boundary = protocol.get("A276_exact_boundary", {})
    blocking = protocol.get("blocking_clause_protocol", {})
    order = protocol.get("frozen_unresolved_order", {})
    values = order.get("unresolved_order", [])
    if (
        protocol.get("schema")
        != "chacha20-round20-replication-residual-two-pass-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A276_exact_top128_boundary_and_before_any_A277_global_discovery_or_fallback_solve"
        or solver.get("global_seconds") != 300.0
        or solver.get("discovery_seconds_per_cell") != 10.0
        or solver.get("fallback_seconds_per_unresolved_cell") != 30.0
        or solver.get("external_timeout_seconds") != 6000.0
        or solver.get("phase_order") != ["global", "discovery", "fallback"]
        or solver.get("single_retained_CaDiCaL_state") is not True
        or solver.get("discovery_UNKNOWN_is_not_elimination") is not True
        or boundary.get("exact_unsat_cells") != 128
        or boundary.get("exact_logical_assignments") != 2**19
        or blocking.get("clause_count") != 128
        or blocking.get("clause_width") != 8
        or blocking.get("solution_preserving") is not True
        or len(values) != 128
        or len(set(values)) != 128
        or set(values) != set(blocking.get("remaining_prefixes", []))
        or _sha256(bytes(values)) != order.get("unresolved_order_uint8_sha256")
        or protocol.get("target", {}).get("generation_label_available") is not False
        or protocol.get("target", {}).get("correct_prefix_or_rank_known") is not False
        or protocol.get("information_boundary", {}).get(
            "all_parameters_frozen_before_any_A277_solver_execution"
        )
        is not True
    ):
        raise RuntimeError("A277 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != anchors.get(hash_key):
            raise RuntimeError(f"A277 anchored dependency differs: {path_key}")
    a276_result = json.loads(_anchor_path(anchors["A276_result_path"]).read_bytes())
    if (
        a276_result.get("execution_summary", {}).get("unsat") != 128
        or a276_result.get("execution_summary", {}).get("unknown") != 0
        or a276_result.get("execution_summary", {}).get("sat") != 0
        or a276_result.get("confirmation") is not None
        or a276_result.get("public_challenge_sha256")
        != protocol["target"]["public_challenge_sha256"]
    ):
        raise RuntimeError("A277 A276 exact-boundary anchor differs")
    a276 = _import_path(_anchor_path(anchors["A276_runner_path"]), "a277_a276")
    (
        a276_protocol,
        a275_protocol,
        a275_result,
        public,
        template,
        _ranked,
        template_protocol,
    ) = a276._load_protocol(
        _anchor_path(anchors["A276_protocol_path"]),
        anchors["A276_protocol_sha256"],
    )
    two_pass = _import_path(
        _anchor_path(anchors["two_pass_wrapper_path"]), "a277_two_pass"
    )
    return (
        protocol,
        a276,
        two_pass,
        a276_protocol,
        a275_protocol,
        a275_result,
        public,
        (template, template_protocol),
    )


def append_blocking_clauses(
    raw: bytes,
    *,
    blocked_prefixes: Sequence[int],
    key_one_literals_bit0_through_bit19: Sequence[int],
) -> tuple[bytes, dict[str, Any]]:
    newline = raw.find(b"\n")
    if newline < 0:
        raise ValueError("A277 DIMACS header is missing")
    header = raw[:newline].decode("ascii").split()
    if len(header) != 4 or header[:2] != ["p", "cnf"]:
        raise ValueError("A277 DIMACS header differs")
    variables, clauses = int(header[2]), int(header[3])
    blocked = [int(value) for value in blocked_prefixes]
    mapping = [int(value) for value in key_one_literals_bit0_through_bit19]
    if (
        len(blocked) != 128
        or len(set(blocked)) != 128
        or min(blocked) < 0
        or max(blocked) > 255
        or len(mapping) != 20
        or len({abs(value) for value in mapping}) != 20
        or max(abs(value) for value in mapping) > variables
    ):
        raise ValueError("A277 blocking inputs differ")
    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    clause_rows = []
    for prefix in blocked:
        bits = f"{prefix:08b}"
        literals = [
            -one_literal if bit == "1" else one_literal
            for bit, one_literal in zip(bits, assumption_one, strict=True)
        ]
        clause_rows.append(" ".join(str(value) for value in literals) + " 0\n")
    clause_raw = "".join(clause_rows).encode("ascii")
    body = raw[newline + 1 :]
    if body and not body.endswith(b"\n"):
        body += b"\n"
    new_header = f"p cnf {variables} {clauses + len(blocked)}\n".encode("ascii")
    result = new_header + body + clause_raw
    return result, {
        "original_header": raw[:newline].decode("ascii"),
        "blocked_header": new_header.decode("ascii").strip(),
        "original_clause_count": clauses,
        "blocked_clause_count": clauses + len(blocked),
        "added_clause_count": len(blocked),
        "added_clause_width": 8,
        "added_clauses_sha256": _sha256(clause_raw),
        "blocked_cnf_sha256": _sha256(result),
        "blocked_cnf_bytes": len(result),
        "blocked_prefixes_uint8_sha256": _sha256(bytes(blocked)),
        "solution_preserving_from_A276_exact_UNSAT_proofs": True,
    }


def _scientific_execution(execution: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": execution["mode"],
        "order": execution["order"],
        "budgets": execution["budgets"],
        "rows": [
            {key: value for key, value in row.items() if key != "elapsed_seconds"}
            for row in execution["rows"]
        ],
        "summary": execution["summary"],
        "sat_found": execution["sat_found"],
        "exact_unsat_prefixes": execution["exact_unsat_prefixes"],
        "retained_state_continuity_verified": execution[
            "retained_state_continuity_verified"
        ],
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    dotcausal_src: Path,
    expected_reader_source: Mapping[str, Any],
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    if source != dict(expected_reader_source):
        raise RuntimeError("A277 authoritative Causal Reader source changed during run")
    confirmed = payload["confirmation"] is not None
    phase = payload["execution_summary"]["model_discovery_phase"]
    terminal = (
        f"A277:confirmed_R20_residual_{phase}_recovery"
        if confirmed
        else "A277:residual_two_pass_budget_boundary"
    )
    writer = CausalWriter(api_id="a277")
    writer._rules = []
    writer.add_rule(
        name="exact_unsat_prefixes_become_solution_preserving_blocking_clauses",
        description="Every A276 exact-UNSAT prefix becomes one negated-assumption clause before A277 starts.",
        pattern=["A276_exact_top128_UNSAT", "A277_128_blocking_clauses"],
        conclusion="A277_exact_bottom_half_residual_formula",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="retained_global_then_timed_cells_then_confirmation",
        description="One CaDiCaL state executes the global arm, short discovery cells, and longer-budget fallback cells; a model is accepted only after dual 4096-bit confirmation.",
        pattern=["A277_exact_bottom_half_residual_formula", "A277_retained_three_phase_solver"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A276:top128_retained_solver_boundary",
        mechanism="materialize_128_exact_negated_prefix_clauses",
        outcome="A277:exact_bottom_half_residual_formula",
        confidence=1.0,
        source=payload["A276_result_sha256"],
        quantification=json.dumps(payload["blocking_clause_manifest"], sort_keys=True),
        evidence="128 exact UNSAT cells; 2^19 assignments",
        domain="full-round ChaCha20-R20 residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A277:exact_bottom_half_residual_formula",
        mechanism="global_then_10s_discovery_then_30s_fallback_in_one_retained_state",
        outcome="A277:retained_three_phase_solver",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["execution_summary"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="target-blind adaptive solver schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A277:retained_three_phase_solver",
        mechanism=(
            "dual_independent_all_eight_block_confirmation"
            if confirmed
            else "complete_frozen_budget_without_model"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 output bits plus flipped control"
            if confirmed
            else "global plus discovery plus fallback frozen budgets"
        ),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independently confirmed recovery or measured budget boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A276:top128_retained_solver_boundary",
        mechanism="materialized_exact_boundary_plus_retained_schedule_plus_confirmation",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A276_boundary_plus_A277_execution",
        quantification="AI-native end-to-end inference chain",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A277 residual-boundary recovery",
        entities=[
            "A276:top128_retained_solver_boundary",
            "A277:exact_bottom_half_residual_formula",
            "A277:retained_three_phase_solver",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "cross_public_material_replication_with_frozen_residual_schedule"
            if confirmed
            else "new_public_reader_or_longer_global_residual_budget"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the entire residual schedule before a target with new public material.",
                "Transfer exact-boundary blocking to a wider residual-key domain.",
            ]
            if confirmed
            else [
                "Which phase accumulated the largest model-directed progress?",
                "Does a new target-blind reader move the exact boundary before solving?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a277"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A277 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    summary = payload["execution_summary"]
    confirmation = payload["confirmation"]
    rows = [
        "# A277 — ChaCha20-R20 residual-boundary retained solve",
        "",
        f"Evidence stage: **{payload['evidence_stage']}**",
        "",
        f"- A276 exact prefix cells materialized: **{summary['previous_exact_unsat_cells']}**",
        f"- New exact UNSAT prefix cells: **{summary['new_exact_unsat_cells']}**",
        f"- Model found: **{summary['sat_found']}**",
        f"- Model-discovery phase: **{summary['model_discovery_phase']}**",
        f"- Complete remaining-half enumeration used: **{summary['complete_remaining_half_enumeration_used']}**",
    ]
    if confirmation is not None:
        rows.extend(
            [
                f"- Recovered low20: **`0x{confirmation['recovered_unknown_low20_hex']}`**",
                f"- Independent output bits confirmed: **{confirmation['output_bits_checked']}**",
                f"- Flipped control matched: **{confirmation['control_first_block_match']}**",
            ]
        )
    rows.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )
    return "\n".join(rows)


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    protocol, *_ = _load_protocol(protocol_path, expected_protocol_sha256)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "blocked_exact_prefixes": len(
            protocol["blocking_clause_protocol"]["blocked_prefixes"]
        ),
        "unresolved_prefixes": len(
            protocol["frozen_unresolved_order"]["unresolved_order"]
        ),
        "solver_protocol": protocol["solver_protocol"],
        "target_label_available": False,
        "solver_execution_started": False,
    }


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    (
        protocol,
        a276,
        two_pass,
        a276_protocol,
        a275_protocol,
        _a275_result,
        public,
        template_pair,
    ) = _load_protocol(protocol_path, expected_protocol_sha256)
    template, template_protocol = template_pair
    anchors = protocol["anchors"]
    _, _, causal_reader_source = _load_dotcausal(dotcausal_src)
    frozen_reader_source = protocol["authentic_causal_readback"]["reader_source"]
    if causal_reader_source != frozen_reader_source:
        raise RuntimeError("A277 authoritative Causal Reader source differs from freeze")
    build = two_pass.compile_helper()
    if build["source_sha256"] != anchors["two_pass_native_sha256"]:
        raise RuntimeError("A277 helper rebuild source differs from freeze")
    challenge = a275_protocol["target"]["public_challenge"]
    with tempfile.TemporaryDirectory(prefix="a277_residual_two_pass_") as temporary:
        directory = Path(temporary)
        base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
            r20=public,
            public_challenge=challenge,
            protocol=template_protocol,
            directory=directory,
        )
        target_raw, _, target_instantiation = template.instantiate_output(
            base_raw,
            output_mapping,
            challenge["target_words"][0],
        )
        blocked_raw, blocking_manifest = append_blocking_clauses(
            target_raw,
            blocked_prefixes=protocol["blocking_clause_protocol"]["blocked_prefixes"],
            key_one_literals_bit0_through_bit19=key_mapping,
        )
        if (
            blocking_manifest["blocked_prefixes_uint8_sha256"]
            != protocol["blocking_clause_protocol"]["blocked_prefixes_uint8_sha256"]
            or blocking_manifest["added_clause_count"] != 128
        ):
            raise RuntimeError("A277 blocking-clause reconstruction differs")
        cnf = directory / "a277_exact_bottom_half.cnf"
        _atomic_bytes(cnf, blocked_raw)
        if _file_sha256(cnf) != blocking_manifest["blocked_cnf_sha256"]:
            raise RuntimeError("A277 blocked CNF readback differs")
        order_values = protocol["frozen_unresolved_order"]["unresolved_order"]
        order = [f"{int(value):08b}" for value in order_values]
        solver = protocol["solver_protocol"]
        execution = two_pass.run_two_pass(
            helper=two_pass.BINARY,
            cnf=cnf,
            mode="A277_A276_exact_boundary_residual_two_pass",
            order=order,
            key_one_literals_bit0_through_bit19=key_mapping,
            global_seconds=float(solver["global_seconds"]),
            discovery_seconds=float(solver["discovery_seconds_per_cell"]),
            fallback_seconds=float(solver["fallback_seconds_per_unresolved_cell"]),
            external_timeout_seconds=float(solver["external_timeout_seconds"]),
        )
    if execution["global_row"]["status"] == "unsat":
        raise RuntimeError("A277 residual formula contradicts A276 exact boundary")
    confirmation = None
    post_model = None
    sat_row = execution["sat_row"]
    if sat_row is not None:
        confirmation_anchors = a276_protocol["anchors"]
        for stem in ("independent_reference", "public_core"):
            if (
                _file_sha256(_anchor_path(confirmation_anchors[f"{stem}_path"]))
                != confirmation_anchors[f"{stem}_sha256"]
            ):
                raise RuntimeError(f"A277 {stem} source changed before confirmation")
        low20 = a276._decode_model(sat_row["model_bits_bit0_through_bit19"])
        prefix = low20 >> 12
        unresolved = set(protocol["frozen_unresolved_order"]["unresolved_order"])
        if prefix not in unresolved:
            raise RuntimeError("A277 SAT model lies outside exact residual half")
        if sat_row["prefix8"] is not None and sat_row["prefix8"] != f"{prefix:08b}":
            raise RuntimeError("A277 SAT model prefix differs from assumed cell")
        confirmation = a276._confirm(public, challenge, low20)
        if (
            any(
                _file_sha256(_anchor_path(confirmation_anchors[f"{stem}_path"]))
                != confirmation_anchors[f"{stem}_sha256"]
                for stem in ("independent_reference", "public_core")
            )
            or confirmation["claim_gate_source_sha256"]
            != confirmation_anchors["independent_reference_sha256"]
            or confirmation["all_blocks_match"] is not True
            or confirmation["all_cross_implementation_blocks_match"] is not True
            or confirmation["claim_gate_rfc8439_section_2_3_2_kat"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError("A277 SAT model failed dual-independent confirmation")
        post_model = {
            "recovered_prefix8": prefix,
            "model_discovery_phase": sat_row["phase"],
            "frozen_unresolved_order_position": (
                None
                if sat_row["prefix8"] is None
                else protocol["frozen_unresolved_order"]["unresolved_order"].index(prefix)
                + 1
            ),
            "numeric_position": prefix + 1,
            "computed_only_after_confirmed_model": True,
        }
    phase = sat_row["phase"] if sat_row is not None else "none"
    stage = (
        f"FULLROUND_R20_TARGET_BLIND_RESIDUAL_{phase.upper()}_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_TARGET_BLIND_RESIDUAL_TWO_PASS_BUDGET_BOUNDARY"
    )
    new_exact = {int(value, 2) for value in execution["exact_unsat_prefixes"]}
    previous_exact = set(protocol["blocking_clause_protocol"]["blocked_prefixes"])
    if new_exact & previous_exact:
        raise RuntimeError("A277 new exact prefix set overlaps A276 boundary")
    if confirmation is None and len(previous_exact | new_exact) == 256:
        raise RuntimeError(
            "A277 exact prefix cover contradicts satisfiable public challenge"
        )
    rows = execution["rows"]
    total_metrics = [
        int(right) - int(left)
        for left, right in zip(
            rows[0]["metrics_before"], rows[-1]["metrics_after"], strict=True
        )
    ]
    exact_plus_model_cells = len(previous_exact | new_exact) + int(confirmation is not None)
    execution_summary = {
        "sat_found": confirmation is not None,
        "model_discovery_phase": phase,
        "attempted_solver_calls": len(rows),
        "global_status": execution["global_row"]["status"],
        "discovery_cells_attempted": len(execution["discovery_rows"]),
        "fallback_cells_attempted": len(execution["fallback_rows"]),
        "previous_exact_unsat_cells": len(previous_exact),
        "new_exact_unsat_cells": len(new_exact),
        "total_exact_unsat_cells": len(previous_exact | new_exact),
        "exact_unsat_logical_assignments": len(previous_exact | new_exact) * 2**12,
        "exact_prefix_cells_plus_confirmed_model_cell": exact_plus_model_cells,
        "full_residual_domain_cells": 256,
        "full_residual_domain_assignments": 2**20,
        "strict_subset_before_confirmed_model": (
            confirmation is not None and exact_plus_model_cells < 256
        ),
        "complete_remaining_half_enumeration_used": (
            confirmation is not None and exact_plus_model_cells >= 256
        ),
        "retained_state_continuity_verified": execution[
            "retained_state_continuity_verified"
        ],
        "metric_names": ["conflicts", "decisions", "search_propagations"],
        "total_metrics_delta": total_metrics,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-replication-residual-two-pass-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": stage,
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "A276_result_sha256": anchors["A276_result_sha256"],
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "target_generation_label_available": False,
        "native_helper_build": build,
        "symbolic_template_manifest": template_manifest,
        "target_instantiation": target_instantiation,
        "blocking_clause_manifest": blocking_manifest,
        "frozen_unresolved_order_sha256": protocol["frozen_unresolved_order"][
            "unresolved_order_uint8_sha256"
        ],
        "execution": execution,
        "scientific_execution": _scientific_execution(execution),
        "execution_summary": execution_summary,
        "confirmation": confirmation,
        "post_model_controls": post_model,
        "information_boundary": protocol["information_boundary"],
    }
    payload["measurement_sha256"] = _canonical_sha256(
        {
            key: payload[key]
            for key in (
                "evidence_stage",
                "A276_result_sha256",
                "public_challenge_sha256",
                "target_generation_label_available",
                "symbolic_template_manifest",
                "target_instantiation",
                "blocking_clause_manifest",
                "frozen_unresolved_order_sha256",
                "scientific_execution",
                "execution_summary",
                "confirmation",
                "post_model_controls",
            )
        }
    )
    payload["causal"] = _build_causal(
        causal_output,
        payload,
        dotcausal_src,
        frozen_reader_source,
    )
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                analyze(args.protocol, args.expected_protocol_sha256),
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "attempt_id": payload["attempt_id"],
                "evidence_stage": payload["evidence_stage"],
                "execution_summary": payload["execution_summary"],
                "confirmation": payload["confirmation"],
                "result_sha256": _file_sha256(args.output),
                "causal_sha256": _file_sha256(args.causal_output),
                "report_sha256": _file_sha256(args.report_output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
