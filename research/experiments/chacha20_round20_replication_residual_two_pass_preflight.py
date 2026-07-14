#!/usr/bin/env python3
"""Freeze A277 after A276's exact top-half boundary and before any new solve."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A277"
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_replication_residual_two_pass_v1.json"
)
A275_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_replication_v1.json"
)
A275_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1.json"
)
A275_CAUSAL = A275_RESULT.with_suffix(".causal")
A275_MEASUREMENT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1/target.numeric.measurement.json.zst"
)
A276_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_selected_channel_target_replication_recovery_v1.json"
)
A276_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_recovery_v1.json"
)
A276_CAUSAL = A276_RESULT.with_suffix(".causal")
A276_RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_recovery.py"
)
TWO_PASS_WRAPPER = Path(__file__).with_name("chacha20_residual_two_pass.py")
TWO_PASS_NATIVE = ROOT / "research/native/cadical_residual_two_pass.cpp"
RUNNER = Path(__file__).with_name("chacha20_round20_replication_residual_two_pass.py")
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

EXPECTED = {
    A275_PROTOCOL: "d6e753defe3eba1e9989e8e6f792a6e731d8371487788917db0d7cff518c75f9",
    A275_RESULT: "2c9236c2aff721ba18f1c4009fdd1dd1724b0ba0d5799268ac49c0ac2d4a672a",
    A275_CAUSAL: "fadae6b3dece94cb207f3eba4572d9fc1bfd6796e4256a5bd7b3de5e11e03f3b",
    A275_MEASUREMENT: "0452f3c418bb29b1904170f7dd7a2a8278b4de68d056b8537ead6985ae97ddde",
    A276_PROTOCOL: "b40a8d6da6a5ce3af80e6f34f0eae28f87f1eb22448985ee95e5382ae455b9e5",
    A276_RESULT: "7f83f0851be7e2c5fbf044dffd13608a5cdf3379d007ae0464c2496037a2b84d",
    A276_CAUSAL: "34451043514d131b0185607cfa4081abe6e79de8169b27c2c71a524425c02eae",
    A276_RUNNER: "e82f3e8d8d98c38b13f7674ed31657737276b021025dc652af790e608b53a931",
}


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


def _atomic_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _load_reader(dotcausal_src: Path) -> tuple[Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _derive_quartet_order(
    *, top128: Sequence[int], scores: Sequence[float]
) -> tuple[list[int], list[dict[str, Any]]]:
    top = {int(value) for value in top128}
    if len(top) != 128 or len(scores) != 256 or not all(math.isfinite(x) for x in scores):
        raise RuntimeError("A277 order inputs differ")
    groups = []
    for upper6 in range(64):
        quartet = [4 * upper6 + low2 for low2 in range(4)]
        proved = [value for value in quartet if value in top]
        remaining = [value for value in quartet if value not in top]
        if not remaining:
            continue
        local_order = sorted(remaining, key=lambda value: (-scores[value], value))
        groups.append(
            {
                "upper6": upper6,
                "proved_top_members": proved,
                "proved_top_occupancy": len(proved),
                "remaining_members": remaining,
                "remaining_order": local_order,
                "maximum_remaining_A275_score": max(scores[value] for value in remaining),
                "mean_remaining_A275_score": sum(scores[value] for value in remaining)
                / len(remaining),
            }
        )
    groups.sort(
        key=lambda row: (
            -int(row["proved_top_occupancy"]),
            -float(row["maximum_remaining_A275_score"]),
            -float(row["mean_remaining_A275_score"]),
            int(row["upper6"]),
        )
    )
    order = [value for row in groups for value in row["remaining_order"]]
    if len(order) != 128 or set(order) != set(range(256)) - top:
        raise RuntimeError("A277 quartet order is not the exact unresolved half")
    return order, groups


def build_protocol(*, root_review_acknowledged: bool, dotcausal_src: Path) -> dict[str, Any]:
    if root_review_acknowledged is not True:
        raise RuntimeError("A277 freeze requires explicit root review acknowledgement")
    for path, digest in EXPECTED.items():
        if _file_sha256(path) != digest:
            raise RuntimeError(f"A277 retained anchor differs: {path.name}")
    for path in (TWO_PASS_WRAPPER, TWO_PASS_NATIVE, RUNNER):
        if not path.is_file():
            raise FileNotFoundError(f"A277 source is unavailable: {path}")

    a275_protocol = json.loads(A275_PROTOCOL.read_bytes())
    a275 = json.loads(A275_RESULT.read_bytes())
    a276_protocol = json.loads(A276_PROTOCOL.read_bytes())
    a276 = json.loads(A276_RESULT.read_bytes())
    top128 = [int(value) for value in a275["analysis"]["top128_cell_order"]]
    complete_order = [int(value) for value in a275["analysis"]["complete_cell_order"]]
    scores = [float(value) for value in a275["analysis"]["score_field"]]
    execution = a276.get("execution_summary", {})
    rows = a276.get("execution", {}).get("rows", [])
    if (
        a275_protocol.get("target", {}).get(
            "ephemeral_generation_label_returned_or_serialized"
        )
        is not False
        or a275.get("information_boundary", {}).get(
            "target_generation_label_stored_in_protocol_result_Causal_or_report"
        )
        is not False
        or a275.get("information_boundary", {}).get(
            "target_label_used_for_feature_construction_scoring_order_or_stop"
        )
        is not False
        or a276.get("attempt_id") != "A276"
        or a276.get("confirmation") is not None
        or a276.get("post_model_controls") is not None
        or execution.get("attempted_cells") != 128
        or execution.get("unsat") != 128
        or execution.get("unknown") != 0
        or execution.get("sat") != 0
        or execution.get("logical_assignments") != 2**19
        or len(rows) != 128
        or any(row.get("status") != "unsat" for row in rows)
        or [int(row["prefix8"], 2) for row in rows] != top128
        or complete_order[:128] != top128
        or _sha256(bytes(complete_order))
        != a275["analysis"]["complete_cell_order_uint8_sha256"]
        or _sha256(bytes(top128))
        != a275["analysis"]["top128_cell_order_uint8_sha256"]
        or a276_protocol.get("target", {}).get("generation_label_available") is not False
    ):
        raise RuntimeError("A277 A275/A276 boundary gate differs")

    CausalReader, reader_source = _load_reader(dotcausal_src)
    reader = CausalReader(str(A276_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a276"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "ordered_clause_timing_or_budget_reallocation_after_top128_boundary"
    ):
        raise RuntimeError("A277 authentic A276 Causal gap differs")

    assumption_variables = [abs(int(value)) for value in rows[0]["assumptions"]]
    if (
        assumption_variables != [67, 62, 55, 53, 51, 49, 47, 45]
        or any(
            [abs(int(value)) for value in row["assumptions"]]
            != assumption_variables
            for row in rows
        )
    ):
        raise RuntimeError("A277 A276 prefix-assumption geometry differs")
    core_widths = Counter(len(row["failed_assumptions"]) for row in rows)
    omitted_variables = Counter(
        tuple(
            variable
            for variable in assumption_variables
            if variable
            not in {abs(int(value)) for value in row["failed_assumptions"]}
        )
        for row in rows
    )
    if core_widths != Counter({8: 109, 7: 18, 6: 1}) or omitted_variables != Counter(
        {(): 109, (45,): 14, (47,): 4, (47, 45): 1}
    ):
        raise RuntimeError("A277 A276 failed-assumption core geometry differs")
    proof_core_support = {
        "source": "A276_execution_rows_failed_assumptions",
        "A276_result_sha256": EXPECTED[A276_RESULT],
        "assumption_variables_by_prefix_position_MSB_to_LSB": assumption_variables,
        "key_bits_by_prefix_position_MSB_to_LSB": list(range(19, 11, -1)),
        "failed_assumption_core_width_histogram": {
            str(width): count for width, count in sorted(core_widths.items())
        },
        "omitted_assumption_variable_histogram": {
            ",".join(str(value) for value in omitted) or "none": count
            for omitted, count in sorted(omitted_variables.items())
        },
        "omitted_key_bit_histogram": {
            "none": 109,
            "12": 14,
            "13": 4,
            "13,12": 1,
        },
        "generalized_core_count": 19,
        "supported_partition": "prefix8_upper6_fixed_low2_free",
        "target_label_used": False,
    }
    bottom_order, quartet_groups = _derive_quartet_order(top128=top128, scores=scores)
    budgets = {
        "global_seconds": 300.0,
        "discovery_seconds_per_cell": 10.0,
        "fallback_seconds_per_unresolved_cell": 30.0,
        "external_timeout_seconds": 6000.0,
    }
    order_derivation = {
        "name": "proof_core_quartet_cluster_then_A275_score",
        "source_gap": gaps[0],
        "proof_core_support": proof_core_support,
        "quartet_definition": "prefix8_upper6_fixed_low2_free",
        "group_order": (
            "descending proved-top occupancy, descending maximum remaining A275 score, "
            "descending mean remaining A275 score, ascending upper6"
        ),
        "within_group_order": "descending A275 score then ascending prefix",
        "quartet_groups": quartet_groups,
        "unresolved_order": bottom_order,
        "unresolved_order_uint8_sha256": _sha256(bytes(bottom_order)),
        "correct_prefix_or_rank_known": False,
        "target_label_used": False,
    }
    blocking = {
        "source": "A276_exact_UNSAT_top128",
        "blocked_prefixes": top128,
        "blocked_prefixes_uint8_sha256": _sha256(bytes(top128)),
        "clause_count": 128,
        "clause_width": 8,
        "semantics": "one negated-assumption clause per exact-UNSAT prefix",
        "solution_preserving": True,
        "remaining_prefixes": sorted(set(range(256)) - set(top128)),
        "remaining_prefixes_uint8_sha256": _sha256(
            bytes(sorted(set(range(256)) - set(top128)))
        ),
    }
    anchors = {
        "A275_protocol_path": str(A275_PROTOCOL.relative_to(ROOT)),
        "A275_protocol_sha256": EXPECTED[A275_PROTOCOL],
        "A275_result_path": str(A275_RESULT.relative_to(ROOT)),
        "A275_result_sha256": EXPECTED[A275_RESULT],
        "A275_causal_path": str(A275_CAUSAL.relative_to(ROOT)),
        "A275_causal_sha256": EXPECTED[A275_CAUSAL],
        "A275_measurement_path": str(A275_MEASUREMENT.relative_to(ROOT)),
        "A275_measurement_sha256": EXPECTED[A275_MEASUREMENT],
        "A276_protocol_path": str(A276_PROTOCOL.relative_to(ROOT)),
        "A276_protocol_sha256": EXPECTED[A276_PROTOCOL],
        "A276_result_path": str(A276_RESULT.relative_to(ROOT)),
        "A276_result_sha256": EXPECTED[A276_RESULT],
        "A276_causal_path": str(A276_CAUSAL.relative_to(ROOT)),
        "A276_causal_sha256": EXPECTED[A276_CAUSAL],
        "A276_runner_path": str(A276_RUNNER.relative_to(ROOT)),
        "A276_runner_sha256": EXPECTED[A276_RUNNER],
        "two_pass_wrapper_path": str(TWO_PASS_WRAPPER.relative_to(ROOT)),
        "two_pass_wrapper_sha256": _file_sha256(TWO_PASS_WRAPPER),
        "two_pass_native_path": str(TWO_PASS_NATIVE.relative_to(ROOT)),
        "two_pass_native_sha256": _file_sha256(TWO_PASS_NATIVE),
        "preflight_path": str(Path(__file__).relative_to(ROOT)),
        "preflight_sha256": _file_sha256(Path(__file__)),
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    protocol = {
        "schema": "chacha20-round20-replication-residual-two-pass-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "frozen_after_A276_exact_top128_boundary_and_before_any_A277_global_"
            "discovery_or_fallback_solve"
        ),
        "research_question": (
            "Can the exact A276 half-domain boundary plus retained global and timed "
            "cell solving recover the hidden full-round ChaCha20-R20 model without "
            "enumerating the complete remaining half?"
        ),
        "anchors": anchors,
        "target": {
            "public_challenge_sha256": a275["public_challenge_sha256"],
            "generation_label_available": False,
            "correct_prefix_or_rank_known": False,
        },
        "A276_exact_boundary": {
            "attempted_cells": 128,
            "exact_unsat_cells": 128,
            "exact_logical_assignments": 2**19,
            "retained_state_continuity_verified": True,
            "result_sha256": EXPECTED[A276_RESULT],
            "causal_sha256": EXPECTED[A276_CAUSAL],
        },
        "blocking_clause_protocol": blocking,
        "frozen_unresolved_order": order_derivation,
        "solver_protocol": {
            **budgets,
            "phase_order": ["global", "discovery", "fallback"],
            "single_retained_CaDiCaL_state": True,
            "global_arm_has_no_prefix_assumptions": True,
            "discovery_visits_all_unresolved_cells_until_first_SAT": True,
            "fallback_visits_only_discovery_UNKNOWN_cells_until_first_SAT": True,
            "discovery_UNKNOWN_is_not_elimination": True,
            "fallback_UNKNOWN_is_not_elimination": True,
            "stop_condition": "first_SAT_only",
            "independent_4096_bit_confirmation_required": True,
        },
        "information_boundary": {
            "target_generation_label_available": False,
            "correct_prefix_or_rank_available": False,
            "A276_exact_UNSAT_mask_is_public_solver_evidence": True,
            "A275_scores_are_public_model_free_measurements": True,
            "new_order_uses_only_target_label_free_A275_scores_A276_exact_UNSAT_"
            "mask_and_A276_failed_assumption_core_geometry": True,
            "all_parameters_frozen_before_any_A277_solver_execution": True,
            "confirmation_permitted_only_after_solver_model": True,
        },
        "authentic_causal_readback": {
            "A276_gap": gaps[0],
            "reader_source": reader_source,
            "read_personally_by_main_before_freeze": True,
        },
    }
    protocol["scientific_design_sha256"] = _canonical_sha256(
        {
            "target": protocol["target"],
            "A276_exact_boundary": protocol["A276_exact_boundary"],
            "blocking_clause_protocol": blocking,
            "frozen_unresolved_order": order_derivation,
            "solver_protocol": protocol["solver_protocol"],
            "information_boundary": protocol["information_boundary"],
        }
    )
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--root-review-acknowledged", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"A277 protocol already exists: {args.output}")
    protocol = build_protocol(
        root_review_acknowledged=args.root_review_acknowledged,
        dotcausal_src=args.dotcausal_src,
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "scientific_design_sha256": protocol["scientific_design_sha256"],
                "unresolved_order_uint8_sha256": protocol["frozen_unresolved_order"][
                    "unresolved_order_uint8_sha256"
                ],
                "target_label_available": False,
                "solver_execution_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
