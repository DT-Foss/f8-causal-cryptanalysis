#!/usr/bin/env python3
"""Compute exact order-weighted affine-gauge landscapes for SHAKE R2."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A161 = _import_sibling(
    "shake_symbolic_r2_affine_gauge_solver_frontier.py",
    "shake_symbolic_r2_order_weighted_gauge_a161_base",
)

_A160 = _A161._A160
_A159 = _A161._A159
_A158 = _A161._A158
_A155 = _A161._A155
_A154 = _A161._A154
_BASE = _A161._BASE
_R1 = _A161._R1
_SYMBOLIC = _A161._SYMBOLIC

ATTEMPT_ID = "A162"
SCHEMA = "shake-symbolic-r2-order-weighted-affine-gauge-reader-v1"
SEED = _A161.SEED
WINDOW_BITS = _A161.WINDOW_BITS
STATE_BITS = _A160.STATE_BITS
A161_FILENAME = _A161.RESULT_FILENAME
A161_SHA256 = "32908a20d5fc5c70ea99edc259ff0ee2575b2d6bc8344994a1afa36c05202971"
A160_FILENAME = _A160.RESULT_FILENAME
A160_SHA256 = _A161.A160_SHA256
A160_SHIFT = _A161.AFFINE_SHIFT
WEIGHT_MODES = (
    "front_loaded_declaration_position",
    "back_loaded_declaration_position",
)
RESULT_FILENAME = "shake_symbolic_r2_order_weighted_gauge_reader_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_order_weighted_gauge_reader_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    a161 = _A161._A156._load_json_gate(results_dir / A161_FILENAME, A161_SHA256, _A161.SCHEMA)
    a160 = _A161._A156._load_json_gate(results_dir / A160_FILENAME, A160_SHA256, _A160.SCHEMA)
    if (
        a161.get("formula_plan_sha256")
        != "e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3"
        or a161.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or [row.get("decision_delta") for row in a161.get("baseline_comparison", [])]
        != [4_919, -3_893, -7_474, -11_399]
        or [row.get("name") for row in a161.get("baseline_comparison", [])]
        != list(_A158.ORDER_NAMES)
        or a160.get("global_optimum", {}).get("minimum_shift") != A160_SHIFT
        or a160.get("global_optimum", {}).get("minimum_tie_count") != 1
        or a160.get("walsh_objective", {}).get("linear_coefficient_positions")
        != STATE_BITS * WINDOW_BITS
        or a160.get("walsh_objective", {}).get("shift_domain_size") != 1 << WINDOW_BITS
    ):
        raise RuntimeError("A160/A161 order-weighted gauge anchor gate failed")
    return a160, a161


def _coordinate_terms(
    polynomials: Sequence[frozenset[int]], width: int
) -> list[tuple[int, int, int]]:
    terms = []
    for polynomial in polynomials:
        for coordinate in range(width):
            linear = int((1 << coordinate) in polynomial)
            neighbors = 0
            for other in range(width):
                if other != coordinate and ((1 << coordinate) | (1 << other)) in polynomial:
                    neighbors |= 1 << other
            terms.append((coordinate, neighbors, linear))
    if len(terms) != len(polynomials) * width:
        raise RuntimeError("A162 coordinate-term construction failed")
    return terms


def _input_weights(order: Sequence[int], mode: str) -> list[int]:
    if sorted(order) != list(range(WINDOW_BITS)):
        raise ValueError("order-weighted objective requires a complete permutation")
    position = {coordinate: index for index, coordinate in enumerate(order)}
    if mode == "front_loaded_declaration_position":
        return [WINDOW_BITS - position[coordinate] for coordinate in range(WINDOW_BITS)]
    if mode == "back_loaded_declaration_position":
        return [position[coordinate] + 1 for coordinate in range(WINDOW_BITS)]
    raise ValueError(f"unknown order-weight mode: {mode}")


def _weighted_spectrum(
    terms: Sequence[tuple[int, int, int]], weights: Sequence[int]
) -> tuple[np.ndarray, int]:
    if len(weights) != WINDOW_BITS or sorted(weights) != list(range(1, WINDOW_BITS + 1)):
        raise ValueError("order weights must be a permutation of 1..24")
    spectrum = np.zeros(1 << WINDOW_BITS, dtype=np.int32)
    total_weight = 0
    for coordinate, neighbors, linear in terms:
        weight = int(weights[coordinate])
        spectrum[neighbors] += weight if linear == 0 else -weight
        total_weight += weight
    expected = STATE_BITS * sum(range(1, WINDOW_BITS + 1))
    if total_weight != expected:
        raise RuntimeError("weighted coefficient-position total differs")
    return spectrum, total_weight


def _weighted_incidence(
    terms: Sequence[tuple[int, int, int]], weights: Sequence[int], shift: int
) -> int:
    return sum(
        int(weights[coordinate]) * (linear ^ ((neighbors & shift).bit_count() & 1))
        for coordinate, neighbors, linear in terms
    )


def _landscape(
    *,
    terms: Sequence[tuple[int, int, int]],
    polynomials: Sequence[frozenset[int]],
    order_name: str,
    order: Sequence[int],
    mode: str,
) -> dict[str, Any]:
    weights = _input_weights(order, mode)
    spectrum, total_weight = _weighted_spectrum(terms, weights)
    scores = _A160._fwht(spectrum)
    shift = int(np.argmax(scores))
    maximum_score = int(scores[shift])
    minimum = (total_weight - maximum_score) // 2
    zero = (total_weight - int(scores[0])) // 2
    a160 = (total_weight - int(scores[A160_SHIFT])) // 2
    if (
        (total_weight - maximum_score) & 1
        or _weighted_incidence(terms, weights, shift) != minimum
        or _weighted_incidence(terms, weights, 0) != zero
        or _weighted_incidence(terms, weights, A160_SHIFT) != a160
    ):
        raise RuntimeError("A162 Walsh/direct weighted objective gate failed")
    coefficient_energy = _A160._score_energy(spectrum)
    score_energy = _A160._score_energy(scores)
    expected_score_energy = spectrum.size * coefficient_energy
    if score_energy != expected_score_energy:
        raise RuntimeError("A162 weighted Walsh Parseval gate failed")
    shifted = _A160._shift_polynomials(polynomials, shift, WINDOW_BITS)
    counts = _A160._coefficient_counts(shifted)
    return {
        "name": f"{order_name}__{mode}",
        "order_name": order_name,
        "weight_mode": mode,
        "variable_to_input_coordinate": list(order),
        "solver_position_weights": (
            list(range(WINDOW_BITS, 0, -1))
            if mode == "front_loaded_declaration_position"
            else list(range(1, WINDOW_BITS + 1))
        ),
        "input_coordinate_weights": weights,
        "input_coordinate_weights_sha256": _canonical_sha256(weights),
        "weighted_position_total": total_weight,
        "coefficient_spectrum_nonzero_bins": int(np.count_nonzero(spectrum)),
        "coefficient_spectrum_sha256": _sha256(spectrum.astype("<i4", copy=False).tobytes()),
        "coefficient_spectrum_energy": coefficient_energy,
        "walsh_score_vector_sha256": _sha256(scores.astype("<i4", copy=False).tobytes()),
        "walsh_score_energy": score_energy,
        "walsh_parseval_verified": True,
        "minimum_shift": shift,
        "minimum_shift_hex": f"0x{shift:06x}",
        "minimum_shift_hamming_weight": shift.bit_count(),
        "minimum_tie_count": int(np.count_nonzero(scores == maximum_score)),
        "maximum_walsh_score": maximum_score,
        "minimum_weighted_linear_incidence": minimum,
        "zero_shift_weighted_linear_incidence": zero,
        "A160_shift_weighted_linear_incidence": a160,
        "improvement_from_zero_shift": zero - minimum,
        "improvement_from_A160_shift": a160 - minimum,
        "selected_shift_unweighted_coefficient_incidence": counts,
        "global_optimum_certified": True,
        "target_rate_input_used": False,
        "solver_observations_used_in_objective": False,
        "instrumented_assignment_used": False,
    }


def _semantic_gates(
    *,
    polynomials: list[frozenset[int]],
    landscapes: Sequence[dict[str, Any]],
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
) -> list[dict[str, Any]]:
    gates = []
    original_quadratics = [
        frozenset(mask for mask in polynomial if mask.bit_count() == 2)
        for polynomial in polynomials
    ]
    for shift in sorted({int(row["minimum_shift"]) for row in landscapes}):
        shifted = _A160._shift_polynomials(polynomials, shift, WINDOW_BITS)
        shifted_quadratics = [
            frozenset(mask for mask in polynomial if mask.bit_count() == 2)
            for polynomial in shifted
        ]
        if shifted_quadratics != original_quadratics:
            raise RuntimeError("A162 affine gauge changed a quadratic coefficient")
        verification = _A160._semantic_gate(
            template=template,
            variant=variant,
            positions=positions,
            original=polynomials,
            shifted=shifted,
            shift=shift,
        )
        gates.append(
            {
                "shift": shift,
                "shift_hex": f"0x{shift:06x}",
                "shifted_R2_polynomial_state_sha256": _SYMBOLIC._poly_hash(shifted, WINDOW_BITS),
                "coefficient_incidence": _A160._coefficient_counts(shifted),
                "per_coordinate_quadratic_terms_unchanged": True,
                "verification": verification,
            }
        )
    return gates


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_order_weighted_affine_gauge_reader",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "order_count": len(_A158.ORDER_NAMES),
            "weight_modes": list(WEIGHT_MODES),
            "shift_domain_size": 1 << WINDOW_BITS,
        },
    )
    ids = [
        "shake128-a161-gauge-by-order-interaction",
        "shake128-a162-order-weighted-walsh-objectives",
        "shake128-a162-eight-complete-gauge-landscapes",
        "shake128-a162-selected-gauge-semantic-gates",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A161:fixed_resource_affine_gauge_solver_frontier",
        mechanism="hash_gate_the_observed_nonuniform_gauge_by_order_traversal_interaction",
        outcome="A162:order_weighted_affine_gauge_requirement",
        confidence=1.0,
        evidence_kind="retained_fixed_resource_factorial_intervention",
        source=A161_SHA256,
        attrs={"A161_gate": payload["anchor_gates"]["A161"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A162:order_weighted_affine_gauge_requirement",
        mechanism="assign_canonical_front_or_back_linear_position_weights_to_each_frozen_A158_order",
        outcome="A162:eight_assignment_free_weighted_Walsh_objectives",
        confidence=1.0,
        evidence_kind="predeclared_order_position_weight_rules",
        source=payload["objective_plan_sha256"],
        provenance=[ids[0]],
        attrs={"objective_plan": payload["objective_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A162:eight_assignment_free_weighted_Walsh_objectives",
        mechanism="evaluate_every_2_power_24_shift_for_each_objective_with_exact_integer_FWHT",
        outcome="A162:eight_globally_optimal_order_weighted_gauges",
        confidence=1.0,
        evidence_kind="complete_domain_transforms_tie_counts_and_parseval_certificates",
        source=payload["landscape_plan_sha256"],
        provenance=[ids[1]],
        attrs={
            "landscapes": payload["landscapes"],
            "unique_selected_shifts": payload["unique_selected_shifts"],
        },
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A162:eight_globally_optimal_order_weighted_gauges",
        mechanism="substitute_every_unique_selected_shift_and_compare_original_shifted_and_independent_bitsliced_R2_states",
        outcome="A162:exact_order_specific_gauge_plan_for_fixed_resource_transfer",
        confidence=1.0,
        evidence_kind="three_way_semantic_gates_for_all_unique_selected_shifts",
        source=payload["semantic_gate_plan_sha256"],
        provenance=[ids[2]],
        attrs={
            "semantic_gates": payload["semantic_gates"],
            "next_mechanism": payload["next_mechanism"],
        },
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids] != [[], [ids[0]], [ids[1]], [ids[2]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A162 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def analyze(results_dir: Path) -> dict[str, Any]:
    a160, a161 = _load_anchor_gates(results_dir)
    baseline = _A159.analyze(results_dir)
    orders = {name: baseline["orders"][name] for name in _A158.ORDER_NAMES}
    variant = _BASE.VARIANTS["shake128"]
    template, positions, instance = _A154._structural_instance(variant)
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, positions, 2)
    if _SYMBOLIC._poly_hash(polynomials, WINDOW_BITS) != _A160.ORIGINAL_R2_POLYNOMIAL_SHA256:
        raise RuntimeError("A162 original R2 polynomial state differs")
    unweighted_terms, unweighted_spectrum, term_hash = _A160._linear_affine_terms(
        polynomials, WINDOW_BITS
    )
    if (
        term_hash != a160["walsh_objective"]["quadratic_neighbor_term_sha256"]
        or _sha256(unweighted_spectrum.astype("<i4", copy=False).tobytes())
        != a160["walsh_objective"]["coefficient_spectrum_sha256"]
    ):
        raise RuntimeError("A162 unweighted Walsh anchor differs from A160")
    terms = _coordinate_terms(polynomials, WINDOW_BITS)
    if [(neighbors, linear) for _, neighbors, linear in terms] != unweighted_terms:
        raise RuntimeError("A162 coordinate terms differ from A160 ordering")

    objective_plan = [
        {
            "name": f"{order_name}__{mode}",
            "order_name": order_name,
            "weight_mode": mode,
            "variable_to_input_coordinate": orders[order_name],
            "solver_position_weights": (
                list(range(WINDOW_BITS, 0, -1))
                if mode == "front_loaded_declaration_position"
                else list(range(1, WINDOW_BITS + 1))
            ),
        }
        for order_name in _A158.ORDER_NAMES
        for mode in WEIGHT_MODES
    ]
    landscapes = [
        _landscape(
            terms=terms,
            polynomials=polynomials,
            order_name=row["order_name"],
            order=row["variable_to_input_coordinate"],
            mode=row["weight_mode"],
        )
        for row in objective_plan
    ]
    semantic_gates = _semantic_gates(
        polynomials=polynomials,
        landscapes=landscapes,
        template=template,
        variant=variant,
        positions=positions,
    )
    unique_shifts = sorted({row["minimum_shift"] for row in landscapes})
    return {
        "anchors": (a160, a161),
        "instance": instance,
        "orders": orders,
        "objective_plan": objective_plan,
        "objective_plan_sha256": _canonical_sha256(objective_plan),
        "landscapes": landscapes,
        "landscape_plan_sha256": _canonical_sha256(landscapes),
        "unique_selected_shifts": [
            {"shift": shift, "shift_hex": f"0x{shift:06x}"} for shift in unique_shifts
        ],
        "semantic_gates": semantic_gates,
        "semantic_gate_plan_sha256": _canonical_sha256(semantic_gates),
    }


def run(results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    a160, a161 = analysis.pop("anchors")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_ORDER_WEIGHTED_AFFINE_GAUGE_LANDSCAPES_RETAINED",
        "result": (
            "Eight complete 2^24 integer Walsh transforms produce globally optimal "
            "front- and back-loaded affine gauges for each frozen A158 order."
        ),
        "scope": (
            "The exact A155 SHAKE128 width-24 R2 polynomial interface and four A158 "
            "input orders; target bits, assignments and solver counters are excluded "
            "from every objective and gauge selection."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "state_output_bits": STATE_BITS,
            "order_count": len(_A158.ORDER_NAMES),
            "weight_modes": list(WEIGHT_MODES),
            "landscape_count": len(_A158.ORDER_NAMES) * len(WEIGHT_MODES),
            "shift_domain_size_per_landscape": 1 << WINDOW_BITS,
            "target_rate_input_used": False,
            "solver_observations_used_in_objective": False,
            "instrumented_assignment_used": False,
        },
        "anchor_gates": {
            "A160": {
                "artifact_sha256": A160_SHA256,
                "unweighted_minimum_shift": a160["global_optimum"]["minimum_shift"],
                "coefficient_spectrum_sha256": a160["walsh_objective"][
                    "coefficient_spectrum_sha256"
                ],
            },
            "A161": {
                "artifact_sha256": A161_SHA256,
                "formula_plan_sha256": a161["formula_plan_sha256"],
                "status_counts": a161["status_counts"],
                "solver_counters_used_in_objective": False,
            },
        },
        **analysis,
        "next_mechanism": {
            "operation": "compile_all_eight_predeclared_order_specific_gauges_and_execute_under_the_A159_fixed_resource_protocol",
            "reason": (
                "A161 shows that one unweighted gauge acts nonuniformly across orders. "
                "A162 now supplies exact order-position-aligned gauges for a direct "
                "factorial transfer without using a target, assignment or solver "
                "counter in their construction."
            ),
            "A161_decision_ranking_used_to_select_a_gauge": False,
        },
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A162 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "landscape_count": len(payload["landscapes"]),
        "unique_selected_shifts": payload["unique_selected_shifts"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                args.results_dir.resolve(),
                args.output.resolve(),
                args.causal_output.resolve(),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
