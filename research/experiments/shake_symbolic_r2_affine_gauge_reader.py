#!/usr/bin/env python3
"""Find the exact affine input shift minimizing SHAKE R2 linear incidence."""

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


_A155 = _import_sibling(
    "shake_symbolic_r2_pivot_basis_reader.py",
    "shake_symbolic_r2_affine_gauge_a155_base",
)

_A154 = _A155._A154
_BASE = _A155._BASE
_SYMBOLIC = _A155._SYMBOLIC
_BITSLICED = _A155._BITSLICED
_PREFIX = _A155._PREFIX

ATTEMPT_ID = "A160"
SCHEMA = "shake-symbolic-r2-affine-gauge-reader-v1"
WINDOW_BITS = _A155.WINDOW_BITS
STATE_BITS = _A155.STATE_BITS
SEED = _A155.SEED
A155_FILENAME = _A155.RESULT_FILENAME
A155_SHA256 = "ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80"
A154_FILENAME = _A155.A154_FILENAME
A154_SHA256 = _A155.A154_SHA256
ORIGINAL_R2_POLYNOMIAL_SHA256 = "d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752"
RESULT_FILENAME = "shake_symbolic_r2_affine_gauge_reader_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_affine_gauge_reader_v1.causal"


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
    a155_path = results_dir / A155_FILENAME
    raw = a155_path.read_bytes()
    observed = _sha256(raw)
    a155 = json.loads(raw)
    if (
        observed != A155_SHA256
        or a155.get("schema") != _A155.SCHEMA
        or a155.get("original_R2", {}).get("polynomial_state_sha256")
        != ORIGINAL_R2_POLYNOMIAL_SHA256
        or a155.get("original_R2", {}).get("global_monomial_count") != 301
        or a155.get("original_R2", {}).get("quadratic_monomial_count") != 276
        or a155.get("complete_graph_proof", {}).get("graph") != "K24"
        or a155.get("complete_graph_proof", {}).get("minimum_vertex_cover_size") != 23
    ):
        raise RuntimeError("A155 exact R2 anchor gate failed")
    a154, a154_gate = _A155._load_a154_gate(results_dir / A154_FILENAME)
    if a154_gate["artifact_sha256"] != A154_SHA256:
        raise RuntimeError("A154 affine-basis anchor gate failed")
    gate = {
        "A155": {
            "artifact": A155_FILENAME,
            "artifact_sha256": observed,
            "schema": a155["schema"],
            "original_R2_polynomial_state_sha256": ORIGINAL_R2_POLYNOMIAL_SHA256,
            "quadratic_graph": a155["complete_graph_proof"]["graph"],
            "target_rate_imported": False,
            "solver_observations_imported": False,
            "instrumented_assignment_imported": False,
        },
        "A154": a154_gate,
    }
    return a154, gate


def _linear_affine_terms(
    polynomials: Sequence[frozenset[int]], width: int
) -> tuple[list[tuple[int, int]], np.ndarray, str]:
    """Return (quadratic-neighbor mask, linear bit) for every output/input pair."""
    terms: list[tuple[int, int]] = []
    spectrum = np.zeros(1 << width, dtype=np.int32)
    encoded = bytearray()
    for polynomial in polynomials:
        for coordinate in range(width):
            linear = int((1 << coordinate) in polynomial)
            neighbors = 0
            for other in range(width):
                if other == coordinate:
                    continue
                pair = (1 << coordinate) | (1 << other)
                if pair in polynomial:
                    neighbors |= 1 << other
            terms.append((neighbors, linear))
            spectrum[neighbors] += 1 if linear == 0 else -1
            encoded.extend(neighbors.to_bytes(3, "little"))
            encoded.append(linear)
    expected = len(polynomials) * width
    if len(terms) != expected or int(spectrum.sum()) != sum(
        1 if linear == 0 else -1 for _, linear in terms
    ):
        raise RuntimeError("linear-affine term construction failed")
    return terms, spectrum, _sha256(bytes(encoded))


def _fwht(values: np.ndarray) -> np.ndarray:
    """Unnormalized exact Walsh-Hadamard transform in lexicographic mask order."""
    if values.dtype != np.int32 or values.ndim != 1 or values.size & (values.size - 1):
        raise ValueError("FWHT input must be a one-dimensional power-of-two int32 array")
    transformed = values.copy()
    step = 1
    while step < transformed.size:
        blocks = transformed.reshape(-1, 2 * step)
        left = blocks[:, :step].copy()
        right = blocks[:, step:]
        blocks[:, :step] = left + right
        blocks[:, step:] = left - right
        step *= 2
    return transformed


def _linear_incidence(terms: Sequence[tuple[int, int]], shift: int) -> int:
    return sum(linear ^ ((neighbors & shift).bit_count() & 1) for neighbors, linear in terms)


def _score_energy(values: np.ndarray) -> int:
    total = 0
    block_size = 1 << 20
    for start in range(0, values.size, block_size):
        block = values[start : start + block_size].astype(np.int64)
        total += int(np.dot(block, block))
    return total


def _systematic_constant_shift(a154: dict[str, Any]) -> int:
    basis = a154["basis"]
    pivot_to_input = list(map(int, basis["pivot_delta_to_input_coordinate"]))
    constants = list(map(int, basis["selected_output_constants"]))
    if (
        len(pivot_to_input) != WINDOW_BITS
        or len(constants) != WINDOW_BITS
        or sorted(pivot_to_input) != list(range(WINDOW_BITS))
        or any(value not in (0, 1) for value in constants)
    ):
        raise RuntimeError("A154 systematic constant map differs")
    shift = 0
    for pivot_coordinate, input_coordinate in enumerate(pivot_to_input):
        shift |= constants[pivot_coordinate] << input_coordinate
    return shift


def _shift_polynomials(
    polynomials: Sequence[frozenset[int]], shift: int, width: int
) -> list[frozenset[int]]:
    variables = [
        frozenset({1 << coordinate, 0})
        if (shift >> coordinate) & 1
        else frozenset({1 << coordinate})
        for coordinate in range(width)
    ]
    monomial_cache: dict[int, frozenset[int]] = {0: _SYMBOLIC.ONE}

    def shifted_monomial(mask: int) -> frozenset[int]:
        cached = monomial_cache.get(mask)
        if cached is not None:
            return cached
        value = _SYMBOLIC.ONE
        for coordinate in range(width):
            if (mask >> coordinate) & 1:
                value = _SYMBOLIC._poly_mul(value, variables[coordinate])
        monomial_cache[mask] = value
        return value

    return [
        _SYMBOLIC._poly_xor(*(shifted_monomial(mask) for mask in polynomial))
        for polynomial in polynomials
    ]


def _coefficient_counts(polynomials: Sequence[frozenset[int]]) -> dict[str, int]:
    counts = {"constant": 0, "linear": 0, "quadratic": 0}
    for polynomial in polynomials:
        for mask in polynomial:
            degree = mask.bit_count()
            if degree == 0:
                counts["constant"] += 1
            elif degree == 1:
                counts["linear"] += 1
            elif degree == 2:
                counts["quadratic"] += 1
            else:
                raise RuntimeError("R2 affine shift unexpectedly changed algebraic degree")
    return counts


def _semantic_gate(
    *,
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    original: list[frozenset[int]],
    shifted: list[frozenset[int]],
    shift: int,
) -> dict[str, Any]:
    shifted_assignments = _A154._deterministic_assignments(WINDOW_BITS)
    input_assignments = [value ^ shift for value in shifted_assignments]
    injected = _SYMBOLIC._inject_assignments(template, variant, positions, input_assignments)
    state = _BITSLICED._scalar_to_bitsliced(injected)
    state = _PREFIX._keccak_round_bitsliced(state, 0)
    state = _PREFIX._keccak_round_bitsliced(state, 1)
    concrete = _BITSLICED._bitsliced_to_scalar(state, len(input_assignments))
    original_symbolic = _SYMBOLIC._evaluate_symbolic(original, input_assignments, WINDOW_BITS)
    shifted_symbolic = _SYMBOLIC._evaluate_symbolic(shifted, shifted_assignments, WINDOW_BITS)
    if not (
        np.array_equal(original_symbolic, concrete) and np.array_equal(shifted_symbolic, concrete)
    ):
        raise RuntimeError("optimal affine gauge differs from independent Keccak rounds")
    return {
        "shifted_assignments_checked": len(shifted_assignments),
        "input_assignments_checked": len(input_assignments),
        "state_bits_checked_per_representation": len(input_assignments) * STATE_BITS,
        "three_way_state_bits_checked": 3 * len(input_assignments) * STATE_BITS,
        "shifted_assignment_sha256": _sha256(
            b"".join(value.to_bytes(3, "little") for value in shifted_assignments)
        ),
        "mapped_input_assignment_sha256": _sha256(
            b"".join(value.to_bytes(3, "little") for value in input_assignments)
        ),
        "r2_state_sha256": _sha256(concrete.astype("<u8", copy=False).tobytes()),
        "original_symbolic_equals_independent_bitsliced_rounds": True,
        "shifted_symbolic_equals_independent_bitsliced_rounds": True,
        "target_rate_input_used": False,
        "instrumented_assignment_input_used": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_affine_gauge_reader",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "shift_domain_size": 1 << WINDOW_BITS,
            "target_rate_input_used": False,
        },
    )
    ids = [
        "shake128-a155-exact-r2-complete-interaction",
        "shake128-a160-linear-incidence-walsh-objective",
        "shake128-a160-exhaustive-affine-gauge-optimum",
        "shake128-a160-optimal-gauge-semantic-gate",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A155:exact_R2_degree_two_interface_with_K24_interaction_graph",
        mechanism="hash_gate_the_complete_1600_coordinate_R2_polynomial_state",
        outcome="A160:fixed_assignment_free_R2_affine_shift_problem",
        confidence=1.0,
        evidence_kind="retained_artifact_and_polynomial_state_hashes",
        source=A155_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A160:fixed_assignment_free_R2_affine_shift_problem",
        mechanism="group_all_38400_shifted_linear_coefficients_by_their_exact_quadratic_neighbor_mask",
        outcome="A160:24_variable_Walsh_objective",
        confidence=1.0,
        evidence_kind="exact_boolean_ring_coefficient_spectrum",
        source=payload["walsh_objective"]["coefficient_spectrum_sha256"],
        provenance=[ids[0]],
        attrs={"walsh_objective": payload["walsh_objective"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A160:24_variable_Walsh_objective",
        mechanism="evaluate_all_2_power_24_affine_shifts_with_an_exact_integer_FWHT",
        outcome="A160:globally_minimal_R2_linear_incidence_gauge",
        confidence=1.0,
        evidence_kind="complete_domain_transform_and_parseval_certificate",
        source=payload["global_optimum"]["walsh_score_vector_sha256"],
        provenance=[ids[1]],
        attrs={"global_optimum": payload["global_optimum"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A160:globally_minimal_R2_linear_incidence_gauge",
        mechanism="substitute_the_selected_shift_and_compare_symbolic_original_symbolic_shifted_and_bitsliced_R2_states",
        outcome="A160:exact_semantics_preserving_affine_gauge_for_fullround_transfer",
        confidence=1.0,
        evidence_kind="three_way_independent_state_gate",
        source=payload["shifted_R2"]["polynomial_state_sha256"],
        provenance=[ids[2]],
        attrs={
            "shifted_R2": payload["shifted_R2"],
            "verification": payload["verification"],
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
        raise RuntimeError("A160 Causal provenance chain failed validation")
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
    a154, anchor_gates = _load_anchor_gates(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    template, positions, instance = _A154._structural_instance(variant)
    original = _A155._R1._SPLIT._symbolic_prefix_polynomials(template, variant, positions, 2)
    original_hash = _SYMBOLIC._poly_hash(original, WINDOW_BITS)
    if original_hash != ORIGINAL_R2_POLYNOMIAL_SHA256:
        raise RuntimeError("A160 regenerated R2 polynomial state differs")

    terms, coefficients, term_hash = _linear_affine_terms(original, WINDOW_BITS)
    scores = _fwht(coefficients)
    total_terms = len(terms)
    minimum_mask = int(np.argmax(scores))
    maximum_mask = int(np.argmin(scores))
    maximum_score = int(scores[minimum_mask])
    minimum_score = int(scores[maximum_mask])
    minimum_incidence = (total_terms - maximum_score) // 2
    maximum_incidence = (total_terms - minimum_score) // 2
    if (
        total_terms - maximum_score & 1
        or total_terms - minimum_score & 1
        or _linear_incidence(terms, minimum_mask) != minimum_incidence
        or _linear_incidence(terms, maximum_mask) != maximum_incidence
    ):
        raise RuntimeError("Walsh optimum does not match direct incidence evaluation")

    check_masks = sorted(
        set(
            _A154._deterministic_assignments(WINDOW_BITS)
            + [0, minimum_mask, maximum_mask, (1 << WINDOW_BITS) - 1]
        )
    )
    direct_checks = []
    for mask in check_masks:
        incidence = _linear_incidence(terms, mask)
        walsh_incidence = (total_terms - int(scores[mask])) // 2
        if incidence != walsh_incidence:
            raise RuntimeError(f"Walsh/direct mismatch at affine shift {mask}")
        direct_checks.append([mask, incidence])

    coefficient_energy = _score_energy(coefficients)
    score_energy = _score_energy(scores)
    expected_score_energy = coefficients.size * coefficient_energy
    if score_energy != expected_score_energy:
        raise RuntimeError("Walsh Parseval certificate failed")

    baseline_incidence = _linear_incidence(terms, 0)
    systematic_shift = _systematic_constant_shift(a154)
    systematic_incidence = _linear_incidence(terms, systematic_shift)
    shifted = _shift_polynomials(original, minimum_mask, WINDOW_BITS)
    original_counts = _coefficient_counts(original)
    shifted_counts = _coefficient_counts(shifted)
    original_quadratics = [
        frozenset(mask for mask in polynomial if mask.bit_count() == 2) for polynomial in original
    ]
    shifted_quadratics = [
        frozenset(mask for mask in polynomial if mask.bit_count() == 2) for polynomial in shifted
    ]
    if (
        original_counts["linear"] != baseline_incidence
        or shifted_counts["linear"] != minimum_incidence
        or original_quadratics != shifted_quadratics
    ):
        raise RuntimeError("affine shift coefficient accounting failed")
    shifted_stats = _A155._polynomial_statistics(shifted, WINDOW_BITS)
    verification = _semantic_gate(
        template=template,
        variant=variant,
        positions=positions,
        original=original,
        shifted=shifted,
        shift=minimum_mask,
    )

    coefficient_raw = coefficients.astype("<i4", copy=False).tobytes()
    score_raw = scores.astype("<i4", copy=False).tobytes()
    walsh_objective = {
        "objective": "total_linear_coefficient_incidence_across_1600_shifted_R2_coordinates",
        "affine_shift_rule": "x_i_equals_y_i_XOR_shift_i",
        "output_coordinates": len(original),
        "input_coordinates": WINDOW_BITS,
        "linear_coefficient_positions": total_terms,
        "shift_domain_size": 1 << WINDOW_BITS,
        "quadratic_neighbor_term_sha256": term_hash,
        "coefficient_spectrum_nonzero_bins": int(np.count_nonzero(coefficients)),
        "coefficient_spectrum_sha256": _sha256(coefficient_raw),
        "coefficient_spectrum_energy": coefficient_energy,
        "walsh_parseval_expected_score_energy": expected_score_energy,
        "walsh_parseval_observed_score_energy": score_energy,
        "walsh_parseval_verified": True,
        "direct_check_count": len(direct_checks),
        "direct_checks_sha256": _canonical_sha256(direct_checks),
        "target_rate_input_used": False,
        "solver_observations_used": False,
        "instrumented_assignment_used": False,
    }
    global_optimum = {
        "selection_rule": "lexicographically_smallest_shift_with_maximal_Walsh_score",
        "minimum_linear_incidence": minimum_incidence,
        "minimum_shift": minimum_mask,
        "minimum_shift_hex": f"0x{minimum_mask:06x}",
        "minimum_shift_hamming_weight": minimum_mask.bit_count(),
        "minimum_tie_count": int(np.count_nonzero(scores == maximum_score)),
        "maximum_walsh_score": maximum_score,
        "maximum_linear_incidence": maximum_incidence,
        "lexicographically_smallest_maximum_shift": maximum_mask,
        "lexicographically_smallest_maximum_shift_hex": f"0x{maximum_mask:06x}",
        "maximum_tie_count": int(np.count_nonzero(scores == minimum_score)),
        "minimum_walsh_score": minimum_score,
        "zero_shift_linear_incidence": baseline_incidence,
        "systematic_R1_constant_shift": systematic_shift,
        "systematic_R1_constant_shift_hex": f"0x{systematic_shift:06x}",
        "systematic_R1_constant_shift_linear_incidence": systematic_incidence,
        "linear_incidence_removed_from_zero_shift": baseline_incidence - minimum_incidence,
        "relative_linear_incidence_reduction_from_zero_shift": (
            baseline_incidence - minimum_incidence
        )
        / baseline_incidence,
        "walsh_score_vector_sha256": _sha256(score_raw),
        "complete_shift_domain_evaluated": True,
        "global_optimum_certified": True,
    }
    shifted_R2 = {
        **shifted_stats,
        "constant_coefficient_incidence": shifted_counts["constant"],
        "linear_coefficient_incidence": shifted_counts["linear"],
        "quadratic_coefficient_incidence": shifted_counts["quadratic"],
        "original_constant_coefficient_incidence": original_counts["constant"],
        "original_linear_coefficient_incidence": original_counts["linear"],
        "original_quadratic_coefficient_incidence": original_counts["quadratic"],
        "per_coordinate_quadratic_terms_unchanged": True,
    }
    return {
        "anchor_gates": anchor_gates,
        "instance": instance,
        "original_R2_polynomial_state_sha256": original_hash,
        "walsh_objective": walsh_objective,
        "global_optimum": global_optimum,
        "shifted_R2": shifted_R2,
        "verification": verification,
    }


def run(results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    optimum = analysis["global_optimum"]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_GLOBAL_R2_AFFINE_GAUGE_RETAINED",
        "result": (
            f"An exact integer Walsh transform evaluates all {1 << WINDOW_BITS:,} "
            "affine input shifts and certifies the lexicographically first global "
            f"minimum at {optimum['minimum_shift_hex']}, reducing total R2 linear "
            f"coefficient incidence from {optimum['zero_shift_linear_incidence']:,} "
            f"to {optimum['minimum_linear_incidence']:,} while preserving every "
            "per-coordinate quadratic coefficient."
        ),
        "scope": (
            "The exact A155 SHAKE128 width-24 R2 polynomial interface over all 1,600 "
            "state coordinates; no target-rate bit, solver observation, model, or "
            "instrumented assignment participates in the objective or selection."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "state_output_bits": STATE_BITS,
            "symbolic_prefix_rounds": 2,
            "target_rate_input_used": False,
            "solver_observations_used": False,
            "instrumented_assignment_used": False,
        },
        **analysis,
        "next_mechanism": {
            "operation": "compile_the_exact_minimum_incidence_affine_gauge_into_each_A158_weighted_order_and_replay_under_A159_fixed_rlimit",
            "reason": (
                "Affine shifts preserve the exact quadratic R2 interface but alter "
                "linear incidence and solver polarity. A160 supplies a globally "
                "optimal assignment-free gauge, so its full-round effect can be "
                "isolated without another heuristic order search."
            ),
            "formula_order_search_selected": False,
            "assignment_derived_polarity_selected": False,
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
        raise RuntimeError("A160 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "minimum_shift": optimum["minimum_shift"],
        "minimum_shift_hex": optimum["minimum_shift_hex"],
        "minimum_linear_incidence": optimum["minimum_linear_incidence"],
        "linear_incidence_removed": optimum["linear_incidence_removed_from_zero_shift"],
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
