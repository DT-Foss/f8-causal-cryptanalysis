#!/usr/bin/env python3
"""Exact symbolic ANF compiler for pre-saturation SHAKE round interfaces."""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_CASCADE_PATH = Path(__file__).with_name("shake_anf_compression_cascade.py")
_CASCADE_SPEC = importlib.util.spec_from_file_location(
    "shake_anf_compression_cascade_symbolic_base", _CASCADE_PATH
)
assert _CASCADE_SPEC is not None and _CASCADE_SPEC.loader is not None
_CASCADE = importlib.util.module_from_spec(_CASCADE_SPEC)
sys.modules[_CASCADE_SPEC.name] = _CASCADE
_CASCADE_SPEC.loader.exec_module(_CASCADE)

_ANF = _CASCADE._ANF
_BASE = _CASCADE._BASE
_BITSLICED = _CASCADE._BITSLICED
_PREFIX = _CASCADE._PREFIX
_WINDOW = _CASCADE._WINDOW
STATE_COORDINATES = 1600
ZERO: frozenset[int] = frozenset()
ONE: frozenset[int] = frozenset({0})
Poly = frozenset[int]

_EXPECTED_K16 = {
    "SHAKE128": {
        0: (
            "7b66b35d858bb068d3f345a0675c46e236656270d70f9bae099c50f32c52e6b1",
            "e6427114858958fbbc5940f60c19d90d8d7b67a0da14441a1cd97110fe75c215",
        ),
        1: (
            "9a0ab13b94a7c6e8e1b44df9e8269a92366801fc9e115054c9cd9353f165feea",
            "37571f904371e13d9be0cec3dd8441878b63623a25c10049e11b826c374ecfc3",
        ),
        2: (
            "0cee740da08a8dd2db9b524c962635c4714058405a38c56a7ec74c5d882f02ac",
            "598669f9f9c2d9975c9a5f5aa9b3f0e8c69f5fa304fc0ab33760448b8c867126",
        ),
    },
    "SHAKE256": {
        0: (
            "7b66b35d858bb068d3f345a0675c46e236656270d70f9bae099c50f32c52e6b1",
            "a7440bf6f2c44b81b7eca7d926baf68cab9bfc350d896418490ddd2c3b327434",
        ),
        1: (
            "9a0ab13b94a7c6e8e1b44df9e8269a92366801fc9e115054c9cd9353f165feea",
            "3962478ab8efa6327e4ca4eec8da024c60a4683188c82b44264ac82c73f10048",
        ),
        2: (
            "a119a0cb66a71d2adbaaf8233e0073ba26e62b7b961e5f7b4dfb52320b0c8a31",
            "34258a068cc43e0b2b905898950a6f2d6549493adcb2256f557464a351721eb0",
        ),
    },
}


def _poly_xor(*polynomials: Poly) -> Poly:
    result: set[int] = set()
    for polynomial in polynomials:
        result.symmetric_difference_update(polynomial)
    return frozenset(result)


@functools.lru_cache(maxsize=65_536)
def _poly_mul(first: Poly, second: Poly) -> Poly:
    if not first or not second:
        return ZERO
    if first == ONE:
        return second
    if second == ONE:
        return first
    if first == second:
        return first
    result: set[int] = set()
    for left in first:
        for right in second:
            monomial = left | right
            if monomial in result:
                result.remove(monomial)
            else:
                result.add(monomial)
    return frozenset(result)


def _symbolic_round(state: list[Poly], round_constant: int) -> list[Poly]:
    if len(state) != STATE_COORDINATES:
        raise ValueError("symbolic Keccak state must have 1,600 coordinates")
    columns = [ZERO] * 320
    for x in range(5):
        for bit in range(64):
            columns[x * 64 + bit] = _poly_xor(
                *(state[(x + 5 * y) * 64 + bit] for y in range(5))
            )
    theta_delta = [ZERO] * 320
    for x in range(5):
        for bit in range(64):
            theta_delta[x * 64 + bit] = _poly_xor(
                columns[((x - 1) % 5) * 64 + bit],
                columns[((x + 1) % 5) * 64 + ((bit - 1) % 64)],
            )
    theta = [ZERO] * STATE_COORDINATES
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            for bit in range(64):
                theta[lane * 64 + bit] = _poly_xor(
                    state[lane * 64 + bit], theta_delta[x * 64 + bit]
                )
    rho_pi = [ZERO] * STATE_COORDINATES
    for x in range(5):
        for y in range(5):
            source = x + 5 * y
            destination = y + 5 * ((2 * x + 3 * y) % 5)
            rotation = int(_BASE.ROTATION_OFFSETS[x, y])
            for bit in range(64):
                rho_pi[destination * 64 + bit] = theta[
                    source * 64 + ((bit - rotation) % 64)
                ]
    output = [ZERO] * STATE_COORDINATES
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            next_lane = ((x + 1) % 5) + 5 * y
            next2_lane = ((x + 2) % 5) + 5 * y
            for bit in range(64):
                value = _poly_xor(
                    rho_pi[lane * 64 + bit],
                    rho_pi[next2_lane * 64 + bit],
                    _poly_mul(
                        rho_pi[next_lane * 64 + bit],
                        rho_pi[next2_lane * 64 + bit],
                    ),
                )
                if lane == 0 and ((round_constant >> bit) & 1):
                    value = _poly_xor(value, ONE)
                output[lane * 64 + bit] = value
    return output


def _initial_symbolic_state(
    template: np.ndarray, variant: Any, positions: np.ndarray
) -> list[Poly]:
    position_to_variable = {
        int(position): variable for variable, position in enumerate(positions)
    }
    state: list[Poly] = []
    for lane in range(25):
        lane_value = int(template[0, lane])
        for bit in range(64):
            capacity_coordinate = (
                (lane - variant.rate_lanes) * 64 + bit
                if lane >= variant.rate_lanes
                else -1
            )
            variable = position_to_variable.get(capacity_coordinate)
            if variable is not None:
                state.append(frozenset({1 << variable}))
            else:
                state.append(ONE if ((lane_value >> bit) & 1) else ZERO)
    return state


def _basis_and_matrix(polynomials: list[Poly]) -> tuple[np.ndarray, bytes]:
    basis = np.array(sorted(set().union(*polynomials)), dtype="<u4")
    index = {int(mask): row for row, mask in enumerate(basis)}
    matrix = np.zeros((len(basis), STATE_COORDINATES), dtype=np.uint8)
    for coordinate, polynomial in enumerate(polynomials):
        for mask in polynomial:
            matrix[index[mask], coordinate] = 1
    return basis, np.packbits(matrix, axis=1, bitorder="little").tobytes()


def _k16_cross_gate(
    variant: Any, traces: list[list[Poly]]
) -> dict[str, Any]:
    observations = []
    for round_number, polynomials in enumerate(traces):
        basis, matrix = _basis_and_matrix(polynomials)
        basis_sha = hashlib.sha256(basis.tobytes()).hexdigest()
        matrix_sha = hashlib.sha256(matrix).hexdigest()
        expected_basis, expected_matrix = _EXPECTED_K16[variant.name][round_number]
        observations.append(
            {
                "round": round_number,
                "basis_sha256": basis_sha,
                "expected_basis_sha256": expected_basis,
                "matrix_sha256": matrix_sha,
                "expected_matrix_sha256": expected_matrix,
                "exact_match": basis_sha == expected_basis
                and matrix_sha == expected_matrix,
            }
        )
    if not all(item["exact_match"] for item in observations):
        raise RuntimeError("symbolic/exhaustive ANF cross-gate failed")
    return {
        "source": "A133_complete_2^16_Mobius_artifacts",
        "rounds": observations,
        "exact_match": True,
    }


def _inject_assignments(
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    assignments: list[int],
) -> np.ndarray:
    states = np.repeat(template, len(assignments), axis=0)
    for variable, position in enumerate(positions):
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        for row, assignment in enumerate(assignments):
            if (assignment >> variable) & 1:
                states[row, lane] |= np.uint64(1) << np.uint64(bit)
    return states


def _evaluate_symbolic(
    polynomials: list[Poly], assignments: list[int], window_bits: int
) -> np.ndarray:
    states = np.zeros((len(assignments), 25), dtype=np.uint64)
    full_assignment = (1 << window_bits) - 1
    for coordinate, polynomial in enumerate(polynomials):
        lane, bit = divmod(coordinate, 64)
        for row, assignment in enumerate(assignments):
            if assignment == 0:
                value = int(0 in polynomial)
            elif assignment == full_assignment:
                value = len(polynomial) & 1
            else:
                value = sum((mask & ~assignment) == 0 for mask in polynomial) & 1
            states[row, lane] |= np.uint64(value) << np.uint64(bit)
    return states


def _assignment_gate(
    polynomials: list[Poly],
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    seed: int,
    samples: int,
) -> dict[str, Any]:
    window_bits = len(positions)
    rng = np.random.default_rng(seed)
    mask = (1 << window_bits) - 1
    assignments = [0, mask]
    while len(assignments) < samples:
        value = int.from_bytes(rng.bytes((window_bits + 7) // 8), "little") & mask
        if value not in assignments:
            assignments.append(value)
    inputs = _inject_assignments(template, variant, positions, assignments)
    planes = _BITSLICED._scalar_to_bitsliced(inputs)
    for round_number in range(2):
        planes = _PREFIX._keccak_round_bitsliced(planes, round_number)
    expected = _BITSLICED._bitsliced_to_scalar(planes, len(assignments))
    if window_bits <= 64:
        observed = _evaluate_symbolic(polynomials, assignments, window_bits)
        exact = np.array_equal(observed, expected)
        full_state_assignments = len(assignments)
        random_coordinates: list[int] = []
        checked = len(assignments) * STATE_COORDINATES
    else:
        observed = _evaluate_symbolic(polynomials, assignments[:2], window_bits)
        exact = np.array_equal(observed, expected[:2])
        full_state_assignments = 2
        random_coordinates = sorted(
            int(value)
            for value in rng.choice(STATE_COORDINATES, size=64, replace=False)
        )
        for row, assignment in enumerate(assignments[2:], start=2):
            for coordinate in random_coordinates:
                lane, bit = divmod(coordinate, 64)
                value = sum(
                    (mask & ~assignment) == 0
                    for mask in polynomials[coordinate]
                ) & 1
                exact &= value == ((int(expected[row, lane]) >> bit) & 1)
        checked = 2 * STATE_COORDINATES + max(0, len(assignments) - 2) * len(
            random_coordinates
        )
    if not exact:
        raise RuntimeError("symbolic assignment gate failed")
    return {
        "assignments_checked": len(assignments),
        "full_state_assignments_checked": full_state_assignments,
        "random_assignments_checked": len(assignments) - full_state_assignments,
        "random_state_coordinates": random_coordinates,
        "state_bits_checked": checked,
        "assignment_sha256": hashlib.sha256(
            b"".join(
                value.to_bytes((window_bits + 7) // 8, "little")
                for value in assignments
            )
        ).hexdigest(),
        "exact_match": True,
    }


def _poly_hash(polynomials: list[Poly], window_bits: int) -> str:
    mask_bytes = max(1, (window_bits + 7) // 8)
    digest = hashlib.sha256()
    for polynomial in polynomials:
        ordered = sorted(polynomial)
        digest.update(len(ordered).to_bytes(8, "little"))
        for mask in ordered:
            digest.update(mask.to_bytes(mask_bytes, "little"))
    return digest.hexdigest()


def _statistics(polynomials: list[Poly], window_bits: int, round_number: int) -> dict[str, Any]:
    total_coefficients = sum(len(polynomial) for polynomial in polynomials)
    interaction_edges: set[tuple[int, int]] = set()
    mask_bytes = max(1, (window_bits + 7) // 8)
    materialize_basis = window_bits <= 256
    if materialize_basis:
        union: set[int] | None = set().union(*polynomials)
        degree_source = union
        representation = "global_dictionary_plus_bitpacked_coordinate_matrix"
        symbolic_bytes = len(union) * (
            mask_bytes + STATE_COORDINATES // 8
        ) + 64
    else:
        union = None
        degree_source = (
            mask for polynomial in polynomials for mask in polynomial
        )
        representation = "coordinate_sparse_monomial_lists"
        symbolic_bytes = (
            total_coefficients * mask_bytes + (STATE_COORDINATES + 1) * 8 + 64
        )
    degree_histogram: dict[int, int] = {}
    maximum_degree = 0
    possible_edges = window_bits * (window_bits - 1) // 2
    for mask in degree_source:
        degree = mask.bit_count()
        maximum_degree = max(maximum_degree, degree)
        degree_histogram[degree] = degree_histogram.get(degree, 0) + 1
        if len(interaction_edges) < possible_edges:
            variables = []
            remaining = mask
            while remaining:
                least = remaining & -remaining
                variables.append(least.bit_length() - 1)
                remaining ^= least
            for left_index, left in enumerate(variables):
                for right in variables[left_index + 1 :]:
                    interaction_edges.add((left, right))
    raw_log2_bytes = window_bits + math.log2(STATE_COORDINATES / 8)
    return {
        "round": round_number,
        "basis_materialized": materialize_basis,
        "basis_monomials": len(union) if union is not None else None,
        "basis_degree_histogram": {
            str(degree): count for degree, count in sorted(degree_histogram.items())
        },
        "degree_histogram_kind": (
            "unique_global_monomials"
            if materialize_basis
            else "coordinate_coefficient_occurrences"
        ),
        "maximum_degree": maximum_degree,
        "total_coordinate_coefficients": total_coefficients,
        "mean_coefficients_per_coordinate": total_coefficients / STATE_COORDINATES,
        "maximum_coefficients_in_one_coordinate": max(map(len, polynomials)),
        "nonconstant_coordinates": sum(
            polynomial not in (ZERO, ONE) for polynomial in polynomials
        ),
        "monomial_primal_edges": len(interaction_edges),
        "possible_primal_edges": possible_edges,
        "complete_monomial_primal_graph": len(interaction_edges) == possible_edges,
        "symbolic_representation": representation,
        "symbolic_dictionary_mask_bytes": mask_bytes,
        "estimated_symbolic_bytes": symbolic_bytes,
        "raw_truth_space_bytes": str((1 << window_bits) * STATE_COORDINATES // 8),
        "log2_raw_to_symbolic_ratio": raw_log2_bytes - math.log2(symbolic_bytes),
        "polynomial_state_sha256": _poly_hash(polynomials, window_bits),
    }


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    assignment_samples: int,
) -> dict[str, Any]:
    _poly_mul.cache_clear()
    rng = np.random.default_rng(seed)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    positions = _WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xC05CADE
    )
    template = _WINDOW._clear_window(base_state, variant, positions)
    state0 = _initial_symbolic_state(template, variant, positions)
    state1 = _symbolic_round(state0, int(_BASE.ROUND_CONSTANTS[0]))
    state2 = _symbolic_round(state1, int(_BASE.ROUND_CONSTANTS[1]))
    traces = [state0, state1, state2]
    cross_gate = _k16_cross_gate(variant, traces) if window_bits == 16 else None
    samples = min(assignment_samples, 64)
    assignment_gate = _assignment_gate(
        state2,
        template,
        variant,
        positions,
        seed ^ 0xA5516E,
        samples,
    )
    cache = _poly_mul.cache_info()
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "symbolic_rounds": 2,
        "truth_table_assignments_materialized": 0,
        "cross_gate": cross_gate,
        "assignment_gate": assignment_gate,
        "multiplication_cache": {
            "hits": cache.hits,
            "misses": cache.misses,
            "current_size": cache.currsize,
        },
        "observations": [
            _statistics(polynomials, window_bits, round_number)
            for round_number, polynomials in enumerate(traces)
        ],
    }


def _build_graph(path: Path, window_bits: list[int], assignment_samples: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_anf_frontier",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "symbolic_rounds": 2,
            "assignment_samples": assignment_samples,
            "prediction_before_measurement": (
                "Direct compilation in the Boolean polynomial ring should retain "
                "the exact compact R2 interface without enumerating 2^k assignments, "
                "and should extend beyond the exhaustive 16-coordinate frontier."
            ),
        },
    )
    for key in _BASE.VARIANTS:
        compile_id = f"{key}-symbolic-boolean-ring-compiler"
        gate_id = f"{key}-symbolic-assignment-reader"
        builder.add_triplet(
            edge_id=compile_id,
            trigger=f"{key}:known_complement_plus_symbolic_capacity_coordinates",
            mechanism="exact_boolean_ring_theta_rho_pi_chi_iota_compilation",
            outcome=f"{key}:shared_R0_R1_R2_anf_formulas",
            confidence=1.0,
            evidence_kind="symbolic_equation_identity",
            source="GF2_idempotent_polynomial_ring",
            attrs={"truth_table_assignments_materialized": 0},
        )
        builder.add_triplet(
            edge_id=gate_id,
            trigger=f"{key}:shared_R2_anf_formulas",
            mechanism="reader_evaluate_symbolic_formulas_on_independent_assignments",
            outcome=f"{key}:exact_two_round_state_matches",
            confidence=1.0,
            evidence_kind="independent_bit_sliced_round_comparison",
            source="symbolic_assignment_reader",
            provenance=[compile_id],
            attrs={
                "reader_recipe": {
                    "ring": "GF2[x]/(x_i^2+x_i)",
                    "xor": "symmetric_difference",
                    "and": "pairwise_monomial_union_with_parity",
                    "rounds": 2,
                }
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-symbolic-width-frontier",
            trigger=f"{key}:exact_symbolic_R2_interfaces",
            mechanism="reader_count_shared_monomials_without_truth_table",
            outcome=f"{key}:symbolic_width_scaling_frontier",
            confidence=1.0,
            evidence_kind="complete_formula_sets",
            source="serialized_polynomial_state_hashes",
            provenance=[gate_id],
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE symbolic ANF causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="16,32,64,128")
    parser.add_argument("--assignment-samples", type=int, default=8)
    parser.add_argument("--seed", type=int, default=89806001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    widths = _ANF._AFFINE._parse_int_list(args.window_bits, 1, 512)
    if args.assignment_samples < 2 or args.assignment_samples > 64:
        raise ValueError("assignment sample count must be in 2..64")
    causal = _build_graph(args.causal_output, widths, args.assignment_samples)
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        for width_index, width in enumerate(widths):
            if width > variant.capacity_bits:
                continue
            seed = args.seed + 100_003 * variant_index + (
                0 if width == 16 else 1009 * width_index
            )
            print(f"{variant.name} symbolic ANF width={width}", flush=True)
            trials.append(
                _trial(variant, width, seed, args.assignment_samples)
            )
    payload = {
        "schema": "shake-symbolic-anf-frontier-v1",
        "evidence_stage": "SYMBOLIC_R2_INTERFACE_WITHOUT_ASSIGNMENT_ENUMERATION_RETAINED",
        "result": (
            "Exact Boolean-ring compilation constructs complete two-round SHAKE "
            "state formulas without materializing any 2^k truth assignments."
        ),
        "scope": (
            "Known-complement capacity windows through exactly two Keccak-f[1600] "
            "rounds; the artifact maps the pre-saturation symbolic interface."
        ),
        "parameters": {
            "requested_window_bits": widths,
            "assignment_samples": args.assignment_samples,
            "seed": args.seed,
            "symbolic_rounds": 2,
        },
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trials": trials,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "frontier": {
                    row["variant"] + f"-w{row['window_bits']}": {
                        "R2_basis": row["observations"][2]["basis_monomials"],
                        "R2_coefficients": row["observations"][2][
                            "total_coordinate_coefficients"
                        ],
                        "log2_raw_to_symbolic_ratio": row["observations"][2][
                            "log2_raw_to_symbolic_ratio"
                        ],
                    }
                    for row in trials
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
