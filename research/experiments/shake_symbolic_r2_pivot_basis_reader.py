#!/usr/bin/env python3
"""Express the A152 R2 interface in the exact A154 systematic R1 basis."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import sys
from collections import Counter
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


_A154 = _import_sibling(
    "shake_symbolic_r1_affine_basis_reader.py",
    "shake_symbolic_r2_pivot_basis_a154_base",
)

_BASE = _A154._BASE
_R1 = _A154._R1
_SYMBOLIC = _A154._SYMBOLIC
_WINDOW = _A154._WINDOW
_BITSLICED = _A154._BITSLICED
_PREFIX = _A154._PREFIX

ATTEMPT_ID = "A155"
SCHEMA = "shake-symbolic-r2-pivot-basis-reader-v1"
WINDOW_BITS = _A154.WINDOW_BITS
STATE_BITS = _A154.STATE_BITS
SEED = _A154.SEED
A154_FILENAME = _A154.RESULT_FILENAME
A154_SHA256 = "108cbcadcbd7cfc3831712b8d2073aab42d42cca098db162d1d63627882d21dd"
RESULT_FILENAME = "shake_symbolic_r2_pivot_basis_reader_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_pivot_basis_reader_v1.causal"


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


def _load_a154_gate(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = path.read_bytes()
    observed = _sha256(raw)
    if observed != A154_SHA256:
        raise RuntimeError(f"A154 retained artifact hash differs: {observed}")
    payload = json.loads(raw)
    basis = payload.get("basis", {})
    interface = payload.get("affine_interface", {})
    if (
        payload.get("schema") != _A154.SCHEMA
        or payload.get("parameters", {}).get("seed") != SEED
        or interface.get("polynomial_state_sha256") != _A154.A152_POLYNOMIAL_SHA256
        or interface.get("maximum_algebraic_degree") != 1
        or basis.get("rank") != WINDOW_BITS
        or basis.get("input_nullity") != 0
        or basis.get("systematic_unit_row_basis") is not True
        or basis.get("basis_transform_kind")
        != "input_coordinate_permutation_after_output_constant_removal"
        or len(basis.get("pivot_delta_to_input_coordinate", [])) != WINDOW_BITS
        or sorted(basis["pivot_delta_to_input_coordinate"]) != list(range(WINDOW_BITS))
    ):
        raise RuntimeError("A154 systematic-basis gate failed")
    gate = {
        "artifact": A154_FILENAME,
        "artifact_sha256": observed,
        "schema": payload["schema"],
        "affine_map_sha256": interface["affine_map_sha256"],
        "basis_sha256": basis["basis_sha256"],
        "inverse_matrix_sha256": basis["inverse_matrix_sha256"],
        "rank": basis["rank"],
        "systematic_unit_row_basis": True,
        "target_rate_imported": False,
        "solver_observations_imported": False,
        "instrumented_assignment_imported": False,
    }
    return payload, gate


def _decode_masks(values: Sequence[str]) -> list[int]:
    masks = [int(value, 16) for value in values]
    if len(masks) != WINDOW_BITS or any(mask < 0 or mask >= 1 << WINDOW_BITS for mask in masks):
        raise ValueError("A154 inverse row encoding differs")
    return masks


def _substitute_linear_basis(
    polynomials: Sequence[frozenset[int]], inverse_rows: Sequence[int], width: int
) -> list[frozenset[int]]:
    """Substitute x_i = XOR_j inverse[i,j] z_j into an exact Boolean ANF."""
    if len(inverse_rows) != width:
        raise ValueError("linear substitution must provide one row per input")
    variables = [
        frozenset(1 << output for output in range(width) if (row >> output) & 1)
        for row in inverse_rows
    ]
    if any(not polynomial for polynomial in variables):
        raise ValueError("linear substitution maps an input variable to zero")
    monomial_cache: dict[int, frozenset[int]] = {0: _SYMBOLIC.ONE}

    def substitute_monomial(mask: int) -> frozenset[int]:
        cached = monomial_cache.get(mask)
        if cached is not None:
            return cached
        value = _SYMBOLIC.ONE
        for input_coordinate in range(width):
            if (mask >> input_coordinate) & 1:
                value = _SYMBOLIC._poly_mul(value, variables[input_coordinate])
        monomial_cache[mask] = value
        return value

    transformed = []
    for polynomial in polynomials:
        transformed.append(_SYMBOLIC._poly_xor(*(substitute_monomial(mask) for mask in polynomial)))
    return transformed


def _polynomial_statistics(polynomials: Sequence[frozenset[int]], width: int) -> dict[str, Any]:
    union = set().union(*polynomials)
    degree_histogram = Counter(mask.bit_count() for mask in union)
    quadratic_masks = sorted(mask for mask in union if mask.bit_count() == 2)
    edges = sorted(
        [
            [
                next(index for index in range(width) if (mask >> index) & 1),
                max(index for index in range(width) if (mask >> index) & 1),
            ]
            for mask in quadratic_masks
        ]
    )
    coordinate_counts = [len(polynomial) for polynomial in polynomials]
    return {
        "polynomial_state_sha256": _SYMBOLIC._poly_hash(list(polynomials), width),
        "maximum_algebraic_degree": max(degree_histogram, default=0),
        "global_monomial_count": len(union),
        "degree_histogram": {
            str(degree): count for degree, count in sorted(degree_histogram.items())
        },
        "coordinate_coefficient_count": sum(coordinate_counts),
        "minimum_coordinate_coefficient_count": min(coordinate_counts),
        "maximum_coordinate_coefficient_count": max(coordinate_counts),
        "quadratic_monomial_count": len(quadratic_masks),
        "quadratic_monomial_masks": quadratic_masks,
        "interaction_edges": edges,
        "interaction_edges_sha256": _canonical_sha256(edges),
        "coordinate_coefficient_count_sha256": _canonical_sha256(coordinate_counts),
    }


def _complete_graph_proof(edges: Sequence[Sequence[int]], width: int) -> dict[str, Any]:
    normalized = sorted({tuple(sorted(map(int, edge))) for edge in edges})
    expected = list(itertools.combinations(range(width), 2))
    if normalized != expected:
        missing = sorted(set(expected) - set(normalized))
        extra = sorted(set(normalized) - set(expected))
        raise RuntimeError(
            f"R2 interaction graph is not complete; missing={missing}, extra={extra}"
        )
    proof_core = {
        "vertices": width,
        "observed_edges": len(normalized),
        "expected_complete_edges": width * (width - 1) // 2,
        "every_unordered_vertex_pair_present": True,
        "graph": f"K{width}",
        "maximum_independent_set_size": 1,
        "minimum_vertex_cover_size": width - 1,
        "minimum_vertex_cover_count": width,
        "linearization_free_coordinates_after_minimum_cover": 1,
        "proof_rule": "complete_graph_complement_of_any_vertex_is_a_minimum_cover",
    }
    return {**proof_core, "proof_sha256": _canonical_sha256(proof_core)}


def _mapped_edges(edges: Sequence[Sequence[int]], input_to_pivot: Sequence[int]) -> list[list[int]]:
    return sorted(
        [sorted([input_to_pivot[int(left)], input_to_pivot[int(right)]]) for left, right in edges]
    )


def _concrete_gate(
    *,
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    original: list[frozenset[int]],
    transformed: list[frozenset[int]],
    inverse_rows: Sequence[int],
) -> dict[str, Any]:
    pivot_assignments = _A154._deterministic_assignments(WINDOW_BITS)
    input_assignments = [_A154._recover_input(value, inverse_rows) for value in pivot_assignments]
    injected = _SYMBOLIC._inject_assignments(template, variant, positions, input_assignments)
    state = _BITSLICED._scalar_to_bitsliced(injected)
    state = _PREFIX._keccak_round_bitsliced(state, 0)
    state = _PREFIX._keccak_round_bitsliced(state, 1)
    concrete = _BITSLICED._bitsliced_to_scalar(state, len(pivot_assignments))
    original_symbolic = _SYMBOLIC._evaluate_symbolic(original, input_assignments, WINDOW_BITS)
    transformed_symbolic = _SYMBOLIC._evaluate_symbolic(transformed, pivot_assignments, WINDOW_BITS)
    if not np.array_equal(original_symbolic, concrete) or not np.array_equal(
        transformed_symbolic, concrete
    ):
        raise RuntimeError("R2 pivot-basis transform differs from concrete Keccak")
    assignment_raw = b"".join(value.to_bytes(3, "little") for value in pivot_assignments)
    input_raw = b"".join(value.to_bytes(3, "little") for value in input_assignments)
    state_raw = concrete.astype("<u8", copy=False).tobytes()
    return {
        "pivot_assignments_checked": len(pivot_assignments),
        "input_assignments_checked": len(input_assignments),
        "state_bits_checked_per_representation": len(pivot_assignments) * STATE_BITS,
        "three_way_state_bits_checked": 3 * len(pivot_assignments) * STATE_BITS,
        "pivot_assignment_sha256": _sha256(assignment_raw),
        "mapped_input_assignment_sha256": _sha256(input_raw),
        "r2_state_sha256": _sha256(state_raw),
        "original_R2_symbolic_equals_independent_bitsliced_rounds": True,
        "pivot_basis_R2_symbolic_equals_independent_bitsliced_rounds": True,
        "target_rate_input_used": False,
        "instrumented_assignment_input_used": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_pivot_basis_reader",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "anchor_sha256": A154_SHA256,
            "target_rate_input_used": False,
        },
    )
    ids = [
        "shake128-a154-systematic-r1-basis",
        "shake128-r2-exact-pivot-basis-transform",
        "shake128-r2-complete-interaction-graph",
        "shake128-r1-to-r2-structure-transition",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A154:exact_bijective_affine_R1_reparameterization",
        mechanism="hash_gate_the_systematic_rank24_R1_output_basis_and_two_sided_inverse",
        outcome="A155:exact_R1_pivot_delta_coordinate_system",
        confidence=1.0,
        evidence_kind="retained_artifact_hash_and_GF2_inverse_certificate",
        source=A154_SHA256,
        attrs={"anchor_gate": payload["anchor_gate"], "basis_map": payload["basis_map"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A155:exact_R1_pivot_delta_coordinate_system",
        mechanism="symbolically_substitute_the_A154_inverse_into_every_exact_R2_ANF_coordinate",
        outcome="A155:complete_R2_interface_in_systematic_R1_basis",
        confidence=1.0,
        evidence_kind="exact_boolean_ring_linear_basis_substitution",
        source=payload["pivot_basis_R2"]["polynomial_state_sha256"],
        provenance=[ids[0]],
        attrs={
            "original_R2": payload["original_R2"],
            "pivot_basis_R2": payload["pivot_basis_R2"],
            "verification": payload["verification"],
        },
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A155:complete_R2_interface_in_systematic_R1_basis",
        mechanism="enumerate_every_unique_degree_two_monomial_and_compare_with_all_24_choose_2_pairs",
        outcome="A155:R2_interaction_graph_is_exactly_K24",
        confidence=1.0,
        evidence_kind="exact_complete_graph_equality_and_vertex_cover_proof",
        source=payload["complete_graph_proof"]["proof_sha256"],
        provenance=[ids[1]],
        attrs={"complete_graph_proof": payload["complete_graph_proof"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A155:R2_interaction_graph_is_exactly_K24",
        mechanism="compare_the_edgeless_systematic_R1_interface_with_the_basis_invariant_complete_R2_graph",
        outcome="A155:pairwise_interaction_saturation_localized_exactly_between_R1_and_R2",
        confidence=1.0,
        evidence_kind="exact_round_boundary_and_basis_mapping",
        source=payload["transition"]["transition_sha256"],
        provenance=[ids[2]],
        attrs={"transition": payload["transition"], "next_mechanism": payload["next_mechanism"]},
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
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A155 Causal provenance chain failed validation")
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


def run(anchor_path: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    a154, anchor_gate = _load_a154_gate(anchor_path)
    basis = a154["basis"]
    inverse_rows = _decode_masks(basis["inverse_row_masks_hex"])
    pivot_to_input = list(map(int, basis["pivot_delta_to_input_coordinate"]))
    input_to_pivot = list(map(int, basis["input_coordinate_to_pivot_delta"]))
    if [pivot_to_input[input_to_pivot[index]] for index in range(WINDOW_BITS)] != list(
        range(WINDOW_BITS)
    ):
        raise RuntimeError("A154 pivot/input coordinate maps are not mutual inverses")

    variant = _BASE.VARIANTS["shake128"]
    template, positions, instance = _A154._structural_instance(variant)
    r1 = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, positions, 1)
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, positions, 2)
    if _SYMBOLIC._poly_hash(r1, WINDOW_BITS) != _A154.A152_POLYNOMIAL_SHA256:
        raise RuntimeError("A154 R1 relation does not reproduce")
    transformed = _substitute_linear_basis(original, inverse_rows, WINDOW_BITS)
    original_stats = _polynomial_statistics(original, WINDOW_BITS)
    transformed_stats = _polynomial_statistics(transformed, WINDOW_BITS)
    mapped_edges = _mapped_edges(original_stats["interaction_edges"], input_to_pivot)
    if mapped_edges != transformed_stats["interaction_edges"]:
        raise RuntimeError("R2 interaction graph does not follow the exact A154 basis map")
    graph_proof = _complete_graph_proof(transformed_stats["interaction_edges"], WINDOW_BITS)
    verification = _concrete_gate(
        template=template,
        variant=variant,
        positions=positions,
        original=original,
        transformed=transformed,
        inverse_rows=inverse_rows,
    )
    basis_map = {
        "selected_R1_output_coordinates": basis["selected_output_coordinates"],
        "selected_R1_output_constants": basis["selected_output_constants"],
        "pivot_delta_to_input_coordinate": pivot_to_input,
        "input_coordinate_to_pivot_delta": input_to_pivot,
        "transform_kind": basis["basis_transform_kind"],
        "systematic_unit_row_basis": True,
        "mapped_interaction_edges_equal_transformed_edges": True,
        "basis_map_sha256": _canonical_sha256(
            {
                "pivot_delta_to_input_coordinate": pivot_to_input,
                "input_coordinate_to_pivot_delta": input_to_pivot,
            }
        ),
    }
    transition_core = {
        "R1_maximum_degree": 1,
        "R1_quadratic_edges": 0,
        "R1_rank": WINDOW_BITS,
        "R1_systematic_input_copies": WINDOW_BITS,
        "R2_maximum_degree": transformed_stats["maximum_algebraic_degree"],
        "R2_quadratic_edges": transformed_stats["quadratic_monomial_count"],
        "R2_possible_quadratic_edges": WINDOW_BITS * (WINDOW_BITS - 1) // 2,
        "R2_graph_complete": True,
        "pairwise_interaction_saturation_first_observed_round": 2,
        "R2_complete_graph_preserved_under_A154_basis": True,
    }
    transition = {**transition_core, "transition_sha256": _canonical_sha256(transition_core)}
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_R2_PIVOT_BASIS_SATURATION_RETAINED",
        "result": (
            "The exact A154 pivot deltas are a permutation of the 24 original inputs. "
            "After substituting that verified inverse into all 1,600 R2 equations, "
            "every one of the 276 possible quadratic pairs is present: the R2 "
            "interaction graph is exactly K24, with minimum vertex-cover size 23. "
            "Pairwise interaction saturation is therefore localized exactly between "
            "the affine R1 interface and R2 and is invariant under the systematic basis."
        ),
        "scope": (
            "The hash-pinned A152 SHAKE128 width-24 cleared-template relation through "
            "two Keccak-f[1600] rounds, expressed in the exact A154 R1 pivot basis."
        ),
        "anchor_gate": anchor_gate,
        "instance": instance,
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "state_output_bits": STATE_BITS,
            "symbolic_prefix_rounds": 2,
            "target_rate_input_used": False,
            "solver_observations_used": False,
            "instrumented_assignment_extracted": False,
        },
        "basis_map": basis_map,
        "original_R2": original_stats,
        "pivot_basis_R2": transformed_stats,
        "complete_graph_proof": graph_proof,
        "transition": transition,
        "verification": verification,
        "next_mechanism": {
            "operation": "compile_the_R1_suffix_from_systematic_pivot_variables_with_exact_alias_and_constant_elimination",
            "reason": (
                "R2 is already the complete graph and any R2 vertex cover fixes 23 of "
                "24 variables. The surviving leverage is the systematic R1 embedding: "
                "reuse pivot variables directly and remove redundant R1 definitions "
                "before measuring the identical full-round relation."
            ),
            "R2_vertex_cover_replay_selected": False,
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
        raise RuntimeError("A155 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "R2_polynomial_state_sha256": original_stats["polynomial_state_sha256"],
        "pivot_R2_polynomial_state_sha256": transformed_stats["polynomial_state_sha256"],
        "quadratic_edges": transformed_stats["quadratic_monomial_count"],
        "minimum_vertex_cover_size": graph_proof["minimum_vertex_cover_size"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--anchor", type=Path, default=research_root / "results" / "v1" / A154_FILENAME
    )
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
            run(args.anchor.resolve(), args.output.resolve(), args.causal_output.resolve()),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
