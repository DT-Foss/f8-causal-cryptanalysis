#!/usr/bin/env python3
"""Extract and invert the exact affine R1 interface exposed by A152.

The A152 prospective window has no degree-two R1 monomials.  This Reader
regenerates only the cleared-template relation, converts all 1,600 R1 output
coordinates into an affine GF(2) matrix, proves its rank, selects the
lexicographically first independent output rows, constructs their exact
inverse, and cross-checks the map against an independent bit-sliced Keccak
round.  No final-rate target, solver outcome, or instrumented assignment is an
input to the construction.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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


_A151 = _import_sibling(
    "shake_symbolic_r1_width24_vertex_cover_reader.py",
    "shake_symbolic_r1_affine_basis_a151_base",
)
_PREFIX = _import_sibling(
    "shake_prefix_observability_frontier.py",
    "shake_symbolic_r1_affine_basis_prefix_gate",
)

_BASE = _A151._BASE
_NATIVE = _A151._NATIVE
_WINDOW = _A151._WINDOW
_R1 = _A151._R1
_SYMBOLIC = _R1._SPLIT._SYMBOLIC
_BITSLICED = _PREFIX._BITSLICED

ATTEMPT_ID = "A154"
SCHEMA = "shake-symbolic-r1-affine-basis-reader-v1"
WINDOW_BITS = 24
STATE_BITS = 1_600
SEED = 260_592_673
A152_FILENAME = "shake_symbolic_r1_width24_prospective_transfer_v1.json"
A152_SHA256 = "0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561"
A152_POLYNOMIAL_SHA256 = "e0c8856814a8fa2a48268ccb580ad0b94decc3879915c300ff66114cfd61025d"
A152_TEMPLATE_SHA256 = "8dd7a73132ae11987e86866552701cc7d093771ec911ee94883d114d3afb33d2"
RESULT_FILENAME = "shake_symbolic_r1_affine_basis_reader_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r1_affine_basis_reader_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return _sha256(raw)


def _load_a152_gate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = _sha256(raw)
    if observed != A152_SHA256:
        raise RuntimeError(f"A152 retained artifact hash differs: {observed}")
    payload = json.loads(raw)
    runtime = payload.get("runtime_instance", {})
    selection = payload.get("selection", {})
    execution = payload.get("execution", {})
    if (
        payload.get("schema") != "shake-symbolic-r1-width24-prospective-transfer-v1"
        or payload.get("parameters", {}).get("seed") != SEED
        or runtime.get("capacity_window_positions") != list(range(143, 167))
        or runtime.get("cleared_template_sha256") != A152_TEMPLATE_SHA256
        or selection.get("r1_polynomial_state_sha256") != A152_POLYNOMIAL_SHA256
        or selection.get("interaction_edges") != []
        or selection.get("partition_bits") != 0
        or execution.get("reconstructed_assignment") is not None
    ):
        raise RuntimeError("A152 affine-boundary gate failed")
    return {
        "artifact": A152_FILENAME,
        "artifact_sha256": observed,
        "schema": payload["schema"],
        "seed": SEED,
        "capacity_window_positions": runtime["capacity_window_positions"],
        "cleared_template_sha256": runtime["cleared_template_sha256"],
        "r1_polynomial_state_sha256": selection["r1_polynomial_state_sha256"],
        "quadratic_edge_count": selection["edge_count"],
        "target_rate_imported": False,
        "solver_observations_imported": False,
        "instrumented_assignment_imported": False,
    }


def _structural_instance(variant: Any) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Regenerate the A152 template without constructing its final-rate target."""
    rng = np.random.default_rng(SEED)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    positions = _WINDOW._window_positions(variant.capacity_bits, WINDOW_BITS, SEED ^ 0xB175)
    template = _WINDOW._clear_window(base_state, variant, positions)
    template_sha256 = _sha256(template.astype("<u8", copy=False).tobytes())
    if positions.tolist() != list(range(143, 167)) or template_sha256 != A152_TEMPLATE_SHA256:
        raise RuntimeError("regenerated A152 structural template differs")
    return (
        template,
        positions,
        {
            "seed": SEED,
            "capacity_window_positions": positions.tolist(),
            "message_sha256": _sha256(message.tobytes()),
            "cleared_template_sha256": template_sha256,
            "target_rate_constructed": False,
            "target_rate_input_used": False,
            "solver_observations_used": False,
            "instrumented_assignment_extracted": False,
        },
    )


def _affine_rows(polynomials: Sequence[frozenset[int]], width: int) -> dict[str, Any]:
    if len(polynomials) != STATE_BITS:
        raise ValueError("R1 polynomial state must contain 1,600 coordinates")
    allowed = {0, *(1 << index for index in range(width))}
    row_masks: list[int] = []
    constants: list[int] = []
    for coordinate, polynomial in enumerate(polynomials):
        outside = set(polynomial) - allowed
        if outside:
            raise RuntimeError(f"R1 coordinate {coordinate} is not affine; masks={sorted(outside)}")
        row_masks.append(sum(1 << index for index in range(width) if (1 << index) in polynomial))
        constants.append(int(0 in polynomial))
    mask_bytes = (width + 7) // 8
    matrix_raw = b"".join(value.to_bytes(mask_bytes, "little") for value in row_masks)
    constant_raw = np.packbits(np.asarray(constants, dtype=np.uint8), bitorder="little").tobytes()
    rebuilt = [
        frozenset(
            ([0] if constants[coordinate] else [])
            + [1 << index for index in range(width) if (row_masks[coordinate] >> index) & 1]
        )
        for coordinate in range(STATE_BITS)
    ]
    if rebuilt != list(polynomials):
        raise RuntimeError("affine coefficient extraction does not rebuild the polynomials")
    return {
        "row_masks": row_masks,
        "constants": constants,
        "matrix_sha256": _sha256(matrix_raw),
        "constant_vector_sha256": _sha256(constant_raw),
        "affine_map_sha256": _sha256(matrix_raw + constant_raw),
        "matrix_encoding": f"{STATE_BITS}_little_endian_{mask_bytes}_byte_row_masks",
        "constant_encoding": f"{STATE_BITS}_bits_little_endian_packbits",
    }


def _reduce_with_basis(value: int, basis: dict[int, int]) -> int:
    reduced = value
    while reduced:
        pivot = reduced.bit_length() - 1
        if pivot not in basis:
            return reduced
        reduced ^= basis[pivot]
    return 0


def _lexicographic_row_basis(row_masks: Sequence[int], width: int) -> dict[str, Any]:
    basis: dict[int, int] = {}
    selected: list[int] = []
    selected_rows: list[int] = []
    rank_prefix = []
    for coordinate, row in enumerate(row_masks):
        reduced = _reduce_with_basis(int(row), basis)
        if reduced:
            pivot = reduced.bit_length() - 1
            basis[pivot] = reduced
            selected.append(coordinate)
            selected_rows.append(int(row))
        rank_prefix.append(len(basis))
    if len(basis) > width:
        raise RuntimeError("GF(2) row rank exceeds input dimension")
    return {
        "rank": len(basis),
        "input_nullity": width - len(basis),
        "output_affine_relation_dimension": len(row_masks) - len(basis),
        "selected_output_coordinates": selected,
        "selected_row_masks": selected_rows,
        "first_coordinate_reaching_full_rank": selected[-1] if len(basis) == width else None,
        "rank_after_each_output_coordinate": rank_prefix,
        "selection_rule": "scan_output_coordinates_ascending_and_keep_exactly_independent_rows",
    }


def _invert_square_gf2(rows: Sequence[int], width: int) -> list[int]:
    if len(rows) != width or any(value < 0 or value >= 1 << width for value in rows):
        raise ValueError("inverse requires a square GF(2) row matrix")
    augmented = [int(row) | (1 << (width + index)) for index, row in enumerate(rows)]
    for column in range(width):
        pivot_row = next(
            (row for row in range(column, width) if (augmented[row] >> column) & 1),
            None,
        )
        if pivot_row is None:
            raise ValueError("GF(2) matrix is singular")
        augmented[column], augmented[pivot_row] = augmented[pivot_row], augmented[column]
        for row in range(width):
            if row != column and ((augmented[row] >> column) & 1):
                augmented[row] ^= augmented[column]
    left_mask = (1 << width) - 1
    if [value & left_mask for value in augmented] != [1 << index for index in range(width)]:
        raise RuntimeError("GF(2) elimination did not produce the identity")
    return [value >> width for value in augmented]


def _inverse_proof(selected_rows: Sequence[int], inverse_rows: Sequence[int]) -> dict[str, Any]:
    width = len(selected_rows)
    products = [_xor_selected(selected_rows, inverse_rows[index]) for index in range(width)]
    # B^-1 B = I is the direct symbolic recovery certificate.  The second
    # identity B B^-1 = I is checked explicitly by multiplying matrix rows.
    second_identity = []
    for row in selected_rows:
        recovered = 0
        for input_index in range(width):
            if (row >> input_index) & 1:
                recovered ^= inverse_rows[input_index]
        second_identity.append(recovered)
    identity = [1 << index for index in range(width)]
    if products != identity or second_identity != identity:
        raise RuntimeError("affine pivot matrix inverse proof failed")
    mask_bytes = (width + 7) // 8
    inverse_raw = b"".join(value.to_bytes(mask_bytes, "little") for value in inverse_rows)
    return {
        "left_inverse_product_rows": products,
        "right_inverse_product_rows": second_identity,
        "identity_rows": identity,
        "left_inverse_exact": True,
        "right_inverse_exact": True,
        "inverse_matrix_sha256": _sha256(inverse_raw),
    }


def _xor_selected(rows: Sequence[int], selector: int) -> int:
    value = 0
    for index, row in enumerate(rows):
        if (selector >> index) & 1:
            value ^= int(row)
    return value


def _evaluate_affine_state(
    row_masks: Sequence[int], constants: Sequence[int], assignments: Sequence[int]
) -> np.ndarray:
    states = np.zeros((len(assignments), 25), dtype=np.uint64)
    for coordinate, (row, constant) in enumerate(zip(row_masks, constants, strict=True)):
        lane, bit = divmod(coordinate, 64)
        for assignment_index, assignment in enumerate(assignments):
            value = int(constant) ^ ((int(row) & int(assignment)).bit_count() & 1)
            states[assignment_index, lane] |= np.uint64(value) << np.uint64(bit)
    return states


def _selected_delta(
    state: np.ndarray, selected_outputs: Sequence[int], constants: Sequence[int]
) -> int:
    value = 0
    for basis_index, coordinate in enumerate(selected_outputs):
        lane, bit = divmod(int(coordinate), 64)
        observed = (int(state[lane]) >> bit) & 1
        value |= (observed ^ int(constants[coordinate])) << basis_index
    return value


def _recover_input(delta: int, inverse_rows: Sequence[int]) -> int:
    return sum(
        ((int(row) & delta).bit_count() & 1) << input_index
        for input_index, row in enumerate(inverse_rows)
    )


def _deterministic_assignments(width: int, count: int = 64) -> list[int]:
    if count < width + 2 or count > 64:
        raise ValueError("assignment gate count must contain zero, every unit, and all-ones")
    mask = (1 << width) - 1
    values = [0, *(1 << index for index in range(width)), mask]
    seen = set(values)
    counter = 0
    while len(values) < count:
        raw = hashlib.sha256(
            b"A154:affine-R1-assignment-gate:v1|" + counter.to_bytes(8, "little")
        ).digest()
        candidate = int.from_bytes(raw, "little") & mask
        counter += 1
        if candidate not in seen:
            seen.add(candidate)
            values.append(candidate)
    return values


def _concrete_gate(
    *,
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    polynomials: list[frozenset[int]],
    affine: dict[str, Any],
    basis: dict[str, Any],
    inverse_rows: Sequence[int],
) -> dict[str, Any]:
    assignments = _deterministic_assignments(WINDOW_BITS)
    injected = _SYMBOLIC._inject_assignments(template, variant, positions, assignments)
    planes = _BITSLICED._scalar_to_bitsliced(injected)
    concrete = _BITSLICED._bitsliced_to_scalar(
        _PREFIX._keccak_round_bitsliced(planes, 0), len(assignments)
    )
    symbolic = _SYMBOLIC._evaluate_symbolic(polynomials, assignments, WINDOW_BITS)
    matrix = _evaluate_affine_state(affine["row_masks"], affine["constants"], assignments)
    if not np.array_equal(symbolic, concrete) or not np.array_equal(matrix, concrete):
        raise RuntimeError("affine R1 map differs from independent concrete Keccak round")
    recovered = [
        _recover_input(
            _selected_delta(
                concrete[index],
                basis["selected_output_coordinates"],
                affine["constants"],
            ),
            inverse_rows,
        )
        for index in range(len(assignments))
    ]
    if recovered != assignments:
        raise RuntimeError("selected R1 pivot outputs do not recover the input assignments")
    assignment_raw = b"".join(value.to_bytes(3, "little") for value in assignments)
    state_raw = concrete.astype("<u8", copy=False).tobytes()
    return {
        "assignments_checked": len(assignments),
        "includes_zero": True,
        "includes_every_unit_vector": True,
        "includes_all_ones": True,
        "deterministic_hash_derived_assignments": len(assignments) - WINDOW_BITS - 2,
        "state_bits_checked_per_representation": len(assignments) * STATE_BITS,
        "three_way_state_bits_checked": 3 * len(assignments) * STATE_BITS,
        "input_roundtrips_checked": len(assignments),
        "assignment_sha256": _sha256(assignment_raw),
        "r1_state_sha256": _sha256(state_raw),
        "symbolic_equals_independent_bitsliced_round": True,
        "affine_matrix_equals_independent_bitsliced_round": True,
        "pivot_output_inverse_recovers_every_checked_input": True,
        "target_rate_input_used": False,
        "instrumented_assignment_input_used": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_affine_basis_reader",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "anchor_sha256": A152_SHA256,
            "target_rate_input_used": False,
            "instrumented_assignment_input_used": False,
        },
    )
    ids = [
        "shake128-a152-affine-boundary",
        "shake128-r1-affine-matrix",
        "shake128-r1-lexicographic-pivot-basis",
        "shake128-r1-exact-affine-inverse",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A152:prospective_width24_R1_graph_has_zero_quadratic_edges",
        mechanism="hash_gate_the_retained_A152_artifact_and_regenerate_only_its_cleared_template",
        outcome="A154:target_independent_exact_R1_relation",
        confidence=1.0,
        evidence_kind="retained_artifact_hash_and_deterministic_template_regeneration",
        source=A152_SHA256,
        attrs={"anchor_gate": payload["anchor_gate"], "instance": payload["instance"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A154:target_independent_exact_R1_relation",
        mechanism="extract_all_constant_and_singleton_ANF_coefficients_into_a_1600_by_24_GF2_map",
        outcome="A154:complete_affine_R1_coefficient_matrix",
        confidence=1.0,
        evidence_kind="exact_boolean_ring_coefficient_extraction",
        source=payload["affine_interface"]["polynomial_state_sha256"],
        provenance=[ids[0]],
        attrs={"affine_interface": payload["affine_interface"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A154:complete_affine_R1_coefficient_matrix",
        mechanism="ascending_output_scan_with_exact_GF2_independence_tests",
        outcome="A154:lexicographically_first_full_rank_R1_output_basis",
        confidence=1.0,
        evidence_kind="exact_GF2_row_reduction",
        source=payload["affine_interface"]["matrix_sha256"],
        provenance=[ids[1]],
        attrs={"basis": payload["basis"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A154:lexicographically_first_full_rank_R1_output_basis",
        mechanism="Gauss_Jordan_inversion_plus_symbolic_matrix_and_independent_bitsliced_roundtrip_gates",
        outcome="A154:exact_bijective_affine_R1_reparameterization",
        confidence=1.0,
        evidence_kind="two_sided_GF2_inverse_and_64_assignment_concrete_cross_check",
        source=payload["basis"]["inverse_matrix_sha256"],
        provenance=[ids[2]],
        attrs={"inverse_proof": payload["inverse_proof"], "verification": payload["verification"]},
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
        raise RuntimeError("A154 Causal provenance chain failed validation")
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
    anchor_gate = _load_a152_gate(anchor_path)
    variant = _BASE.VARIANTS["shake128"]
    template, positions, instance = _structural_instance(variant)
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, positions, 1)
    polynomial_hash = _SYMBOLIC._poly_hash(polynomials, WINDOW_BITS)
    if polynomial_hash != A152_POLYNOMIAL_SHA256:
        raise RuntimeError(f"A152 R1 polynomial state differs: {polynomial_hash}")
    affine = _affine_rows(polynomials, WINDOW_BITS)
    basis = _lexicographic_row_basis(affine["row_masks"], WINDOW_BITS)
    if basis["rank"] != WINDOW_BITS or basis["input_nullity"] != 0:
        raise RuntimeError("A152 affine R1 interface does not have full input rank")
    inverse_rows = _invert_square_gf2(basis["selected_row_masks"], WINDOW_BITS)
    inverse_proof = _inverse_proof(basis["selected_row_masks"], inverse_rows)
    systematic_unit_basis = all(value.bit_count() == 1 for value in basis["selected_row_masks"])
    if not systematic_unit_basis:
        raise RuntimeError("lexicographically first A152 R1 basis is not systematic")
    pivot_delta_to_input = [value.bit_length() - 1 for value in basis["selected_row_masks"]]
    input_to_pivot_delta = [pivot_delta_to_input.index(index) for index in range(WINDOW_BITS)]
    verification = _concrete_gate(
        template=template,
        variant=variant,
        positions=positions,
        polynomials=polynomials,
        affine=affine,
        basis=basis,
        inverse_rows=inverse_rows,
    )
    row_weights = [value.bit_count() for value in affine["row_masks"]]
    column_weights = [
        sum((row >> coordinate) & 1 for row in affine["row_masks"])
        for coordinate in range(WINDOW_BITS)
    ]
    selected = basis["selected_output_coordinates"]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_AFFINE_R1_BASIS_AND_INVERSE_RETAINED",
        "result": (
            "The A152 cleared-template R1 interface is an injective affine map from "
            "24 unknown coordinates into the 1,600-bit Keccak state. Its exact GF(2) "
            "rank is 24, and the lexicographically first independent output basis is "
            "systematic: after removing known output constants, its 24 coordinates "
            "are a permutation of the 24 inputs. The verified two-sided inverse "
            "recovers every checked input from those R1 output deltas."
        ),
        "scope": (
            "The hash-pinned A152 SHAKE128 width-24 cleared-template relation through "
            "exactly one Keccak-f[1600] round; no final-rate target or solver result."
        ),
        "anchor_gate": anchor_gate,
        "instance": instance,
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "state_output_bits": STATE_BITS,
            "symbolic_prefix_rounds": 1,
            "field": "GF(2)",
            "target_rate_input_used": False,
            "solver_observations_used": False,
            "instrumented_assignment_extracted": False,
        },
        "affine_interface": {
            "polynomial_state_sha256": polynomial_hash,
            "maximum_algebraic_degree": 1,
            "output_coordinate_count": STATE_BITS,
            "input_coordinate_count": WINDOW_BITS,
            "constant_term_one_count": sum(affine["constants"]),
            "nonconstant_output_count": sum(value != 0 for value in affine["row_masks"]),
            "zero_linear_row_count": sum(value == 0 for value in affine["row_masks"]),
            "row_weight_histogram": {
                str(weight): count for weight, count in sorted(Counter(row_weights).items())
            },
            "column_weights": column_weights,
            "row_masks_hex": [f"{value:06x}" for value in affine["row_masks"]],
            "constant_term_one_coordinates": [
                coordinate for coordinate, value in enumerate(affine["constants"]) if value
            ],
            "matrix_encoding": affine["matrix_encoding"],
            "constant_encoding": affine["constant_encoding"],
            "matrix_sha256": affine["matrix_sha256"],
            "constant_vector_sha256": affine["constant_vector_sha256"],
            "affine_map_sha256": affine["affine_map_sha256"],
            "exact_polynomial_reconstruction": True,
        },
        "basis": {
            "rank": basis["rank"],
            "input_nullity": basis["input_nullity"],
            "output_affine_relation_dimension": basis["output_affine_relation_dimension"],
            "selection_rule": basis["selection_rule"],
            "selected_output_coordinates": selected,
            "selected_output_lane_bits": [
                {"coordinate": value, "lane": value // 64, "bit": value % 64} for value in selected
            ],
            "selected_row_masks_hex": [f"{value:06x}" for value in basis["selected_row_masks"]],
            "selected_output_constants": [affine["constants"][value] for value in selected],
            "systematic_unit_row_basis": systematic_unit_basis,
            "basis_transform_kind": "input_coordinate_permutation_after_output_constant_removal",
            "pivot_delta_to_input_coordinate": pivot_delta_to_input,
            "input_coordinate_to_pivot_delta": input_to_pivot_delta,
            "first_coordinate_reaching_full_rank": basis["first_coordinate_reaching_full_rank"],
            "basis_sha256": _canonical_sha256(
                {
                    "selected_output_coordinates": selected,
                    "selected_row_masks": basis["selected_row_masks"],
                    "selected_output_constants": [affine["constants"][value] for value in selected],
                }
            ),
            "inverse_row_masks_hex": [f"{value:06x}" for value in inverse_rows],
            "inverse_matrix_sha256": inverse_proof["inverse_matrix_sha256"],
        },
        "inverse_proof": inverse_proof,
        "verification": verification,
        "next_mechanism": {
            "operation": "express_the_exact_R2_interface_in_the_A154_pivot_output_basis",
            "reason": (
                "The R1 map is bijective onto a 24-dimensional affine image, so its "
                "pivot output deltas are exact replacement variables. R2 graph changes "
                "in this basis measure structure that the empty R1 graph cannot expose."
            ),
            "replay_vertex_cover_selected": False,
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
        raise RuntimeError("A154 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "rank": basis["rank"],
        "input_nullity": basis["input_nullity"],
        "selected_output_coordinates": selected,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--anchor",
        type=Path,
        default=research_root / "results" / "v1" / A152_FILENAME,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
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
