#!/usr/bin/env python3
"""Exact SPARKLE full-step projection and linear-order causal Reader.

The implementation follows the official SPARKLE C source.  The experiment
keeps three statements separate:

* a full-step endpoint projection: the final right half is the post-Alzette
  left half, so it is sufficient to reconstruct the pre-final-step left half;
* the exact minimal order of the SPARKLE linear layer;
* the exact order of the four-word XOR-aggregate quotient of that layer.

All executable recipes are loaded back from the generated ``.causal`` file
before confirmation.  No semantic or fuzzy edge inference is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


OFFICIAL_SOURCE_URL = "https://github.com/cryptolu/sparkle/blob/master/software/sparkle/sparkle.c"
OFFICIAL_RAW_URL = "https://raw.githubusercontent.com/cryptolu/sparkle/master/software/sparkle/sparkle.c"
OFFICIAL_RAW_SHA256 = "a670d9ae8084270eda2de955d4225212d01672778303ca16e33ef850da9a3c79"

RCON = np.array(
    [
        0xB7E15162,
        0xBF715880,
        0x38B4DA56,
        0x324E7738,
        0xBB1185EB,
        0x4F7C7B57,
        0xCFBFA1C8,
        0xC2B3293D,
    ],
    dtype=np.uint32,
)


@dataclass(frozen=True)
class Variant:
    name: str
    state_bits: int
    branches: int
    steps: int
    linear_order: int
    quotient_order: int
    zero_kat_words: str


VARIANTS: dict[str, Variant] = {
    "sparkle256": Variant(
        name="SPARKLE-256",
        state_bits=256,
        branches=4,
        steps=10,
        linear_order=6,
        quotient_order=3,
        zero_kat_words=(
            "c056d47e1c46af31bfb353beeb4c118a"
            "60ab9b560ffc876a8c1d8681d626d0b2"
        ),
    ),
    "sparkle384": Variant(
        name="SPARKLE-384",
        state_bits=384,
        branches=6,
        steps=11,
        linear_order=30,
        quotient_order=10,
        zero_kat_words=(
            "f3c2bf25fc53dd55cad654069eaff917"
            "3fa5648ce1a2f2485841fcee3a937e3c"
            "61f72c442b6673da168419a5ff9e6b22"
        ),
    ),
    "sparkle512": Variant(
        name="SPARKLE-512",
        state_bits=512,
        branches=8,
        steps=12,
        linear_order=12,
        quotient_order=3,
        zero_kat_words=(
            "4e22054039c1a4a9b85107ecd95569de"
            "7e08711e241999b13cf576d6dc06597b"
            "fb2e7468b7f1384da841bbf6799316d0"
            "7fa519f00b6ac8e746c1dee5b62efac8"
        ),
    ),
}


def _validate_state(state: np.ndarray, branches: int) -> None:
    if state.dtype != np.uint32 or state.ndim != 2 or state.shape[1] != 2 * branches:
        raise ValueError(f"state must be uint32[N,{2 * branches}]")
    if branches not in (4, 6, 8):
        raise ValueError("SPARKLE branches must be 4, 6, or 8")


def _ror32(value: np.ndarray, shift: int) -> np.ndarray:
    if not 0 < shift < 32:
        raise ValueError("rotation must be in 1..31")
    return ((value >> np.uint32(shift)) | (value << np.uint32(32 - shift))).astype(
        np.uint32
    )


def _ell(value: np.ndarray) -> np.ndarray:
    return _ror32(value ^ (value << np.uint32(16)), 16)


def _add_step_constants(state: np.ndarray, step_index: int) -> np.ndarray:
    result = state.copy()
    result[:, 1] ^= RCON[step_index % len(RCON)]
    result[:, 3] ^= np.uint32(step_index)
    return result


def _alzette_layer(state: np.ndarray, branches: int) -> np.ndarray:
    _validate_state(state, branches)
    result = state.copy()
    for branch in range(branches):
        x = result[:, 2 * branch].copy()
        y = result[:, 2 * branch + 1].copy()
        constant = RCON[branch]
        x = x + _ror32(y, 31)
        y ^= _ror32(x, 24)
        x ^= constant
        x = x + _ror32(y, 17)
        y ^= _ror32(x, 17)
        x ^= constant
        x = x + y
        y ^= _ror32(x, 31)
        x ^= constant
        x = x + _ror32(y, 24)
        y ^= _ror32(x, 16)
        x ^= constant
        result[:, 2 * branch] = x
        result[:, 2 * branch + 1] = y
    return result


def _alzette_inverse(state: np.ndarray, branches: int) -> np.ndarray:
    _validate_state(state, branches)
    result = state.copy()
    for branch in range(branches):
        x = result[:, 2 * branch].copy()
        y = result[:, 2 * branch + 1].copy()
        constant = RCON[branch]
        x ^= constant
        y ^= _ror32(x, 16)
        x = x - _ror32(y, 24)
        x ^= constant
        y ^= _ror32(x, 31)
        x = x - y
        x ^= constant
        y ^= _ror32(x, 17)
        x = x - _ror32(y, 17)
        x ^= constant
        y ^= _ror32(x, 24)
        x = x - _ror32(y, 31)
        result[:, 2 * branch] = x
        result[:, 2 * branch + 1] = y
    return result


def _linear_layer(state: np.ndarray, branches: int) -> np.ndarray:
    """Apply the official SPARKLE branch linear layer without in-place aliases."""
    _validate_state(state, branches)
    half = branches // 2
    left_x = np.bitwise_xor.reduce(state[:, 0:branches:2], axis=1)
    left_y = np.bitwise_xor.reduce(state[:, 1:branches:2], axis=1)
    tmp_x = _ell(left_x)
    tmp_y = _ell(left_y)
    result = np.empty_like(state)
    for source in range(half):
        destination = (source - 1) % half
        left_word = 2 * source
        right_word = 2 * (half + source)
        destination_word = 2 * destination
        result[:, destination_word] = (
            state[:, right_word] ^ state[:, left_word] ^ tmp_y
        )
        result[:, destination_word + 1] = (
            state[:, right_word + 1] ^ state[:, left_word + 1] ^ tmp_x
        )
        result[:, branches + left_word] = state[:, left_word]
        result[:, branches + left_word + 1] = state[:, left_word + 1]
    return result


def _linear_inverse(state: np.ndarray, branches: int) -> np.ndarray:
    """Invert the linear layer from its explicit generalized-Feistel equations."""
    _validate_state(state, branches)
    half = branches // 2
    result = np.empty_like(state)
    result[:, :branches] = state[:, branches:]
    left_x = np.bitwise_xor.reduce(result[:, 0:branches:2], axis=1)
    left_y = np.bitwise_xor.reduce(result[:, 1:branches:2], axis=1)
    tmp_x = _ell(left_x)
    tmp_y = _ell(left_y)
    for source in range(half):
        destination = (source - 1) % half
        left_word = 2 * source
        right_word = 2 * (half + source)
        destination_word = 2 * destination
        result[:, right_word] = (
            state[:, destination_word] ^ result[:, left_word] ^ tmp_y
        )
        result[:, right_word + 1] = (
            state[:, destination_word + 1] ^ result[:, left_word + 1] ^ tmp_x
        )
    return result


def _linear_power(state: np.ndarray, branches: int, exponent: int) -> np.ndarray:
    if exponent < 0:
        raise ValueError("linear exponent must be non-negative")
    result = state.copy()
    for _ in range(exponent):
        result = _linear_layer(result, branches)
    return result


def _step(state: np.ndarray, branches: int, step_index: int) -> np.ndarray:
    injected = _add_step_constants(state, step_index)
    return _linear_layer(_alzette_layer(injected, branches), branches)


def _step_inverse(state: np.ndarray, branches: int, step_index: int) -> np.ndarray:
    post_alzette = _linear_inverse(state, branches)
    injected = _alzette_inverse(post_alzette, branches)
    return _add_step_constants(injected, step_index)


def _trace(state: np.ndarray, branches: int, steps: int) -> list[np.ndarray]:
    _validate_state(state, branches)
    trace = [state.copy()]
    current = state.copy()
    for step_index in range(steps):
        current = _step(current, branches, step_index)
        trace.append(current)
    return trace


def _permute(state: np.ndarray, branches: int, steps: int) -> np.ndarray:
    return _trace(state, branches, steps)[-1]


def _permute_inverse(state: np.ndarray, branches: int, steps: int) -> np.ndarray:
    result = state.copy()
    for step_index in range(steps - 1, -1, -1):
        result = _step_inverse(result, branches, step_index)
    return result


def _words_hex(state: np.ndarray) -> str:
    if state.shape[0] != 1:
        raise ValueError("word hex formatting expects one state")
    return "".join(f"{int(word):08x}" for word in state[0])


def _kat() -> dict[str, Any]:
    rows = []
    for key, variant in VARIANTS.items():
        zero = np.zeros((1, 2 * variant.branches), dtype=np.uint32)
        encrypted = _permute(zero, variant.branches, variant.steps)
        observed = _words_hex(encrypted)
        if observed != variant.zero_kat_words:
            raise RuntimeError(
                f"{variant.name} zero-state KAT failed: {observed} != {variant.zero_kat_words}"
            )
        recovered = _permute_inverse(encrypted, variant.branches, variant.steps)
        if not np.array_equal(recovered, zero):
            raise RuntimeError(f"{variant.name} official inverse roundtrip failed")
        rows.append(
            {
                "variant": key,
                "state_bits": variant.state_bits,
                "steps": variant.steps,
                "input_words": "00" * (variant.state_bits // 8),
                "expected_output_words": variant.zero_kat_words,
                "observed_output_words": observed,
                "forward_match": True,
                "inverse_match": True,
            }
        )
    return {
        "official_source_url": OFFICIAL_SOURCE_URL,
        "official_raw_url": OFFICIAL_RAW_URL,
        "official_raw_sha256": OFFICIAL_RAW_SHA256,
        "vectors": rows,
    }


def _aggregate(state: np.ndarray, branches: int) -> np.ndarray:
    """Return (left-x, left-y, right-x, right-y) XOR aggregates."""
    _validate_state(state, branches)
    return np.stack(
        (
            np.bitwise_xor.reduce(state[:, 0:branches:2], axis=1),
            np.bitwise_xor.reduce(state[:, 1:branches:2], axis=1),
            np.bitwise_xor.reduce(state[:, branches::2], axis=1),
            np.bitwise_xor.reduce(state[:, branches + 1::2], axis=1),
        ),
        axis=1,
    )


def _quotient_step(aggregate: np.ndarray, half_branches: int) -> np.ndarray:
    if aggregate.dtype != np.uint32 or aggregate.ndim != 2 or aggregate.shape[1] != 4:
        raise ValueError("aggregate must be uint32[N,4]")
    left_x, left_y, right_x, right_y = [aggregate[:, i] for i in range(4)]
    if half_branches % 2:
        next_left_x = left_x ^ right_x ^ _ell(left_y)
        next_left_y = left_y ^ right_y ^ _ell(left_x)
    else:
        next_left_x = left_x ^ right_x
        next_left_y = left_y ^ right_y
    return np.stack((next_left_x, next_left_y, left_x, left_y), axis=1)


def _proper_divisors(value: int) -> list[int]:
    return [candidate for candidate in range(1, value) if value % candidate == 0]


def _basis_state(bit: int, words: int) -> np.ndarray:
    state = np.zeros((1, words), dtype=np.uint32)
    state[0, bit // 32] = np.uint32(1 << (bit % 32))
    return state


def _basis_linear_order_proof(variant: Variant) -> dict[str, Any]:
    bits = variant.state_bits
    for bit in range(bits):
        basis = _basis_state(bit, 2 * variant.branches)
        cycled = _linear_power(basis, variant.branches, variant.linear_order)
        if not np.array_equal(cycled, basis):
            raise RuntimeError(f"{variant.name} linear order failed on basis bit {bit}")
    divisor_witnesses: dict[str, int] = {}
    for divisor in _proper_divisors(variant.linear_order):
        for bit in range(bits):
            basis = _basis_state(bit, 2 * variant.branches)
            if not np.array_equal(
                _linear_power(basis, variant.branches, divisor), basis
            ):
                divisor_witnesses[str(divisor)] = bit
                break
        else:
            raise RuntimeError(
                f"{variant.name} claimed order is not minimal; divisor {divisor} is identity"
            )
    return {
        "dimension_bits": bits,
        "basis_vectors_checked": bits,
        "identity_exponent": variant.linear_order,
        "proper_divisor_nonidentity_witnesses": divisor_witnesses,
        "minimal_order_proved": True,
        "inverse_as_forward_power": variant.linear_order - 1,
    }


def _basis_quotient_order_proof(variant: Variant) -> dict[str, Any]:
    half = variant.branches // 2
    relation_vectors = 0
    for bit in range(variant.state_bits):
        basis = _basis_state(bit, 2 * variant.branches)
        expected = _aggregate(_linear_layer(basis, variant.branches), variant.branches)
        observed = _quotient_step(_aggregate(basis, variant.branches), half)
        if not np.array_equal(observed, expected):
            raise RuntimeError(f"{variant.name} quotient relation failed on state bit {bit}")
        relation_vectors += 1
    for bit in range(128):
        basis = _basis_state(bit, 4)
        cycled = basis.copy()
        for _ in range(variant.quotient_order):
            cycled = _quotient_step(cycled, half)
        if not np.array_equal(cycled, basis):
            raise RuntimeError(f"{variant.name} quotient order failed on bit {bit}")
    divisor_witnesses: dict[str, int] = {}
    for divisor in _proper_divisors(variant.quotient_order):
        for bit in range(128):
            basis = _basis_state(bit, 4)
            cycled = basis.copy()
            for _ in range(divisor):
                cycled = _quotient_step(cycled, half)
            if not np.array_equal(cycled, basis):
                divisor_witnesses[str(divisor)] = bit
                break
        else:
            raise RuntimeError(
                f"{variant.name} quotient order is not minimal at divisor {divisor}"
            )
    return {
        "quotient_dimension_bits": 128,
        "full_state_relation_basis_vectors_checked": relation_vectors,
        "quotient_basis_vectors_checked": 128,
        "identity_exponent": variant.quotient_order,
        "proper_divisor_nonidentity_witnesses": divisor_witnesses,
        "minimal_order_proved": True,
        "parity_case": "odd_half_branch_count" if half % 2 else "even_half_branch_count",
    }


def _projection_recipe(variant: Variant) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "word_bits": 32,
        "source": "full_step_output_right_half_only",
        "source_words": variant.branches,
        "destination": "pre_final_step_left_half",
        "destination_words": variant.branches,
        "branch_count": variant.branches // 2,
        "alzette_constants": [int(value) for value in RCON[: variant.branches // 2]],
        "inverse_operation": "official_alzette_inverse",
        "undo_step_injection": [
            {"word": 1, "xor": int(RCON[(variant.steps - 1) % len(RCON)])},
            {"word": 3, "xor": variant.steps - 1},
        ],
        "step_index": variant.steps - 1,
    }


def _fullstep_recipe(variant: Variant) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "source": "full_step_output_all_words",
        "destination": "pre_final_step_all_words",
        "linear_inverse_operation": "repeat_forward_linear_layer",
        "linear_forward_applications": variant.linear_order - 1,
        "then": "official_alzette_inverse_and_undo_step_injection",
        "step_index": variant.steps - 1,
    }


def _execute_projection_recipe(
    final_state: np.ndarray, variant: Variant, recipe: dict[str, Any]
) -> np.ndarray:
    _validate_state(final_state, variant.branches)
    if recipe["source"] != "full_step_output_right_half_only":
        raise ValueError("unsupported projection source")
    if int(recipe["branch_count"]) != variant.branches // 2:
        raise ValueError("projection branch count does not match variant")
    constants = [int(value) for value in recipe["alzette_constants"]]
    if len(constants) != variant.branches // 2:
        raise ValueError("projection recipe has the wrong constant count")
    projected = final_state[:, variant.branches :].copy()
    # Execute the inverse operation using only constants serialized in the recipe.
    for branch, serialized_constant in enumerate(constants):
        x = projected[:, 2 * branch].copy()
        y = projected[:, 2 * branch + 1].copy()
        constant = np.uint32(serialized_constant)
        x ^= constant
        y ^= _ror32(x, 16)
        x = x - _ror32(y, 24)
        x ^= constant
        y ^= _ror32(x, 31)
        x = x - y
        x ^= constant
        y ^= _ror32(x, 17)
        x = x - _ror32(y, 17)
        x ^= constant
        y ^= _ror32(x, 24)
        x = x - _ror32(y, 31)
        projected[:, 2 * branch] = x
        projected[:, 2 * branch + 1] = y
    for operation in recipe["undo_step_injection"]:
        projected[:, int(operation["word"])] ^= np.uint32(int(operation["xor"]))
    return projected


def _execute_fullstep_recipe(
    final_state: np.ndarray, variant: Variant, recipe: dict[str, Any]
) -> np.ndarray:
    _validate_state(final_state, variant.branches)
    if recipe["linear_inverse_operation"] != "repeat_forward_linear_layer":
        raise ValueError("unsupported full-step Reader linear operation")
    post_alzette = _linear_power(
        final_state,
        variant.branches,
        int(recipe["linear_forward_applications"]),
    )
    injected = _alzette_inverse(post_alzette, variant.branches)
    return _add_step_constants(injected, int(recipe["step_index"]))


def _build_graph(
    path: Path,
    proofs: dict[str, dict[str, Any]],
    pairs: int,
    seeds: int,
    routes: int,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="sparkle_fullstep_projection_and_linear_order",
        parameters={
            "variants": list(VARIANTS),
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "bvn_routes": routes,
            "prediction_before_measurement": (
                "The endpoint right half carries the post-Alzette left half exactly; "
                "the Reader should invert that projection from half the final state."
            ),
        },
    )
    for key, variant in VARIANTS.items():
        prefix = key.replace("sparkle", "sparkle-")
        copy_id = f"{prefix}-linear-right-copy"
        order_id = f"{prefix}-linear-minimal-order"
        builder.add_triplet(
            edge_id=copy_id,
            trigger=f"{key}:final_step_post_alzette_left_half",
            mechanism="exact_generalized_feistel_branch_copy",
            outcome=f"{key}:full_permutation_output_right_half",
            confidence=1.0,
            evidence_kind="exact_official_linear_layer_equation",
            source="SPARKLE_official_linear_layer",
            attrs={
                "formula": "output_right_half = post_alzette_left_half",
                "copied_bits": variant.state_bits // 2,
            },
        )
        builder.add_triplet(
            edge_id=f"{prefix}-reader-half-projection",
            trigger=f"{key}:full_permutation_output_right_half",
            mechanism="reader_executable_half_state_projection_inverse",
            outcome=f"{key}:pre_final_step_left_half",
            confidence=1.0,
            evidence_kind="exact_composed_projection_inverse",
            source="SPARKLE_right_copy_plus_Alzette_inverse",
            provenance=[copy_id],
            attrs={
                "reader_recipe": _projection_recipe(variant),
                "information_reconstructed_bits": variant.state_bits // 2,
            },
        )
        builder.add_triplet(
            edge_id=order_id,
            trigger=f"{key}:linear_layer_input",
            mechanism="exact_minimal_finite_order_cycle",
            outcome=f"{key}:linear_layer_input",
            confidence=1.0,
            evidence_kind="complete_binary_basis_proof",
            source="SPARKLE_linear_layer_basis_enumeration",
            attrs=proofs[key]["linear"],
        )
        builder.add_triplet(
            edge_id=f"{prefix}-reader-forward-power-inverse",
            trigger=f"{key}:full_permutation_output_all_words",
            mechanism="reader_executable_forward_power_step_inverse",
            outcome=f"{key}:pre_final_step_all_words",
            confidence=1.0,
            evidence_kind="exact_composed_step_inverse",
            source="SPARKLE_linear_order_and_Alzette_inverse",
            provenance=[order_id],
            attrs={
                "reader_recipe": _fullstep_recipe(variant),
                "information_reconstructed_bits": variant.state_bits,
            },
        )
        builder.add_triplet(
            edge_id=f"{prefix}-aggregate-quotient-order",
            trigger=f"{key}:linear_layer_four_word_xor_aggregate",
            mechanism="exact_aggregate_quotient_cycle",
            outcome=f"{key}:linear_layer_four_word_xor_aggregate",
            confidence=1.0,
            evidence_kind="complete_binary_basis_proof",
            source="SPARKLE_linear_layer_aggregate_recurrence",
            attrs=proofs[key]["quotient"],
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance():
        raise RuntimeError("SPARKLE causal provenance gate failed")
    if len(reader.triplets(include_inferred=False)) != 5 * len(VARIANTS):
        raise RuntimeError("SPARKLE causal triplet count gate failed")
    return stats


def _recipes_from_reader(path: Path) -> dict[str, dict[str, dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    recipes: dict[str, dict[str, dict[str, Any]]] = {}
    for key, variant in VARIANTS.items():
        rows = [
            row
            for row in reader.triplets(include_inferred=False)
            if row["trigger"].startswith(f"{key}:")
        ]
        half = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_half_state_projection_inverse"
        ]
        full = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_forward_power_step_inverse"
        ]
        if len(half) != 1 or len(full) != 1:
            raise RuntimeError(f"Reader did not return unique recipes for {variant.name}")
        recipes[key] = {
            "projection": half[0]["attrs"]["reader_recipe"],
            "fullstep": full[0]["attrs"]["reader_recipe"],
        }
    return recipes


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict[str, Any]:
    if expected.shape != observed.shape or expected.dtype != np.uint32 or observed.dtype != np.uint32:
        raise ValueError("accuracy arrays must have matching uint32 shapes")
    difference = expected ^ observed
    bit_differences = sum(int(value).bit_count() for value in difference.ravel())
    bit_total = int(expected.size * 32)
    branch_words = expected.shape[1] - (expected.shape[1] % 2)
    expected_branches = expected[:, :branch_words].reshape(len(expected), -1, 2)
    observed_branches = observed[:, :branch_words].reshape(len(observed), -1, 2)
    branch_equal = np.all(expected_branches == observed_branches, axis=2)
    row_equal = np.all(expected == observed, axis=1)
    return {
        "word_matches": int(np.sum(expected == observed)),
        "word_total": int(expected.size),
        "word_accuracy": float(np.mean(expected == observed)),
        "branch64_matches": int(np.sum(branch_equal)),
        "branch64_total": int(branch_equal.size),
        "branch64_accuracy": float(np.mean(branch_equal)),
        "state_matches": int(np.sum(row_equal)),
        "state_total": int(len(expected)),
        "state_accuracy": float(np.mean(row_equal)),
        "bit_matches": bit_total - bit_differences,
        "bit_total": bit_total,
        "bit_accuracy": (bit_total - bit_differences) / bit_total,
    }


def _routes(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    verified = verify_routes(routes)
    if not verified["all_bijective"] or verified["forbidden_alignments"]:
        raise RuntimeError("invalid SPARKLE BvN route bank")
    return routes


def _confirm_seed(
    variant: Variant,
    initial: np.ndarray,
    recipes: dict[str, dict[str, Any]],
    routes: int,
    seed: int,
) -> dict[str, Any]:
    trace = _trace(initial, variant.branches, variant.steps)
    prefinal = trace[-2]
    final = trace[-1]
    expected_half = prefinal[:, : variant.branches]
    projected = _execute_projection_recipe(final, variant, recipes["projection"])
    factual_projection = _accuracy(expected_half, projected)
    full_reconstructed = _execute_fullstep_recipe(final, variant, recipes["fullstep"])
    factual_fullstep = _accuracy(prefinal, full_reconstructed)

    route_rows = []
    for route in _routes(len(initial), routes, seed):
        routed = final.copy()
        routed[:, variant.branches :] = final[route, variant.branches :]
        route_rows.append(
            _accuracy(
                expected_half,
                _execute_projection_recipe(routed, variant, recipes["projection"]),
            )
        )

    branch_rotated = final.copy()
    branch_rotated[:, variant.branches :] = np.roll(
        final[:, variant.branches :], shift=2, axis=1
    )
    wrong_branch_route = _accuracy(
        expected_half,
        _execute_projection_recipe(branch_rotated, variant, recipes["projection"]),
    )

    source_left = final.copy()
    source_left[:, variant.branches :] = final[:, : variant.branches]
    wrong_source_half = _accuracy(
        expected_half,
        _execute_projection_recipe(source_left, variant, recipes["projection"]),
    )

    wrong_constants_recipe = json.loads(json.dumps(recipes["projection"]))
    wrong_constants_recipe["alzette_constants"] = list(
        np.roll(wrong_constants_recipe["alzette_constants"], 1)
    )
    wrong_constants = _accuracy(
        expected_half,
        _execute_projection_recipe(final, variant, wrong_constants_recipe),
    )

    wrong_step_recipe = json.loads(json.dumps(recipes["projection"]))
    wrong_step_recipe["undo_step_injection"][0]["xor"] = int(
        RCON[(variant.steps - 2) % len(RCON)]
    )
    wrong_step_recipe["undo_step_injection"][1]["xor"] = variant.steps - 2
    wrong_step = _accuracy(
        expected_half,
        _execute_projection_recipe(final, variant, wrong_step_recipe),
    )

    wrong_power_recipe = json.loads(json.dumps(recipes["fullstep"]))
    wrong_power_recipe["linear_forward_applications"] = max(
        0, int(wrong_power_recipe["linear_forward_applications"]) - 1
    )
    wrong_linear_power = _accuracy(
        prefinal,
        _execute_fullstep_recipe(final, variant, wrong_power_recipe),
    )

    return {
        "factual_projection_reader": factual_projection,
        "factual_forward_power_fullstep_reader": factual_fullstep,
        "bvn_routes": {
            "count": routes,
            "total_state_matches": sum(row["state_matches"] for row in route_rows),
            "max_state_matches": max(row["state_matches"] for row in route_rows),
            "max_branch64_matches": max(row["branch64_matches"] for row in route_rows),
            "mean_bit_accuracy": float(np.mean([row["bit_accuracy"] for row in route_rows])),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in route_rows),
        },
        "wrong_branch_route_control": wrong_branch_route,
        "wrong_source_half_control": wrong_source_half,
        "wrong_alzette_constants_control": wrong_constants,
        "wrong_step_index_control": wrong_step,
        "wrong_linear_power_control": wrong_linear_power,
        "factual_projection_above_all_bvn_routes": (
            factual_projection["state_matches"] > max(row["state_matches"] for row in route_rows)
            and factual_projection["branch64_matches"]
            > max(row["branch64_matches"] for row in route_rows)
            and factual_projection["bit_accuracy"] > max(row["bit_accuracy"] for row in route_rows)
        ),
    }


def _proofs() -> dict[str, dict[str, Any]]:
    return {
        key: {
            "linear": _basis_linear_order_proof(variant),
            "quotient": _basis_quotient_order_proof(variant),
        }
        for key, variant in VARIANTS.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88928001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.seeds, args.routes) < 1:
        raise ValueError("pairs, seeds, and routes must be positive")

    kat = _kat()
    proofs = _proofs()
    causal = _build_graph(
        args.causal_output,
        proofs,
        args.pairs,
        args.seeds,
        args.routes,
    )
    recipes = _recipes_from_reader(args.causal_output)

    confirmations: dict[str, list[dict[str, Any]]] = {}
    for variant_index, (key, variant) in enumerate(VARIANTS.items()):
        rows = []
        for seed_index in range(args.seeds):
            seed = args.seed + 100_003 * variant_index + 1009 * seed_index
            rng = np.random.default_rng(seed)
            initial = rng.integers(
                0,
                1 << 32,
                size=(args.pairs, 2 * variant.branches),
                dtype=np.uint32,
            )
            print(
                f"{variant.name} endpoint Reader seed={seed_index + 1}/{args.seeds}",
                flush=True,
            )
            rows.append(
                {
                    "seed_index": seed_index,
                    "seed": seed,
                    **_confirm_seed(
                        variant,
                        initial,
                        recipes[key],
                        args.routes,
                        seed ^ 0x5A71,
                    ),
                }
            )
        confirmations[key] = rows

    retained = all(
        row["factual_projection_reader"]["state_accuracy"] == 1.0
        and row["factual_forward_power_fullstep_reader"]["state_accuracy"] == 1.0
        and row["factual_projection_above_all_bvn_routes"]
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "sparkle-fullstep-causal-v1",
        "evidence_stage": (
            "FULLSTEP_PROJECTION_AND_LINEAR_ORDER_RETAINED"
            if retained
            else "NEW_REPRESENTATION_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "At each standard full-permutation endpoint, the Reader reconstructs the "
            "complete pre-final-step left half from only the final right half. The same "
            "artifact records complete-basis proofs of the linear-layer and aggregate-quotient orders."
        ),
        "scope": (
            "Exact internal full-step relations and Reader inference; no claim about "
            "recovering an external secret is made by this experiment."
        ),
        "parameters": {
            "pairs_per_seed": args.pairs,
            "seeds": args.seeds,
            "bvn_routes": args.routes,
            "seed": args.seed,
        },
        "kat": kat,
        "proofs": proofs,
        "causal": causal,
        "reader_recipes": recipes,
        "confirmation": confirmations,
        "retained": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "retained": retained,
                "linear_orders": {
                    key: value["linear"]["identity_exponent"]
                    for key, value in proofs.items()
                },
                "quotient_orders": {
                    key: value["quotient"]["identity_exponent"]
                    for key, value in proofs.items()
                },
                "projection_state_matches": {
                    key: [row["factual_projection_reader"]["state_matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
                "bvn_total_state_matches": {
                    key: [row["bvn_routes"]["total_state_matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
