#!/usr/bin/env python3
"""Public ChaCha20 operator atlas transferred from the complete formula re-audit."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader

ATTEMPT_ID = "A199"
SCHEMA = "chacha20-formula-operator-atlas-v1"
PROTOCOL_SCHEMA = "chacha20-formula-operator-atlas-protocol-v1"
PROTOCOL_FILENAME = "chacha20_formula_operator_atlas_v1.json"
PROTOCOL_SHA256 = "cd24c2e342a401b2c47c248ade39d791476b9e2388fcecad583cdfdbf937d93a"
ATLAS_FILENAME = "formula_atlas_transfer_coverage_v1.json"
ATLAS_SHA256 = "feadca39a2cdb0caf38018e9d28ed6aecd56384f5771d7a6e6ab261f87ee1cc2"
ATLAS_CANDIDATE_SHA256 = "6b48da24730a5f2fd39497f1f7f34feab25860393382db8c2ce33f0976420d46"
A198_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.json"
A198_SHA256 = "693367464ab488c49d386c1d011e8c45e7fb094cceeb37352934dde121773373"
A198_CAUSAL_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.causal"
A198_CAUSAL_SHA256 = "b7c4e1302594e266c7958057221fb4101fb5ef5ee284792d6ca93e43386dd514"
SEED_LABEL = "f8-causal/A199/public-chacha20-operator-atlas/v1"
ROUNDS = 20
KEY_BITS = 20
OPERATOR_SAMPLES = 16
TRIPLET_SAMPLES = 64
NULL_REPLICATES = 32
ROOT_TOLERANCE = 1e-6
PARTITION_BITS = 5
RESULT_FILENAME = "chacha20_formula_operator_atlas_v1.json"
CAUSAL_FILENAME = "chacha20_formula_operator_atlas_v1.causal"
CONSTANTS = np.array(
    [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574],
    dtype=np.uint32,
)
POPCOUNT8 = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1)
FLIP_MASKS = np.zeros((512, 16), dtype=np.uint32)
FLIP_MASKS[np.arange(512), np.arange(512) // 32] = np.left_shift(
    np.uint32(1), np.arange(512, dtype=np.uint32) % 32
)
TRIPLETS = tuple(itertools.combinations(range(ROUNDS), 3))


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return _sha256(raw)


def _q(value: float, digits: int = 12) -> float:
    rounded = round(float(value), digits)
    return 0.0 if rounded == 0.0 else rounded


def _q_list(values: np.ndarray, digits: int = 12) -> list[Any]:
    return np.round(np.asarray(values, dtype=np.float64), digits).tolist()


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _load_protocol(results_dir: Path) -> dict[str, Any]:
    protocol_path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(protocol_path) != PROTOCOL_SHA256:
        raise RuntimeError("A199 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A198_and_full_formula_reaudit_before_any_A199_measurement"
        or protocol.get("transfer_families") != ["T01", "T02", "T03", "T04", "T05"]
        or boundary.get("A199_measurements_used_before_protocol_freeze") is not False
        or boundary.get("hidden_cipher_assignment_used") is not False
        or boundary.get("partition_masks_selected_from_public_data_only") is not True
        or boundary.get("solver_execution_in_A199") is not False
        or boundary.get("transfer_family_or_threshold_changed_after_any_A199_measurement")
        is not False
    ):
        raise RuntimeError("A199 frozen protocol identity gate failed")

    atlas_path = results_dir / ATLAS_FILENAME
    a198_path = results_dir / A198_FILENAME
    a198_causal_path = results_dir / A198_CAUSAL_FILENAME
    if (
        _file_sha256(atlas_path) != ATLAS_SHA256
        or _file_sha256(a198_path) != A198_SHA256
        or _file_sha256(a198_causal_path) != A198_CAUSAL_SHA256
    ):
        raise RuntimeError("A199 retained anchor hash gate failed")
    atlas = json.loads(atlas_path.read_bytes())
    a198 = json.loads(a198_path.read_bytes())
    a198_reader = CryptoCausalReader(a198_causal_path)
    if (
        atlas.get("candidate_registry_sha256") != ATLAS_CANDIDATE_SHA256
        or atlas.get("summary", {}).get("entries") != 2411
        or atlas.get("summary", {}).get("pages") != 113
        or a198.get("evidence_stage") != "ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_RETAINED"
        or a198.get("execution", {}).get("returned_model_count") != 0
        or a198_reader.file_sha256 != A198_CAUSAL_SHA256
        or not a198_reader.verify_provenance()
    ):
        raise RuntimeError("A199 retained anchor content gate failed")
    return protocol


def _rotl32(value: np.ndarray, amount: int) -> np.ndarray:
    return (value << np.uint32(amount)) | (value >> np.uint32(32 - amount))


def _rotr32(value: np.ndarray, amount: int) -> np.ndarray:
    return (value >> np.uint32(amount)) | (value << np.uint32(32 - amount))


def _quarter_round(state: np.ndarray, a: int, b: int, c: int, d: int) -> None:
    state[..., a] += state[..., b]
    state[..., d] = _rotl32(state[..., d] ^ state[..., a], 16)
    state[..., c] += state[..., d]
    state[..., b] = _rotl32(state[..., b] ^ state[..., c], 12)
    state[..., a] += state[..., b]
    state[..., d] = _rotl32(state[..., d] ^ state[..., a], 8)
    state[..., c] += state[..., d]
    state[..., b] = _rotl32(state[..., b] ^ state[..., c], 7)


def _inverse_quarter_round(state: np.ndarray, a: int, b: int, c: int, d: int) -> None:
    state[..., b] = _rotr32(state[..., b], 7) ^ state[..., c]
    state[..., c] -= state[..., d]
    state[..., d] = _rotr32(state[..., d], 8) ^ state[..., a]
    state[..., a] -= state[..., b]
    state[..., b] = _rotr32(state[..., b], 12) ^ state[..., c]
    state[..., c] -= state[..., d]
    state[..., d] = _rotr32(state[..., d], 16) ^ state[..., a]
    state[..., a] -= state[..., b]


def _round_quads(round_index: int) -> tuple[tuple[int, int, int, int], ...]:
    if round_index % 2 == 0:
        return ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
    return ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def _apply_round(state: np.ndarray, round_index: int) -> None:
    for quad in _round_quads(round_index):
        _quarter_round(state, *quad)


def _apply_inverse_round(state: np.ndarray, round_index: int) -> None:
    for quad in reversed(_round_quads(round_index)):
        _inverse_quarter_round(state, *quad)


def _core(initial: np.ndarray, rounds: int) -> np.ndarray:
    state = initial.copy()
    for round_index in range(rounds):
        _apply_round(state, round_index)
    return state


def _inverse_core(output: np.ndarray, rounds: int) -> np.ndarray:
    state = output.copy()
    for round_index in reversed(range(rounds)):
        _apply_inverse_round(state, round_index)
    return state


def _word_popcount(values: np.ndarray) -> np.ndarray:
    array = np.ascontiguousarray(values, dtype=np.uint32)
    byte_view = array.view(np.uint8).reshape(*array.shape, 4)
    return POPCOUNT8[byte_view].sum(axis=-1, dtype=np.uint16)


def _public_states(count: int) -> np.ndarray:
    raw = hashlib.shake_256(SEED_LABEL.encode()).digest(count * 12 * 4)
    words = np.frombuffer(raw, dtype="<u4").reshape(count, 12).copy()
    states = np.empty((count, 16), dtype=np.uint32)
    states[:, :4] = CONSTANTS
    states[:, 4:] = words
    return states


def _kat_gate() -> dict[str, Any]:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    initial = np.empty((1, 16), dtype=np.uint32)
    initial[0, :4] = CONSTANTS
    initial[0, 4:12] = np.frombuffer(key, dtype="<u4")
    initial[0, 12] = 1
    initial[0, 13:16] = np.frombuffer(nonce, dtype="<u4")
    output = (_core(initial, 20) + initial).astype("<u4").tobytes()
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    if output != expected:
        raise RuntimeError("A199 RFC 8439 ChaCha20 KAT failed")
    return {
        "name": "RFC_8439_section_2_3_2",
        "passed": True,
        "output_sha256": _sha256(output),
    }


def _base_cuts(initial: np.ndarray) -> list[np.ndarray]:
    cuts = [initial.copy()]
    current = initial.copy()
    for round_index in range(ROUNDS):
        _apply_round(current, round_index)
        cuts.append(current.copy())
    return cuts


def _inverse_gates(states: np.ndarray, cuts: list[np.ndarray]) -> dict[str, Any]:
    checked = []
    for rounds in range(1, ROUNDS + 1):
        recovered = _inverse_core(cuts[rounds], rounds)
        checked.append(bool(np.array_equal(recovered, states)))
    if not all(checked):
        raise RuntimeError("A199 ChaCha inverse round-trip gate failed")
    return {
        "round_depths_checked": ROUNDS,
        "states_per_depth": int(states.shape[0]),
        "all_exact": True,
        "initial_state_sha256": _sha256(states.astype("<u4").tobytes()),
        "final_cut_sha256": _sha256(cuts[-1].astype("<u4").tobytes()),
    }


def _normalize_columns(counts: np.ndarray) -> np.ndarray:
    matrix = np.asarray(counts, dtype=np.float64)
    totals = matrix.sum(axis=0)
    if np.any(totals <= 0):
        raise RuntimeError("A199 influence operator has an empty input column")
    return matrix / totals[None, :]


def _local_operators(cuts: list[np.ndarray]) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    forward = []
    aligned_inverse = []
    raw_hashes = []
    for round_index in range(ROUNDS):
        cut = cuts[round_index]
        output = cuts[round_index + 1]

        perturbed = (cut[:, None, :] ^ FLIP_MASKS[None, :, :]).reshape(-1, 16)
        _apply_round(perturbed, round_index)
        delta = perturbed.reshape(cut.shape[0], 512, 16) ^ output[:, None, :]
        hamming = _word_popcount(delta).reshape(cut.shape[0], 16, 32, 16)
        forward_counts = hamming.sum(axis=(0, 2), dtype=np.uint64).T

        output_perturbed = (output[:, None, :] ^ FLIP_MASKS[None, :, :]).reshape(-1, 16)
        _apply_inverse_round(output_perturbed, round_index)
        inverse_delta = output_perturbed.reshape(cut.shape[0], 512, 16) ^ cut[:, None, :]
        inverse_hamming = _word_popcount(inverse_delta).reshape(cut.shape[0], 16, 32, 16)
        inverse_counts = inverse_hamming.sum(axis=(0, 2), dtype=np.uint64)

        forward.append(_normalize_columns(forward_counts))
        aligned_inverse.append(_normalize_columns(inverse_counts))
        raw_hashes.append(
            {
                "round": round_index + 1,
                "forward_counts_sha256": _sha256(forward_counts.astype("<u8").tobytes()),
                "aligned_inverse_counts_sha256": _sha256(inverse_counts.astype("<u8").tobytes()),
                "forward_total_edges": int(forward_counts.sum()),
                "aligned_inverse_total_edges": int(inverse_counts.sum()),
            }
        )
    forward_array = np.stack(forward)
    inverse_array = np.stack(aligned_inverse)
    column_error = max(
        float(np.max(np.abs(forward_array.sum(axis=1) - 1.0))),
        float(np.max(np.abs(inverse_array.sum(axis=1) - 1.0))),
    )
    if column_error > 1e-12:
        raise RuntimeError("A199 column-stochastic normalization gate failed")
    return (
        forward_array,
        inverse_array,
        {
            "raw_round_hashes": raw_hashes,
            "maximum_column_sum_error": _q(column_error, 15),
            "forward_matrix_sha256": _sha256(forward_array.astype("<f8").tobytes()),
            "aligned_inverse_matrix_sha256": _sha256(inverse_array.astype("<f8").tobytes()),
        },
    )


def _key_trajectories(states: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    base = states.copy()
    variants = np.repeat(states[:, None, :], KEY_BITS, axis=1)
    variants[:, np.arange(KEY_BITS), 4] ^= np.left_shift(
        np.uint32(1), np.arange(KEY_BITS, dtype=np.uint32)
    )
    trajectories = np.empty((states.shape[0], KEY_BITS, ROUNDS), dtype=np.float64)
    profiles = np.empty((KEY_BITS, ROUNDS, 16), dtype=np.float64)
    for round_index in range(ROUNDS):
        _apply_round(base, round_index)
        flat = variants.reshape(-1, 16)
        _apply_round(flat, round_index)
        delta = variants ^ base[:, None, :]
        hamming = _word_popcount(delta)
        trajectories[:, :, round_index] = hamming.sum(axis=2) / 512.0
        profiles[:, round_index, :] = hamming.mean(axis=0)
    return trajectories, profiles


def _backward_key_profiles(initial: np.ndarray, cuts: list[np.ndarray]) -> np.ndarray:
    profiles = np.empty((KEY_BITS, ROUNDS, 16), dtype=np.float64)
    key_shifts = np.arange(KEY_BITS, dtype=np.uint32)
    for rounds in range(1, ROUNDS + 1):
        cut = cuts[rounds]
        perturbed = (cut[:, None, :] ^ FLIP_MASKS[None, :, :]).reshape(-1, 16)
        recovered = _inverse_core(perturbed, rounds).reshape(cut.shape[0], 512, 16)
        key_delta = recovered[:, :, 4] ^ initial[:, None, 4]
        changed = ((key_delta[:, :, None] >> key_shifts) & np.uint32(1)).astype(np.uint8)
        counts = changed.reshape(cut.shape[0], 16, 32, KEY_BITS).sum(axis=(0, 2), dtype=np.uint64)
        profiles[:, rounds - 1, :] = counts.T / float(cut.shape[0])
    return profiles


def _relative_frobenius(left: np.ndarray, right: np.ndarray) -> float:
    scale = 0.5 * (np.linalg.norm(left) + np.linalg.norm(right))
    return float(np.linalg.norm(left - right) / max(float(scale), np.finfo(float).tiny))


def _finite_matmul(left: np.ndarray, right: np.ndarray, label: str) -> np.ndarray:
    # Accelerate can surface stale floating-point flags after the preceding uint32
    # ARX kernels. Finiteness is therefore checked explicitly on every product.
    with np.errstate(all="ignore"):
        product = left @ right
    if not np.isfinite(product).all():
        raise RuntimeError(f"A199 non-finite matrix product: {label}")
    return product


def _dobrushin_column(matrix: np.ndarray) -> float:
    differences = np.abs(matrix[:, :, None] - matrix[:, None, :]).sum(axis=0)
    return 0.5 * float(np.max(differences))


def _birkhoff_regularized(matrix: np.ndarray, epsilon: float = 2.0**-20) -> float:
    positive = matrix + epsilon
    positive /= positive.sum(axis=0, keepdims=True)
    logged = np.log(positive)
    diameter = 0.0
    for left in range(matrix.shape[1]):
        for right in range(left + 1, matrix.shape[1]):
            ratio = logged[:, left] - logged[:, right]
            diameter = max(diameter, float(np.max(ratio) - np.min(ratio)))
    return math.tanh(diameter / 4.0)


def _t01(forward: np.ndarray) -> tuple[dict[str, Any], list[np.ndarray]]:
    adjacent = []
    for index in range(ROUNDS - 1):
        left = _finite_matmul(forward[index + 1], forward[index], f"adjacent-left-{index}")
        right = _finite_matmul(forward[index], forward[index + 1], f"adjacent-right-{index}")
        adjacent.append(_relative_frobenius(left, right))
    lag2 = []
    for index in range(ROUNDS - 2):
        left = _finite_matmul(forward[index + 2], forward[index], f"lag2-left-{index}")
        right = _finite_matmul(forward[index], forward[index + 2], f"lag2-right-{index}")
        lag2.append(_relative_frobenius(left, right))

    chronological = np.eye(16)
    reversed_order = np.eye(16)
    adjoint_control = np.eye(16)
    products = []
    depths = []
    for index, operator in enumerate(forward):
        chronological = _finite_matmul(operator, chronological, f"chronological-depth-{index + 1}")
        reversed_order = _finite_matmul(reversed_order, operator, f"reversed-depth-{index + 1}")
        adjoint_control = _finite_matmul(adjoint_control, operator.T, f"adjoint-depth-{index + 1}")
        products.append(chronological.copy())
        depths.append(
            {
                "depth": index + 1,
                "forward_reverse_relative_frobenius": _q(
                    _relative_frobenius(chronological, reversed_order)
                ),
                "adjoint_identity_error": _q(
                    float(np.linalg.norm(chronological.T - adjoint_control)), 15
                ),
                "chronological_dobrushin": _q(_dobrushin_column(chronological)),
                "reversed_dobrushin": _q(_dobrushin_column(reversed_order)),
                "chronological_birkhoff_regularized": _q(_birkhoff_regularized(chronological)),
            }
        )
    maximum_adjoint_error = max(row["adjoint_identity_error"] for row in depths)
    if maximum_adjoint_error > 1e-12:
        raise RuntimeError("A199 adjoint order identity gate failed")
    result = {
        "transfer_family": "T01",
        "adjacent_relative_commutators": [_q(value) for value in adjacent],
        "lag2_same_phase_relative_commutators": [_q(value) for value in lag2],
        "adjacent_summary": {
            "minimum": _q(min(adjacent)),
            "mean": _q(float(np.mean(adjacent))),
            "maximum": _q(max(adjacent)),
        },
        "lag2_summary": {
            "minimum": _q(min(lag2)),
            "mean": _q(float(np.mean(lag2))),
            "maximum": _q(max(lag2)),
        },
        "depth_products": depths,
        "regularization_epsilon": 2.0**-20,
        "maximum_adjoint_identity_error": maximum_adjoint_error,
        "prediction_retained": (
            max(adjacent) > 1e-3 and depths[-1]["forward_reverse_relative_frobenius"] > 1e-6
        ),
    }
    return result, products


def _stable_permutation(length: int, label: str) -> np.ndarray:
    raw = hashlib.shake_256(label.encode()).digest(length * 8)
    keys = np.frombuffer(raw, dtype="<u8")
    return np.argsort(keys, kind="stable")


def _triplet_values(centered: np.ndarray) -> np.ndarray:
    first = np.fromiter((row[0] for row in TRIPLETS), dtype=np.int16)
    second = np.fromiter((row[1] for row in TRIPLETS), dtype=np.int16)
    third = np.fromiter((row[2] for row in TRIPLETS), dtype=np.int16)
    return np.mean(
        centered[:, first] * centered[:, second] * centered[:, third],
        axis=0,
    )


def _t02(trajectories: np.ndarray) -> dict[str, Any]:
    flattened = trajectories.reshape(-1, ROUNDS)
    centered = flattened - flattened.mean(axis=0, keepdims=True)
    observed = _triplet_values(centered)
    observed_norm = float(np.linalg.norm(observed))
    observed_covariance = np.cov(flattened, rowvar=False, bias=True)
    np.fill_diagonal(observed_covariance, 0.0)
    observed_pair_norm = float(np.linalg.norm(observed_covariance))
    null_norms = []
    null_pair_norms = []
    for replicate in range(NULL_REPLICATES):
        shuffled = trajectories.copy()
        for bit in range(KEY_BITS):
            for round_index in range(ROUNDS):
                permutation = _stable_permutation(
                    trajectories.shape[0],
                    f"{SEED_LABEL}/T02/null/{replicate}/bit/{bit}/round/{round_index}",
                )
                shuffled[:, bit, round_index] = trajectories[permutation, bit, round_index]
        null_flat = shuffled.reshape(-1, ROUNDS)
        null_centered = null_flat - null_flat.mean(axis=0, keepdims=True)
        null_norms.append(float(np.linalg.norm(_triplet_values(null_centered))))
        null_covariance = np.cov(null_flat, rowvar=False, bias=True)
        np.fill_diagonal(null_covariance, 0.0)
        null_pair_norms.append(float(np.linalg.norm(null_covariance)))
    threshold = float(np.quantile(null_norms, 0.975, method="higher"))
    ordering = np.argsort(-np.abs(observed), kind="stable")[:20]
    top = [
        {
            "rounds": [value + 1 for value in TRIPLETS[index]],
            "centered_third_cumulant": _q(observed[index], 15),
            "absolute_value": _q(abs(observed[index]), 15),
        }
        for index in ordering
    ]
    return {
        "transfer_family": "T02",
        "sample_key_bit_rows": int(flattened.shape[0]),
        "triplet_count": len(TRIPLETS),
        "observed_l2_norm": _q(observed_norm, 15),
        "null_l2_norms": [_q(value, 15) for value in null_norms],
        "null_97_5_percentile_higher": _q(threshold, 15),
        "observed_to_null_mean_ratio": _q(observed_norm / float(np.mean(null_norms))),
        "empirical_upper_p_value": _q(
            (1 + sum(value >= observed_norm for value in null_norms)) / (NULL_REPLICATES + 1)
        ),
        "observed_pair_offdiagonal_frobenius": _q(observed_pair_norm),
        "null_pair_offdiagonal_frobenius": [_q(value) for value in null_pair_norms],
        "top_absolute_triplets": top,
        "same_marginals_exact": True,
        "prediction_retained": observed_norm > threshold,
    }


def _faddeev_leverrier(matrix: np.ndarray) -> np.ndarray:
    size = matrix.shape[0]
    identity = np.eye(size, dtype=np.complex128)
    work = identity.copy()
    coefficients = [1.0 + 0.0j]
    complex_matrix = matrix.astype(np.complex128)
    for order in range(1, size + 1):
        product = _finite_matmul(complex_matrix, work, f"faddeev-order-{order}")
        coefficient = -np.trace(product) / order
        coefficients.append(coefficient)
        work = product + coefficient * identity
    return np.asarray(coefficients, dtype=np.complex128)


def _normalized_root_residual(coefficients: np.ndarray, roots: np.ndarray) -> float:
    degree = len(coefficients) - 1
    residuals = []
    for root in roots:
        numerator = abs(np.polyval(coefficients, root))
        denominator = sum(
            abs(coefficient) * abs(root) ** (degree - index)
            for index, coefficient in enumerate(coefficients)
        )
        residuals.append(float(numerator / max(float(denominator), np.finfo(float).tiny)))
    return max(residuals, default=0.0)


def _sorted_complex(values: np.ndarray) -> list[list[float]]:
    rows = sorted(
        ((_q(value.real, 12), _q(value.imag, 12)) for value in values),
        key=lambda row: (row[0], row[1]),
    )
    return [[real, imaginary] for real, imaginary in rows]


def _root_diagnostic(matrix: np.ndarray, label: str) -> dict[str, Any]:
    independent_coefficients = _faddeev_leverrier(matrix)
    eigenvalues = np.linalg.eigvals(matrix.astype(np.complex128))
    coefficients = np.poly(eigenvalues).astype(np.complex128)
    derivative = np.polyder(coefficients)
    critical_roots = np.roots(derivative)
    eigen_reconstruction = np.poly(eigenvalues)
    critical_reconstruction = derivative[0] * np.poly(critical_roots)
    coefficient_scale = max(float(np.linalg.norm(coefficients)), np.finfo(float).tiny)
    derivative_scale = max(float(np.linalg.norm(derivative)), np.finfo(float).tiny)
    gates = {
        "independent_characteristic_coefficient_error": _q(
            float(np.linalg.norm(independent_coefficients - coefficients)) / coefficient_scale,
            15,
        ),
        "eigen_root_residual": _q(_normalized_root_residual(coefficients, eigenvalues), 15),
        "critical_root_residual": _q(_normalized_root_residual(derivative, critical_roots), 15),
        "eigen_coefficient_reconstruction_error": _q(
            float(np.linalg.norm(eigen_reconstruction - coefficients)) / coefficient_scale,
            15,
        ),
        "critical_coefficient_reconstruction_error": _q(
            float(np.linalg.norm(critical_reconstruction - derivative)) / derivative_scale,
            15,
        ),
    }
    maximum = max(gates.values())
    return {
        "label": label,
        "eigenvalues": _sorted_complex(eigenvalues),
        "critical_roots": _sorted_complex(critical_roots),
        "eigenvalue_radial_mean": _q(float(np.mean(np.abs(eigenvalues)))),
        "critical_root_radial_mean": _q(float(np.mean(np.abs(critical_roots)))),
        "gates": gates,
        "maximum_gate_error": maximum,
        "gate_passed": maximum <= ROOT_TOLERANCE,
    }


def _t03(forward: np.ndarray, products: list[np.ndarray]) -> dict[str, Any]:
    local = [
        _root_diagnostic(matrix, f"local_round_{index + 1}") for index, matrix in enumerate(forward)
    ]
    cumulative = [
        _root_diagnostic(matrix, f"cumulative_depth_{index + 1}")
        for index, matrix in enumerate(products)
    ]
    maximum = max(row["maximum_gate_error"] for row in [*local, *cumulative])
    return {
        "transfer_family": "T03",
        "characteristic_coefficient_method": (
            "eigenvalue_product_with_independent_Faddeev_LeVerrier_crosscheck"
        ),
        "numerical_stability_note": (
            "The direct Faddeev-LeVerrier coefficients cross-check the same matrix, while "
            "root residuals use the eigenvalue-product polynomial to avoid cancellation at "
            "near-zero roots; the frozen 1e-6 threshold is unchanged."
        ),
        "root_reconstruction_tolerance": ROOT_TOLERANCE,
        "local_operators": local,
        "cumulative_products": cumulative,
        "diagnostic_count": len(local) + len(cumulative),
        "maximum_gate_error": maximum,
        "prediction_retained": maximum <= ROOT_TOLERANCE,
    }


def _row_normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return matrix / np.maximum(norms, np.finfo(float).tiny)


def _orient_columns(vectors: np.ndarray) -> np.ndarray:
    oriented = vectors.copy()
    for column in range(oriented.shape[1]):
        pivot = int(np.argmax(np.abs(oriented[:, column])))
        if oriented[pivot, column] < 0:
            oriented[:, column] *= -1.0
    return oriented


def _t05(forward: np.ndarray, backward: np.ndarray) -> tuple[dict[str, Any], np.ndarray]:
    physical_sum = forward + backward
    signed_difference = forward - backward
    ratio = np.divide(
        signed_difference,
        physical_sum,
        out=np.zeros_like(signed_difference),
        where=physical_sum != 0,
    )
    swapped_sum = backward + forward
    swapped_difference = backward - forward
    sum_swap_error = float(np.max(np.abs(physical_sum - swapped_sum)))
    difference_swap_error = float(np.max(np.abs(signed_difference + swapped_difference)))
    forward_flat = _row_normalize(forward.reshape(KEY_BITS, -1))
    backward_flat = _row_normalize(backward.reshape(KEY_BITS, -1))
    cross = _finite_matmul(forward_flat, backward_flat.T, "T05-cross-copy")
    left, singular_values, right_t = np.linalg.svd(cross, full_matrices=True)
    left = _orient_columns(left)
    right = _orient_columns(right_t.T)
    signed_relative = _relative_frobenius(forward, backward)
    prediction = (
        signed_relative > 1e-3 and sum_swap_error <= 1e-12 and difference_swap_error <= 1e-12
    )
    features = np.concatenate(
        [
            forward_flat,
            backward_flat,
            _row_normalize(ratio.reshape(KEY_BITS, -1)),
            left * singular_values[None, :],
            right * singular_values[None, :],
        ],
        axis=1,
    )
    return {
        "transfer_family": "T05",
        "signed_channel_relative_frobenius": _q(signed_relative),
        "physical_sum_copy_swap_error": _q(sum_swap_error, 15),
        "signed_difference_copy_swap_error": _q(difference_swap_error, 15),
        "zero_denominator_count": int(np.count_nonzero(physical_sum == 0)),
        "cross_copy_singular_values": [_q(value) for value in singular_values],
        "cross_copy_effective_rank_1e_10": int(
            np.count_nonzero(singular_values > singular_values[0] * 1e-10)
        ),
        "forward_profile_sha256": _sha256(forward.astype("<f8").tobytes()),
        "backward_profile_sha256": _sha256(backward.astype("<f8").tobytes()),
        "ratio_profile_sha256": _sha256(ratio.astype("<f8").tobytes()),
        "prediction_retained": prediction,
    }, features


def _gf2_rank(masks: list[int], width: int = KEY_BITS) -> int:
    rows = masks.copy()
    rank = 0
    for bit in reversed(range(width)):
        pivot = next((index for index in range(rank, len(rows)) if rows[index] >> bit & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for index in range(len(rows)):
            if index != rank and rows[index] >> bit & 1:
                rows[index] ^= rows[rank]
        rank += 1
    return rank


def _partition_from_masks(masks: list[int]) -> dict[str, Any]:
    values = np.arange(1 << KEY_BITS, dtype=np.uint32)
    syndrome = np.zeros(values.shape, dtype=np.uint8)
    for index, mask in enumerate(masks):
        parity = (_word_popcount(values & np.uint32(mask)) & 1).astype(np.uint8)
        syndrome |= parity << np.uint8(index)
    histogram = np.bincount(syndrome, minlength=1 << len(masks))
    return {
        "binary_rank": _gf2_rank(masks),
        "cell_histogram": histogram.astype(int).tolist(),
        "cell_count": int(histogram.size),
        "minimum_cell_size": int(histogram.min()),
        "maximum_cell_size": int(histogram.max()),
        "syndrome_map_sha256": _sha256(syndrome.tobytes()),
        "complete_candidate_count": int(histogram.sum()),
    }


def _t04(features: np.ndarray) -> dict[str, Any]:
    normalized = _row_normalize(features)
    distances = np.sum((normalized[:, None, :] - normalized[None, :, :]) ** 2, axis=2)
    positive = distances[np.triu_indices(KEY_BITS, 1)]
    sigma2 = float(np.median(positive[positive > 0]))
    adjacency = np.exp(-distances / max(2.0 * sigma2, np.finfo(float).tiny))
    np.fill_diagonal(adjacency, 0.0)
    degrees = adjacency.sum(axis=1)
    inverse_sqrt = 1.0 / np.sqrt(degrees)
    laplacian = np.eye(KEY_BITS) - (inverse_sqrt[:, None] * adjacency * inverse_sqrt[None, :])
    eigenvalues, eigenvectors = np.linalg.eigh(laplacian)
    eigenvectors = _orient_columns(eigenvectors)

    chosen_masks: list[int] = []
    chosen = []
    candidates = []
    for mode in range(1, KEY_BITS):
        vector = eigenvectors[:, mode]
        order = sorted(range(KEY_BITS), key=lambda index: (-vector[index], index))
        for selected_count in range(8, 13):
            selected = sorted(order[:selected_count])
            mask = sum(1 << bit for bit in selected)
            before = _gf2_rank(chosen_masks)
            after = _gf2_rank([*chosen_masks, mask])
            row = {
                "mode_index": mode,
                "laplacian_eigenvalue": _q(eigenvalues[mode]),
                "selected_count": selected_count,
                "selected_key_bits": selected,
                "mask_hex": f"0x{mask:05x}",
                "increases_binary_rank": after > before,
            }
            candidates.append(row)
            if after > before and len(chosen_masks) < PARTITION_BITS:
                chosen_masks.append(mask)
                chosen.append(row)
            if len(chosen_masks) == PARTITION_BITS:
                break
        if len(chosen_masks) == PARTITION_BITS:
            break
    if len(chosen_masks) != PARTITION_BITS:
        raise RuntimeError("A199 could not derive five independent public masks")

    numeric_masks = [1 << bit for bit in range(19, 14, -1)]
    gray_masks = [
        1 << 19,
        (1 << 19) | (1 << 18),
        (1 << 18) | (1 << 17),
        (1 << 17) | (1 << 16),
        (1 << 16) | (1 << 15),
    ]
    spectral_partition = _partition_from_masks(chosen_masks)
    numeric_partition = _partition_from_masks(numeric_masks)
    gray_partition = _partition_from_masks(gray_masks)
    exact = (
        spectral_partition["binary_rank"] == PARTITION_BITS
        and spectral_partition["cell_histogram"] == [1 << 15] * 32
    )
    return {
        "transfer_family": "T04",
        "graph": {
            "feature_shape": list(features.shape),
            "distance_scale_median_squared": _q(sigma2),
            "adjacency_sha256": _sha256(adjacency.astype("<f8").tobytes()),
            "normalized_laplacian_sha256": _sha256(laplacian.astype("<f8").tobytes()),
            "laplacian_eigenvalues": [_q(value) for value in eigenvalues],
            "minimum_degree": _q(float(degrees.min())),
            "maximum_degree": _q(float(degrees.max())),
        },
        "candidate_count_examined": len(candidates),
        "chosen_masks": chosen,
        "chosen_mask_hex_order": [f"0x{mask:05x}" for mask in chosen_masks],
        "spectral_partition": spectral_partition,
        "numeric_prefix_control": {
            "mask_hex_order": [f"0x{mask:05x}" for mask in numeric_masks],
            **numeric_partition,
        },
        "gray_prefix_control": {
            "mask_hex_order": [f"0x{mask:05x}" for mask in gray_masks],
            **gray_partition,
        },
        "prediction_retained": exact,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_formula_operator_atlas",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "operator_samples": OPERATOR_SAMPLES,
            "triplet_samples": TRIPLET_SAMPLES,
            "triplets": len(TRIPLETS),
            "null_replicates": NULL_REPLICATES,
        },
    )
    rows = [
        (
            "a199-formula-audit-anchor",
            "formula_atlas:2411_entries_113_pages",
            "select_T01_through_T05_without_keyword_prefilter",
            "A199:predeclared_public_operator_program",
            "complete_formula_reaudit_transfer",
            ATLAS_SHA256,
            [],
            {"protocol_sha256": PROTOCOL_SHA256},
        ),
        (
            "a199-a198-boundary-anchor",
            "A198:two_complete_round10_b8_covers_all_unknown",
            "replace_uniform_prefix_refinement_with_public_geometry",
            "A199:representation_change_requirement",
            "retained_round10_resource_boundary",
            A198_CAUSAL_SHA256,
            [],
            {"A198_sha256": A198_SHA256},
        ),
        (
            "a199-public-cha-cha-operators",
            "A199:predeclared_public_operator_program",
            "execute_RFC_and_inverse_gates_then_build_forward_inverse_operators",
            "A199:twenty_public_round_operators",
            "public_cipher_operator_construction",
            payload["operator_sha256"],
            ["a199-formula-audit-anchor"],
            {"operator_gates": payload["operator_gates"]},
        ),
        (
            "a199-t01-ordered-products",
            "A199:twenty_public_round_operators",
            "compare_chronological_reverse_commutator_and_adjoint_products",
            "A199:T01_noncommutative_order_result",
            "ordered_product_and_commutator_transfer",
            payload["T01_sha256"],
            ["a199-public-cha-cha-operators"],
            {"summary": payload["T01"]["adjacent_summary"]},
        ),
        (
            "a199-t02-triplet-cumulants",
            "A199:predeclared_public_operator_program",
            "measure_all_1140_centered_triplets_against_32_same_marginal_nulls",
            "A199:T02_triplet_dependence_result",
            "genuine_triplet_cumulant_transfer",
            payload["T02_sha256"],
            ["a199-formula-audit-anchor"],
            {
                "observed_l2_norm": payload["T02"]["observed_l2_norm"],
                "null_97_5_percentile": payload["T02"]["null_97_5_percentile_higher"],
            },
        ),
        (
            "a199-t03-derivative-roots",
            "A199:twenty_public_round_operators",
            "reconstruct_characteristic_and_derivative_root_views_with_residual_gates",
            "A199:T03_critical_root_result",
            "characteristic_derivative_root_transfer",
            payload["T03_sha256"],
            ["a199-public-cha-cha-operators"],
            {"maximum_gate_error": payload["T03"]["maximum_gate_error"]},
        ),
        (
            "a199-t05-sum-difference",
            "A199:twenty_public_round_operators",
            "align_forward_key_and_inverse_cut_channels_then_apply_copy_swap_control",
            "A199:T05_sum_difference_result",
            "z2_sum_difference_and_cross_copy_svd_transfer",
            payload["T05_sha256"],
            ["a199-public-cha-cha-operators"],
            {"signed_relative_frobenius": payload["T05"]["signed_channel_relative_frobenius"]},
        ),
        (
            "a199-t04-public-partition",
            "A199:representation_change_requirement",
            "construct_a_public_key_bit_graph_from_T05_channels_then_quantize_low_modes",
            "A199:T04_exact_complete_public_partition",
            "fiedler_multimode_complete_partition_transfer",
            payload["T04_sha256"],
            [
                "a199-a198-boundary-anchor",
                "a199-t05-sum-difference",
            ],
            {"chosen_masks": payload["T04"]["chosen_mask_hex_order"]},
        ),
    ]
    for edge_id, trigger, mechanism, outcome, kind, source, provenance, attrs in rows:
        builder.add_triplet(
            edge_id=edge_id,
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    explicit = reader.triplets(include_inferred=False)
    if len(explicit) != len(rows) or not reader.verify_provenance():
        raise RuntimeError("A199 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(explicit),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    protocol = _load_protocol(results_dir)
    kat = _kat_gate()
    states = _public_states(TRIPLET_SAMPLES)
    operator_states = states[:OPERATOR_SAMPLES]
    cuts = _base_cuts(operator_states)
    inverse_gates = _inverse_gates(operator_states, cuts)
    forward_operators, inverse_operators, operator_gates = _local_operators(cuts)
    trajectories, _ = _key_trajectories(states)
    _, forward_key_profiles = _key_trajectories(operator_states)
    backward_key_profiles = _backward_key_profiles(operator_states, cuts)

    t01, products = _t01(forward_operators)
    t02 = _t02(trajectories)
    t03 = _t03(forward_operators, products)
    t05, features = _t05(
        forward_key_profiles[:, :, :],
        backward_key_profiles,
    )
    t04 = _t04(features)

    predictions = {
        "H1_noncommutative_order": t01["prediction_retained"],
        "H2_triplet_dependence": t02["prediction_retained"],
        "H3_derivative_root_gate": t03["prediction_retained"],
        "H4_complete_public_partition": t04["prediction_retained"],
        "H5_sum_difference": t05["prediction_retained"],
    }
    evidence_stage = (
        "PUBLIC_FORMULA_OPERATOR_ATLAS_ALL_PREDICTIONS_RETAINED"
        if all(predictions.values())
        else "PUBLIC_FORMULA_OPERATOR_ATLAS_MIXED_BOUNDARY_RETAINED"
    )
    operator_payload = {
        "forward_word_operators": _q_list(forward_operators),
        "aligned_inverse_word_operators": _q_list(inverse_operators),
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A public ChaCha20 influence-operator atlas executes formula transfers "
            "T01 through T05 and derives an exact five-bit affine partition map."
        ),
        "scope": (
            "Public deterministic operator discovery only; A199 performs no secret-key "
            "solver run and makes no key-recovery claim."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchors": {
            "formula_atlas_sha256": ATLAS_SHA256,
            "formula_atlas_candidate_registry_sha256": ATLAS_CANDIDATE_SHA256,
            "A198_result_sha256": A198_SHA256,
            "A198_causal_sha256": A198_CAUSAL_SHA256,
        },
        "parameters": {
            "seed_label": SEED_LABEL,
            "rounds": ROUNDS,
            "key_bits": KEY_BITS,
            "operator_samples": OPERATOR_SAMPLES,
            "triplet_samples": TRIPLET_SAMPLES,
            "triplets": len(TRIPLETS),
            "null_replicates": NULL_REPLICATES,
            "partition_bits": PARTITION_BITS,
        },
        "public_input": {
            "states_sha256": _sha256(states.astype("<u4").tobytes()),
            "operator_states_sha256": _sha256(operator_states.astype("<u4").tobytes()),
            "hidden_assignment_present": False,
        },
        "implementation_gates": {
            "RFC_8439_KAT": kat,
            "inverse_roundtrip": inverse_gates,
        },
        "operator_gates": operator_gates,
        "operators": operator_payload,
        "operator_sha256": _canonical_sha256(operator_payload),
        "T01": t01,
        "T01_sha256": _canonical_sha256(t01),
        "T02": t02,
        "T02_sha256": _canonical_sha256(t02),
        "T03": t03,
        "T03_sha256": _canonical_sha256(t03),
        "T04": t04,
        "T04_sha256": _canonical_sha256(t04),
        "T05": t05,
        "T05_sha256": _canonical_sha256(t05),
        "prospective_predictions_retained": predictions,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A199 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "predictions": predictions,
        "chosen_masks": t04["chosen_mask_hex_order"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
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
    summary = run(
        results_dir=args.results_dir.resolve(),
        output=args.output.resolve(),
        causal_output=args.causal_output.resolve(),
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
