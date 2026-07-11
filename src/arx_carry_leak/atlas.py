"""Shared information-heatmap primitives for multi-cipher output studies."""

from __future__ import annotations

import itertools
from typing import Any

import numpy as np

from .live_casi_v091.ciphers import _AES_SBOX, _aes_key_expansion, _aes_xtime


def rows32(raw: bytes, *, limit: int | None = None) -> np.ndarray:
    """Return complete 32-byte rows without silently padding an output."""
    usable = len(raw) - len(raw) % 32
    rows = np.frombuffer(raw[:usable], dtype=np.uint8).reshape(-1, 32).copy()
    if limit is not None:
        rows = rows[:limit]
    if len(rows) < 2:
        raise ValueError("at least two complete 32-byte rows are required")
    return rows


def mutual_information_matrix(
    source_rows: np.ndarray, outcome_rows: np.ndarray, *, shift: int = 5
) -> np.ndarray:
    """Compute I(source byte_i; outcome byte_j) after equal quantization."""
    if source_rows.shape != outcome_rows.shape or source_rows.ndim != 2:
        raise ValueError("source and outcome must be equally shaped matrices")
    if not 0 <= shift <= 7:
        raise ValueError("shift must be in [0, 7]")
    bins = 2 ** (8 - shift)
    source = source_rows >> shift
    outcome = outcome_rows >> shift
    matrix = np.zeros((source.shape[1], outcome.shape[1]), dtype=float)
    for i in range(source.shape[1]):
        for j in range(outcome.shape[1]):
            counts = np.bincount(
                source[:, i].astype(np.int64) * bins + outcome[:, j],
                minlength=bins * bins,
            ).reshape(bins, bins)
            joint = counts / counts.sum()
            independent = joint.sum(axis=1, keepdims=True) @ joint.sum(axis=0, keepdims=True)
            valid = joint > 0
            matrix[i, j] = float(
                np.sum(joint[valid] * np.log2(joint[valid] / independent[valid]))
            )
    return matrix


def sequential_delta_heatmap(rows: np.ndarray, *, shift: int = 5) -> np.ndarray:
    """Measure I(row_t[i]; (row_t XOR row_t+1)[j])."""
    if rows.ndim != 2 or rows.shape[1] != 32:
        raise ValueError("rows must have shape (n, 32)")
    return mutual_information_matrix(rows[:-1], rows[:-1] ^ rows[1:], shift=shift)


def positional_entropy(rows: np.ndarray) -> np.ndarray:
    """Shannon entropy in bits for each byte position."""
    entropies = np.zeros(rows.shape[1], dtype=float)
    for index in range(rows.shape[1]):
        counts = np.bincount(rows[:, index], minlength=256)
        probabilities = counts[counts > 0] / len(rows)
        entropies[index] = -float(np.sum(probabilities * np.log2(probabilities)))
    return entropies


def permutation_control(
    rows: np.ndarray, *, shift: int, permutations: int, seed: int
) -> dict[str, Any]:
    """Compare the observed row order with deterministic order-breaking controls."""
    if permutations < 2:
        raise ValueError("at least two permutations are required")
    observed = sequential_delta_heatmap(rows, shift=shift)
    rng = np.random.default_rng(seed)
    controls = np.stack(
        [sequential_delta_heatmap(rows[rng.permutation(len(rows))], shift=shift) for _ in range(permutations)]
    )
    mean = controls.mean(axis=0)
    sd = controls.std(axis=0, ddof=1)
    return {
        "observed": observed,
        "control_mean": mean,
        "control_sd": sd,
        "excess": observed - mean,
        "z_score": (observed - mean) / np.maximum(sd, 1e-12),
        "control_matrices": controls,
    }


def exact_sign_flip_test(differences: list[float]) -> dict[str, float | int]:
    """Exact paired randomization test for a small multi-seed experiment."""
    values = np.asarray(differences, dtype=float)
    observed = float(values.mean())
    null = np.asarray(
        [np.mean(values * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(values))]
    )
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "mean_difference": observed,
        "seed_pairs": len(values),
        "exact_assignments": len(null),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def cosine_similarity(first: np.ndarray, second: np.ndarray) -> float:
    left = np.asarray(first, dtype=float).ravel()
    right = np.asarray(second, dtype=float).ravel()
    denominator = float(np.linalg.norm(left) * np.linalg.norm(right))
    return float(np.dot(left, right) / denominator) if denominator else 0.0


def aes_prefix_batch(key: np.ndarray, plaintexts: np.ndarray, rounds: int) -> np.ndarray:
    """Return a genuine AES-128 prefix with MixColumns in rounds 1 through 9."""
    if not 1 <= rounds <= 10:
        raise ValueError("AES prefix rounds must be in [1, 10]")
    round_keys = _aes_key_expansion(key).reshape(11, 4, 4).transpose(0, 2, 1)
    state = plaintexts.reshape(-1, 4, 4).transpose(0, 2, 1).copy()
    state ^= round_keys[0][None, :, :]
    for round_index in range(1, rounds + 1):
        state = _AES_SBOX[state]
        for row in range(1, 4):
            state[:, row, :] = np.roll(state[:, row, :], -row, axis=1)
        if round_index < 10:
            s0, s1, s2, s3 = (state[:, index, :].copy() for index in range(4))
            x0, x1, x2, x3 = (_aes_xtime(value) for value in (s0, s1, s2, s3))
            state[:, 0, :] = x0 ^ x1 ^ s1 ^ s2 ^ s3
            state[:, 1, :] = s0 ^ x1 ^ x2 ^ s2 ^ s3
            state[:, 2, :] = s0 ^ s1 ^ x2 ^ x3 ^ s3
            state[:, 3, :] = x0 ^ s0 ^ s1 ^ s2 ^ x3
        state ^= round_keys[round_index][None, :, :]
    return state.transpose(0, 2, 1).reshape(-1, 16)


def _aes_gf_mul(values: np.ndarray, factor: int) -> np.ndarray:
    """Multiply AES field elements by a public constant."""
    result = np.zeros_like(values)
    term = values.copy()
    multiplier = factor
    while multiplier:
        if multiplier & 1:
            result ^= term
        term = _aes_xtime(term)
        multiplier >>= 1
    return result


def aes_inverse_linear_layer(blocks: np.ndarray) -> np.ndarray:
    """Undo AES MixColumns and ShiftRows on a matrix of 16-byte blocks.

    Applied to an output XOR difference from prefix rounds 1-9, this removes
    the public final linear layer; the final AddRoundKey cancels in the XOR.
    """
    if blocks.ndim != 2 or blocks.shape[1] != 16 or blocks.dtype != np.uint8:
        raise ValueError("blocks must be a uint8 matrix with shape (n, 16)")
    state = blocks.reshape(-1, 4, 4).transpose(0, 2, 1).copy()
    s0, s1, s2, s3 = (state[:, index, :].copy() for index in range(4))
    state[:, 0, :] = (
        _aes_gf_mul(s0, 14) ^ _aes_gf_mul(s1, 11) ^ _aes_gf_mul(s2, 13) ^ _aes_gf_mul(s3, 9)
    )
    state[:, 1, :] = (
        _aes_gf_mul(s0, 9) ^ _aes_gf_mul(s1, 14) ^ _aes_gf_mul(s2, 11) ^ _aes_gf_mul(s3, 13)
    )
    state[:, 2, :] = (
        _aes_gf_mul(s0, 13) ^ _aes_gf_mul(s1, 9) ^ _aes_gf_mul(s2, 14) ^ _aes_gf_mul(s3, 11)
    )
    state[:, 3, :] = (
        _aes_gf_mul(s0, 11) ^ _aes_gf_mul(s1, 13) ^ _aes_gf_mul(s2, 9) ^ _aes_gf_mul(s3, 14)
    )
    for row in range(1, 4):
        state[:, row, :] = np.roll(state[:, row, :], row, axis=1)
    return state.transpose(0, 2, 1).reshape(-1, 16)


def aes_inverse_shift_rows(blocks: np.ndarray) -> np.ndarray:
    """Undo the public ShiftRows permutation on AES blocks or differences."""
    if blocks.ndim != 2 or blocks.shape[1] != 16 or blocks.dtype != np.uint8:
        raise ValueError("blocks must be a uint8 matrix with shape (n, 16)")
    state = blocks.reshape(-1, 4, 4).transpose(0, 2, 1).copy()
    for row in range(1, 4):
        state[:, row, :] = np.roll(state[:, row, :], row, axis=1)
    return state.transpose(0, 2, 1).reshape(-1, 16)


def aes_counter_blocks(count: int, rounds: int, seed: int) -> np.ndarray:
    """Encrypt little-endian 64-bit counters under one seeded AES-128 key."""
    rng = np.random.default_rng(seed)
    key = rng.integers(0, 256, size=16, dtype=np.uint8)
    plaintexts = np.zeros((count, 16), dtype=np.uint8)
    counters = np.arange(count, dtype=np.uint64)
    for byte in range(8):
        plaintexts[:, byte] = ((counters >> (8 * byte)) & 0xFF).astype(np.uint8)
    return aes_prefix_batch(key, plaintexts, rounds)


def chacha_counter_blocks(counters: np.ndarray, rounds: int, seed: int, *, feedforward: bool = True) -> np.ndarray:
    """Evaluate seeded ChaCha blocks at an explicit uint32 counter traversal.

    ``feedforward=False`` returns the pre-addition ChaCha core in the same
    little-endian byte layout.  It is an explicit representation ablation for
    causal experiments; the default remains the standard ChaCha block output.
    """
    values = np.asarray(counters)
    if values.ndim != 1 or not np.issubdtype(values.dtype, np.integer):
        raise ValueError("counters must be a one-dimensional integer array")
    if np.any(values < 0) or np.any(values > np.iinfo(np.uint32).max):
        raise ValueError("ChaCha counters must fit uint32")
    rng = np.random.RandomState(seed)
    key = rng.bytes(32)
    nonce = rng.bytes(12)
    state = np.zeros((len(values), 16), dtype=np.uint32)
    state[:, :4] = np.asarray([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
    state[:, 4:12] = np.frombuffer(key, dtype="<u4")
    state[:, 12] = values.astype(np.uint32)
    state[:, 13:16] = np.frombuffer(nonce, dtype="<u4")
    initial = state.copy()

    def rotate_left(value: np.ndarray, bits: int) -> np.ndarray:
        return ((value << np.uint32(bits)) | (value >> np.uint32(32 - bits))).astype(np.uint32)

    def quarter_round(a: int, b: int, c: int, d: int) -> None:
        state[:, a] += state[:, b]
        state[:, d] = rotate_left(state[:, d] ^ state[:, a], 16)
        state[:, c] += state[:, d]
        state[:, b] = rotate_left(state[:, b] ^ state[:, c], 12)
        state[:, a] += state[:, b]
        state[:, d] = rotate_left(state[:, d] ^ state[:, a], 8)
        state[:, c] += state[:, d]
        state[:, b] = rotate_left(state[:, b] ^ state[:, c], 7)

    for round_index in range(rounds):
        if round_index % 2 == 0:
            quarter_round(0, 4, 8, 12)
            quarter_round(1, 5, 9, 13)
            quarter_round(2, 6, 10, 14)
            quarter_round(3, 7, 11, 15)
        else:
            quarter_round(0, 5, 10, 15)
            quarter_round(1, 6, 11, 12)
            quarter_round(2, 7, 8, 13)
            quarter_round(3, 4, 9, 14)
    output = state + initial if feedforward else state
    return output.astype("<u4", copy=False).view(np.uint8).reshape(len(values), 64).copy()
