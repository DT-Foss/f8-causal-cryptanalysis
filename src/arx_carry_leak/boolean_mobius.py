"""Exact local Boolean-Mobius models for controlled bit interventions.

The first axis always indexes intervention subsets or candidate keys.  Every
remaining axis is treated as an opaque bit-packed payload, so the same code
works for ChaCha states, outputs, and carry masks without converting them to
individual Boolean columns.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Sequence

import numpy as np


_BYTE_POPCOUNT = np.asarray([value.bit_count() for value in range(256)], dtype=np.uint8)


def subset_masks(width: int, maximum_order: int) -> tuple[int, ...]:
    """Return all masks through ``maximum_order`` in degree/lexicographic order."""
    if isinstance(width, bool) or not isinstance(width, int) or width < 1:
        raise ValueError("width must be a positive integer")
    if (
        isinstance(maximum_order, bool)
        or not isinstance(maximum_order, int)
        or maximum_order < 0
        or maximum_order > width
    ):
        raise ValueError("maximum_order must be an integer in [0, width]")
    masks: list[int] = []
    for order in range(maximum_order + 1):
        masks.extend(
            sum(1 << bit for bit in combination)
            for combination in itertools.combinations(range(width), order)
        )
    return tuple(masks)


def intervention_values(center: int, masks: Sequence[int], width: int) -> np.ndarray:
    """Map local intervention masks to global candidate values."""
    limit = 1 << width
    if isinstance(center, bool) or not isinstance(center, int) or not 0 <= center < limit:
        raise ValueError("center must fit width bits")
    checked = _checked_masks(masks, width)
    return np.asarray([center ^ mask for mask in checked], dtype=_unsigned_dtype(width))


def local_mobius_coefficients(
    evaluations: np.ndarray,
    masks: Sequence[int],
    *,
    width: int,
    maximum_order: int,
) -> np.ndarray:
    """Recover exact local ANF coefficients from subset-intervention values.

    ``evaluations[j]`` must equal ``F(center xor masks[j])``.  The center does
    not enter the transform: it only defines the local coordinates.  Inputs
    may be bool or any integer dtype; XOR is applied bitwise to the payload.
    """
    values = _checked_payload(evaluations, "evaluations")
    checked = _checked_complete_masks(masks, width, maximum_order)
    if values.shape[0] != len(checked):
        raise ValueError("evaluations and masks must have the same first dimension")
    row_by_mask = {mask: row for row, mask in enumerate(checked)}
    coefficients = np.empty_like(values)
    for output_row, mask in enumerate(checked):
        rows: list[int] = []
        subset = mask
        while True:
            rows.append(row_by_mask[subset])
            if subset == 0:
                break
            subset = (subset - 1) & mask
        coefficients[output_row] = np.bitwise_xor.reduce(values[rows], axis=0)
    return coefficients


def evaluate_local_mobius(
    coefficients: np.ndarray,
    masks: Sequence[int],
    candidates: Iterable[int] | np.ndarray,
    *,
    center: int,
    width: int,
    maximum_order: int | None = None,
) -> np.ndarray:
    """Evaluate a local truncated ANF on an arbitrary candidate sequence."""
    values = _checked_payload(coefficients, "coefficients")
    checked = _checked_masks(masks, width)
    if values.shape[0] != len(checked):
        raise ValueError("coefficients and masks must have the same first dimension")
    available_order = max(mask.bit_count() for mask in checked)
    order = available_order if maximum_order is None else maximum_order
    if isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= available_order:
        raise ValueError("maximum_order exceeds the available coefficient order")
    candidate_array = _checked_candidates(candidates, width)
    delta = candidate_array ^ np.asarray(center, dtype=candidate_array.dtype)
    output = np.zeros((len(candidate_array), *values.shape[1:]), dtype=values.dtype)
    for row, mask in enumerate(checked):
        if mask.bit_count() > order:
            continue
        selected = (delta & mask) == mask
        if np.any(selected):
            output[selected] ^= values[row]
    return output


def local_truth_table(
    coefficients: np.ndarray,
    masks: Sequence[int],
    *,
    width: int,
    maximum_order: int | None = None,
) -> np.ndarray:
    """Expand local ANF coefficients to all ``2**width`` local assignments."""
    values = _checked_payload(coefficients, "coefficients")
    checked = _checked_masks(masks, width)
    if values.shape[0] != len(checked):
        raise ValueError("coefficients and masks must have the same first dimension")
    available_order = max(mask.bit_count() for mask in checked)
    order = available_order if maximum_order is None else maximum_order
    if isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= available_order:
        raise ValueError("maximum_order exceeds the available coefficient order")
    table = np.zeros((1 << width, *values.shape[1:]), dtype=values.dtype)
    for row, mask in enumerate(checked):
        if mask.bit_count() <= order:
            table[mask] = values[row]
    subset_zeta_xor_inplace(table, width=width)
    return table


def subset_zeta_xor_inplace(table: np.ndarray, *, width: int) -> None:
    """Apply the subset zeta transform over GF(2) to the first axis in place."""
    values = _checked_payload(table, "table")
    if values.shape[0] != 1 << width:
        raise ValueError("table first dimension must equal 2**width")
    for bit in range(width):
        step = 1 << bit
        view = values.reshape(-1, step << 1, *values.shape[1:])
        view[:, step:] ^= view[:, :step]


def packed_hamming_distance(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    """Return row-wise Hamming distances for equally shaped uint8 payloads."""
    left = np.asarray(first)
    right = np.asarray(second)
    if left.dtype != np.uint8 or right.dtype != np.uint8:
        raise TypeError("packed Hamming inputs must use uint8")
    if left.shape != right.shape or left.ndim < 2:
        raise ValueError("packed Hamming inputs must have equal shape and at least two axes")
    difference = np.bitwise_xor(left, right)
    return np.sum(_BYTE_POPCOUNT[difference], axis=tuple(range(1, difference.ndim)), dtype=np.uint64)


def hamming_weight(values: Iterable[int] | np.ndarray, *, width: int) -> np.ndarray:
    """Return the Hamming weight of each checked ``width``-bit integer."""
    checked = _checked_candidates(values, width)
    raw = checked.view(np.uint8).reshape(len(checked), checked.dtype.itemsize)
    return np.sum(_BYTE_POPCOUNT[raw], axis=1, dtype=np.uint16)


def nearest_center_indices(
    candidates: Iterable[int] | np.ndarray,
    centers: Sequence[int],
    *,
    width: int,
) -> np.ndarray:
    """Choose the nearest center; input order is the deterministic tie break."""
    checked_candidates = _checked_candidates(candidates, width)
    if not centers:
        raise ValueError("at least one center is required")
    limit = 1 << width
    if any(
        isinstance(center, bool) or not isinstance(center, int) or not 0 <= center < limit
        for center in centers
    ):
        raise ValueError("every center must fit width bits")
    distances = np.stack(
        [hamming_weight(checked_candidates ^ center, width=width) for center in centers],
        axis=1,
    )
    return np.argmin(distances, axis=1).astype(np.uint8)


def _checked_payload(values: np.ndarray, name: str) -> np.ndarray:
    array = np.asarray(values)
    if array.ndim < 1:
        raise ValueError(f"{name} must have at least one axis")
    if array.dtype != np.bool_ and not np.issubdtype(array.dtype, np.integer):
        raise TypeError(f"{name} must use a Boolean or integer dtype")
    return array


def _checked_masks(masks: Sequence[int], width: int) -> tuple[int, ...]:
    if isinstance(width, bool) or not isinstance(width, int) or width < 1 or width > 63:
        raise ValueError("width must be an integer in [1, 63]")
    checked = tuple(masks)
    limit = 1 << width
    if not checked or any(
        isinstance(mask, bool) or not isinstance(mask, int) or not 0 <= mask < limit
        for mask in checked
    ):
        raise ValueError("masks must be non-empty width-bit integers")
    if len(set(checked)) != len(checked):
        raise ValueError("masks must be unique")
    return checked


def _checked_complete_masks(
    masks: Sequence[int], width: int, maximum_order: int
) -> tuple[int, ...]:
    checked = _checked_masks(masks, width)
    expected = subset_masks(width, maximum_order)
    if set(checked) != set(expected):
        raise ValueError("masks must contain every subset through maximum_order exactly once")
    return checked


def _checked_candidates(values: Iterable[int] | np.ndarray, width: int) -> np.ndarray:
    if isinstance(width, bool) or not isinstance(width, int) or width < 1 or width > 63:
        raise ValueError("width must be an integer in [1, 63]")
    if isinstance(values, np.ndarray):
        raw = values
    else:
        raw = np.asarray(list(values))
    if raw.ndim != 1 or raw.dtype == np.bool_ or not np.issubdtype(raw.dtype, np.integer):
        raise ValueError("candidates must be a one-dimensional integer sequence")
    if np.issubdtype(raw.dtype, np.signedinteger) and np.any(raw < 0):
        raise ValueError("candidate values must be non-negative")
    if np.any(raw.astype(np.uint64, copy=False) >= np.uint64(1 << width)):
        raise ValueError("candidate value exceeds width")
    return raw.astype(_unsigned_dtype(width), copy=False)


def _unsigned_dtype(width: int) -> np.dtype[np.unsignedinteger]:
    if width <= 8:
        return np.dtype(np.uint8)
    if width <= 16:
        return np.dtype(np.uint16)
    if width <= 32:
        return np.dtype(np.uint32)
    return np.dtype(np.uint64)


__all__ = [
    "evaluate_local_mobius",
    "hamming_weight",
    "intervention_values",
    "local_mobius_coefficients",
    "local_truth_table",
    "nearest_center_indices",
    "packed_hamming_distance",
    "subset_masks",
    "subset_zeta_xor_inplace",
]
