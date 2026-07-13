"""Exact, side-effect-free ChaCha20 round and quarter-round tracing.

The trace records the state at round boundaries and every primitive operation
inside each quarter round.  Words use the RFC 8439 little-endian layout.  A
carry-out mask has bit ``i`` set exactly when addition produces a carry out of
bit ``i``; bit 31 therefore records the carry discarded by addition modulo
``2**32``.
"""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass
from numbers import Integral
from typing import Any, Literal

import numpy as np
from numpy.typing import ArrayLike, NDArray

MASK32 = (1 << 32) - 1
CHACHA20_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

_COLUMN_QUARTER_ROUNDS = (
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
)
_DIAGONAL_QUARTER_ROUNDS = (
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
)


@dataclass(frozen=True)
class AdditionTrace:
    """One exact 32-bit modular addition and its ripple-carry masks."""

    target_lane: int
    left_lane: int
    right_lane: int
    left: int
    right: int
    full_sum: int
    sum: int
    carry_in_mask: int
    carry_out_mask: int
    overflow: int


@dataclass(frozen=True)
class XorRotateTrace:
    """The XOR and rotation immediately following one ChaCha addition."""

    target_lane: int
    left_lane: int
    right_lane: int
    left: int
    right: int
    xor_value: int
    rotate_left: int
    rotated_value: int


@dataclass(frozen=True)
class QuarterRoundStepTrace:
    """One of the four add-then-XOR/rotate steps in a quarter round."""

    step_number: int
    addition: AdditionTrace
    xor_rotate: XorRotateTrace


@dataclass(frozen=True)
class QuarterRoundTrace:
    """A complete ChaCha quarter round, including its boundary states."""

    round_number: int
    round_kind: str
    quarter_round_number: int
    global_quarter_round_number: int
    lanes: tuple[int, int, int, int]
    state_before: tuple[int, ...]
    steps: tuple[QuarterRoundStepTrace, ...]
    state_after: tuple[int, ...]


@dataclass(frozen=True)
class ChaCha20BlockTrace:
    """Trace of one ChaCha20 block from round zero through feed-forward."""

    rounds: int
    initial_state: tuple[int, ...]
    round_states: tuple[tuple[int, ...], ...]
    quarter_rounds: tuple[QuarterRoundTrace, ...]
    core_state: tuple[int, ...]
    block_state: tuple[int, ...]

    def round_state(self, round_number: int) -> tuple[int, ...]:
        """Return the state after ``round_number`` rounds (zero is initial)."""
        if not isinstance(round_number, Integral) or isinstance(round_number, bool):
            raise TypeError("round_number must be an integer")
        index = int(round_number)
        if index < 0 or index > self.rounds:
            raise ValueError(f"round_number must be in [0, {self.rounds}]")
        return self.round_states[index]

    def quarter_rounds_for_round(self, round_number: int) -> tuple[QuarterRoundTrace, ...]:
        """Return the four quarter-round traces for a one-based round number."""
        if not isinstance(round_number, Integral) or isinstance(round_number, bool):
            raise TypeError("round_number must be an integer")
        number = int(round_number)
        if number < 1 or number > self.rounds:
            raise ValueError(f"round_number must be in [1, {self.rounds}]")
        start = (number - 1) * 4
        return self.quarter_rounds[start : start + 4]

    def core_bytes(self) -> bytes:
        """Serialize the pre-feed-forward core in RFC little-endian word order."""
        return struct.pack("<16I", *self.core_state)

    def block_bytes(self) -> bytes:
        """Serialize the standard feed-forward block in RFC word order."""
        return struct.pack("<16I", *self.block_state)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the complete trace."""
        return asdict(self)


@dataclass(frozen=True)
class ChaCha20SelectedBlockBatchTrace:
    """Dense operation trace for every key at one selected counter position.

    ``quarter_round_states`` has shape ``(keys, rounds, 5, 16)``.  Index zero
    is the round input and indices one through four are the states after each
    quarter round.  Step arrays have shape ``(keys, rounds, 4, 4, ...)`` for
    four quarter rounds and four add/XOR-rotate steps.
    """

    counter_index: int
    counter: int
    quarter_round_lanes: NDArray[np.uint8]
    rotation_distances: NDArray[np.uint8]
    quarter_round_states: NDArray[np.uint32]
    addition_operands: NDArray[np.uint32]
    modular_sums: NDArray[np.uint32]
    addition_results: NDArray[np.uint32]
    addition_overflows: NDArray[np.uint8]
    carry_in_masks: NDArray[np.uint32]
    carry_out_masks: NDArray[np.uint32]
    xor_rotate_operands: NDArray[np.uint32]
    xor_values: NDArray[np.uint32]
    rotated_values: NDArray[np.uint32]


@dataclass(frozen=True)
class ChaCha20BatchTrace:
    """Memory-bounded vectorized traces for keys sharing one counter schedule.

    ``core_round_states`` has shape ``(keys, counters, rounds + 1, 16)`` and
    ``block_states`` has shape ``(keys, counters, 16)``.  Factual mode uses
    modular addition in both the core and feed-forward.  Carry-free mode
    replaces every such addition, including feed-forward, with XOR.
    """

    mode: Literal["factual", "carry_free"]
    rounds: int
    key_count: int
    counters: tuple[int, ...]
    feedforward_operation: Literal["add_mod2_32", "xor"]
    core_round_states: NDArray[np.uint32]
    block_states: NDArray[np.uint32]
    selected_blocks: tuple[ChaCha20SelectedBlockBatchTrace, ...]

    def selected_block(self, counter_index: int) -> ChaCha20SelectedBlockBatchTrace:
        """Return the unique dense detail trace for ``counter_index``."""
        matches = tuple(
            trace for trace in self.selected_blocks if trace.counter_index == counter_index
        )
        if len(matches) != 1:
            raise KeyError(f"counter index {counter_index} was not selected")
        return matches[0]


def _word(value: int, name: str) -> int:
    if not isinstance(value, Integral) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    word = int(value)
    if word < 0 or word > MASK32:
        raise ValueError(f"{name} must fit uint32")
    return word


def _words(values: tuple[int, ...] | list[int], expected: int, name: str) -> tuple[int, ...]:
    if len(values) != expected:
        raise ValueError(f"{name} must contain exactly {expected} words")
    return tuple(_word(value, f"{name}[{index}]") for index, value in enumerate(values))


def _rounds(value: int) -> int:
    if not isinstance(value, Integral) or isinstance(value, bool):
        raise TypeError("rounds must be an integer")
    rounds = int(value)
    if rounds < 0:
        raise ValueError("rounds must be non-negative")
    return rounds


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) | (value >> (32 - distance))) & MASK32


def _addition_trace(
    state: list[int], target_lane: int, left_lane: int, right_lane: int
) -> AdditionTrace:
    left = state[left_lane]
    right = state[right_lane]
    full_sum = left + right
    result = full_sum & MASK32
    carry_in_mask = (left ^ right ^ result) & MASK32
    carry_out_mask = ((left & right) | ((left | right) & ((~result) & MASK32))) & MASK32
    trace = AdditionTrace(
        target_lane=target_lane,
        left_lane=left_lane,
        right_lane=right_lane,
        left=left,
        right=right,
        full_sum=full_sum,
        sum=result,
        carry_in_mask=carry_in_mask,
        carry_out_mask=carry_out_mask,
        overflow=full_sum >> 32,
    )
    state[target_lane] = result
    return trace


def _xor_rotate_trace(
    state: list[int], target_lane: int, right_lane: int, distance: int
) -> XorRotateTrace:
    left = state[target_lane]
    right = state[right_lane]
    xor_value = left ^ right
    rotated_value = _rotl32(xor_value, distance)
    trace = XorRotateTrace(
        target_lane=target_lane,
        left_lane=target_lane,
        right_lane=right_lane,
        left=left,
        right=right,
        xor_value=xor_value,
        rotate_left=distance,
        rotated_value=rotated_value,
    )
    state[target_lane] = rotated_value
    return trace


def _quarter_round_trace(
    state: list[int],
    *,
    lanes: tuple[int, int, int, int],
    round_number: int,
    round_kind: str,
    quarter_round_number: int,
) -> QuarterRoundTrace:
    a, b, c, d = lanes
    before = tuple(state)
    operations = (
        (a, a, b, d, a, 16),
        (c, c, d, b, c, 12),
        (a, a, b, d, a, 8),
        (c, c, d, b, c, 7),
    )
    steps: list[QuarterRoundStepTrace] = []
    for step_number, (
        target_lane,
        left_lane,
        right_lane,
        xor_target_lane,
        xor_right_lane,
        rotation,
    ) in enumerate(operations, start=1):
        addition = _addition_trace(state, target_lane, left_lane, right_lane)
        xor_rotate = _xor_rotate_trace(state, xor_target_lane, xor_right_lane, rotation)
        steps.append(
            QuarterRoundStepTrace(
                step_number=step_number,
                addition=addition,
                xor_rotate=xor_rotate,
            )
        )
    return QuarterRoundTrace(
        round_number=round_number,
        round_kind=round_kind,
        quarter_round_number=quarter_round_number,
        global_quarter_round_number=(round_number - 1) * 4 + quarter_round_number,
        lanes=lanes,
        state_before=before,
        steps=tuple(steps),
        state_after=tuple(state),
    )


def trace_chacha20_block_words(
    *,
    key_words: tuple[int, ...] | list[int],
    counter: int,
    nonce_words: tuple[int, ...] | list[int],
    rounds: int = 20,
) -> ChaCha20BlockTrace:
    """Trace a ChaCha block supplied as eight key and three nonce words.

    ``round_states[n]`` is the core state after exactly ``n`` rounds.  Each
    round contains four quarter-round traces, and each quarter round contains
    four :class:`QuarterRoundStepTrace` records.
    """
    checked_key = _words(key_words, 8, "key_words")
    checked_nonce = _words(nonce_words, 3, "nonce_words")
    checked_counter = _word(counter, "counter")
    checked_rounds = _rounds(rounds)
    initial = (*CHACHA20_CONSTANTS, *checked_key, checked_counter, *checked_nonce)
    state = list(initial)
    round_states: list[tuple[int, ...]] = [initial]
    quarter_rounds: list[QuarterRoundTrace] = []

    for round_index in range(checked_rounds):
        round_number = round_index + 1
        if round_index % 2 == 0:
            round_kind = "column"
            lane_sets = _COLUMN_QUARTER_ROUNDS
        else:
            round_kind = "diagonal"
            lane_sets = _DIAGONAL_QUARTER_ROUNDS
        for quarter_round_number, lanes in enumerate(lane_sets, start=1):
            quarter_rounds.append(
                _quarter_round_trace(
                    state,
                    lanes=lanes,
                    round_number=round_number,
                    round_kind=round_kind,
                    quarter_round_number=quarter_round_number,
                )
            )
        round_states.append(tuple(state))

    core_state = tuple(state)
    block_state = tuple(
        (core_word + initial_word) & MASK32
        for core_word, initial_word in zip(core_state, initial, strict=True)
    )
    return ChaCha20BlockTrace(
        rounds=checked_rounds,
        initial_state=initial,
        round_states=tuple(round_states),
        quarter_rounds=tuple(quarter_rounds),
        core_state=core_state,
        block_state=block_state,
    )


def trace_chacha20_block(
    *, key: bytes, counter: int, nonce: bytes, rounds: int = 20
) -> ChaCha20BlockTrace:
    """Trace a ChaCha block supplied in the RFC 8439 byte representation."""
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")
    if len(key) != 32:
        raise ValueError("key must contain exactly 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must contain exactly 12 bytes")
    return trace_chacha20_block_words(
        key_words=struct.unpack("<8I", key),
        counter=counter,
        nonce_words=struct.unpack("<3I", nonce),
        rounds=rounds,
    )


def _word_matrix(values: ArrayLike, *, columns: int, name: str) -> NDArray[np.uint32]:
    array = np.asarray(values)
    if array.ndim != 2 or array.shape[1] != columns:
        raise ValueError(f"{name} must have shape (n, {columns})")
    if array.shape[0] < 1:
        raise ValueError(f"{name} must contain at least one row")
    if not np.issubdtype(array.dtype, np.integer):
        raise TypeError(f"{name} must contain integers")
    if np.any(array < 0) or np.any(array > MASK32):
        raise ValueError(f"{name} entries must fit uint32")
    return np.ascontiguousarray(array, dtype=np.uint32)


def _word_vector(values: ArrayLike, *, length: int | None, name: str) -> NDArray[np.uint32]:
    array = np.asarray(values)
    if array.ndim != 1 or (length is not None and len(array) != length):
        suffix = "one-dimensional" if length is None else f"contain exactly {length} words"
        raise ValueError(f"{name} must {suffix}")
    if len(array) < 1:
        raise ValueError(f"{name} must not be empty")
    if not np.issubdtype(array.dtype, np.integer):
        raise TypeError(f"{name} must contain integers")
    if np.any(array < 0) or np.any(array > MASK32):
        raise ValueError(f"{name} entries must fit uint32")
    return np.ascontiguousarray(array, dtype=np.uint32)


def _selected_counter_indices(
    values: tuple[int, ...] | list[int], counter_count: int
) -> tuple[int, ...]:
    checked: list[int] = []
    for value in values:
        if not isinstance(value, Integral) or isinstance(value, bool):
            raise TypeError("selected_trace_blocks entries must be integers")
        index = int(value)
        if index < 0 or index >= counter_count:
            raise ValueError(f"selected trace block index {index} is outside the counter schedule")
        checked.append(index)
    if len(set(checked)) != len(checked):
        raise ValueError("selected_trace_blocks must not contain duplicates")
    return tuple(checked)


def _new_selected_block_trace(
    *, key_count: int, rounds: int, counter_index: int, counter: int
) -> ChaCha20SelectedBlockBatchTrace:
    quarter_round_lanes = np.empty((rounds, 4, 4), dtype=np.uint8)
    for round_index in range(rounds):
        lane_sets = _COLUMN_QUARTER_ROUNDS if round_index % 2 == 0 else _DIAGONAL_QUARTER_ROUNDS
        quarter_round_lanes[round_index] = np.asarray(lane_sets, dtype=np.uint8)
    rotation_distances = np.broadcast_to(
        np.asarray((16, 12, 8, 7), dtype=np.uint8), (rounds, 4, 4)
    ).copy()
    operation_shape = (key_count, rounds, 4, 4)
    return ChaCha20SelectedBlockBatchTrace(
        counter_index=counter_index,
        counter=counter,
        quarter_round_lanes=quarter_round_lanes,
        rotation_distances=rotation_distances,
        quarter_round_states=np.empty((key_count, rounds, 5, 16), dtype=np.uint32),
        addition_operands=np.empty((*operation_shape, 2), dtype=np.uint32),
        modular_sums=np.empty(operation_shape, dtype=np.uint32),
        addition_results=np.empty(operation_shape, dtype=np.uint32),
        addition_overflows=np.empty(operation_shape, dtype=np.uint8),
        carry_in_masks=np.empty(operation_shape, dtype=np.uint32),
        carry_out_masks=np.empty(operation_shape, dtype=np.uint32),
        xor_rotate_operands=np.empty((*operation_shape, 2), dtype=np.uint32),
        xor_values=np.empty(operation_shape, dtype=np.uint32),
        rotated_values=np.empty(operation_shape, dtype=np.uint32),
    )


def _freeze_array(array: NDArray[Any]) -> None:
    array.setflags(write=False)


def _freeze_selected_block_trace(trace: ChaCha20SelectedBlockBatchTrace) -> None:
    _freeze_array(trace.quarter_round_lanes)
    _freeze_array(trace.rotation_distances)
    _freeze_array(trace.quarter_round_states)
    _freeze_array(trace.addition_operands)
    _freeze_array(trace.modular_sums)
    _freeze_array(trace.addition_results)
    _freeze_array(trace.addition_overflows)
    _freeze_array(trace.carry_in_masks)
    _freeze_array(trace.carry_out_masks)
    _freeze_array(trace.xor_rotate_operands)
    _freeze_array(trace.xor_values)
    _freeze_array(trace.rotated_values)


def trace_chacha20_batch_words(
    *,
    key_words: ArrayLike,
    counters: ArrayLike,
    nonce_words: ArrayLike,
    rounds: int = 20,
    mode: Literal["factual", "carry_free"] = "factual",
    selected_trace_blocks: tuple[int, ...] | list[int] = (),
    chunk_size: int = 256,
) -> ChaCha20BatchTrace:
    """Vectorize known-key traces over one shared counter schedule.

    The resident result arrays are unavoidable output.  Temporary working
    state is bounded by ``chunk_size * len(counters) * 16`` words.  Detailed
    operation arrays are allocated only for ``selected_trace_blocks``; each
    entry is a position in the supplied counter schedule.

    In ``carry_free`` mode, every core addition and the final feed-forward
    addition are replaced with XOR.  ``modular_sums`` and carry masks remain in
    selected traces as counterfactual annotations, while ``addition_results``
    records the XOR values actually propagated through the ablated core.
    """
    keys = _word_matrix(key_words, columns=8, name="key_words")
    checked_counters = _word_vector(counters, length=None, name="counters")
    checked_nonce = _word_vector(nonce_words, length=3, name="nonce_words")
    checked_rounds = _rounds(rounds)
    if mode not in ("factual", "carry_free"):
        raise ValueError("mode must be 'factual' or 'carry_free'")
    if not isinstance(chunk_size, Integral) or isinstance(chunk_size, bool):
        raise TypeError("chunk_size must be an integer")
    checked_chunk_size = int(chunk_size)
    if checked_chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    selected_indices = _selected_counter_indices(selected_trace_blocks, len(checked_counters))

    key_count = len(keys)
    counter_count = len(checked_counters)
    core_round_states = np.empty(
        (key_count, counter_count, checked_rounds + 1, 16), dtype=np.uint32
    )
    block_states = np.empty((key_count, counter_count, 16), dtype=np.uint32)
    selected_blocks = tuple(
        _new_selected_block_trace(
            key_count=key_count,
            rounds=checked_rounds,
            counter_index=index,
            counter=int(checked_counters[index]),
        )
        for index in selected_indices
    )

    for first_key in range(0, key_count, checked_chunk_size):
        last_key = min(first_key + checked_chunk_size, key_count)
        key_slice = slice(first_key, last_key)
        chunk_keys = keys[key_slice]
        initial = np.empty((len(chunk_keys), counter_count, 16), dtype=np.uint32)
        initial[..., :4] = np.asarray(CHACHA20_CONSTANTS, dtype=np.uint32)
        initial[..., 4:12] = chunk_keys[:, None, :]
        initial[..., 12] = checked_counters[None, :]
        initial[..., 13:16] = checked_nonce
        state = initial.copy()
        core_round_states[key_slice, :, 0, :] = state

        for round_index in range(checked_rounds):
            lane_sets = _COLUMN_QUARTER_ROUNDS if round_index % 2 == 0 else _DIAGONAL_QUARTER_ROUNDS
            for quarter_round_index, lanes in enumerate(lane_sets):
                for detail in selected_blocks:
                    detail.quarter_round_states[key_slice, round_index, quarter_round_index, :] = (
                        state[:, detail.counter_index, :]
                    )

                a, b, c, d = lanes
                operations = (
                    (a, a, b, d, a, 16),
                    (c, c, d, b, c, 12),
                    (a, a, b, d, a, 8),
                    (c, c, d, b, c, 7),
                )
                for step_index, (
                    target_lane,
                    left_lane,
                    right_lane,
                    xor_target_lane,
                    xor_right_lane,
                    rotation,
                ) in enumerate(operations):
                    left = state[..., left_lane].copy()
                    right = state[..., right_lane].copy()
                    modular_sum = left + right
                    carry_in_mask = left ^ right ^ modular_sum
                    carry_out_mask = (left & right) | ((left | right) & ~modular_sum)
                    addition_result = modular_sum if mode == "factual" else left ^ right
                    state[..., target_lane] = addition_result

                    xor_left = state[..., xor_target_lane].copy()
                    xor_right = state[..., xor_right_lane].copy()
                    xor_value = xor_left ^ xor_right
                    rotated_value = (
                        (xor_value << np.uint32(rotation)) | (xor_value >> np.uint32(32 - rotation))
                    ).astype(np.uint32)
                    state[..., xor_target_lane] = rotated_value

                    for detail in selected_blocks:
                        block = detail.counter_index
                        destination = (key_slice, round_index, quarter_round_index, step_index)
                        detail.addition_operands[destination + (0,)] = left[:, block]
                        detail.addition_operands[destination + (1,)] = right[:, block]
                        detail.modular_sums[destination] = modular_sum[:, block]
                        detail.addition_results[destination] = addition_result[:, block]
                        detail.addition_overflows[destination] = (
                            carry_out_mask[:, block] >> np.uint32(31)
                        ).astype(np.uint8)
                        detail.carry_in_masks[destination] = carry_in_mask[:, block]
                        detail.carry_out_masks[destination] = carry_out_mask[:, block]
                        detail.xor_rotate_operands[destination + (0,)] = xor_left[:, block]
                        detail.xor_rotate_operands[destination + (1,)] = xor_right[:, block]
                        detail.xor_values[destination] = xor_value[:, block]
                        detail.rotated_values[destination] = rotated_value[:, block]

                for detail in selected_blocks:
                    detail.quarter_round_states[
                        key_slice, round_index, quarter_round_index + 1, :
                    ] = state[:, detail.counter_index, :]
            core_round_states[key_slice, :, round_index + 1, :] = state

        block_states[key_slice] = state + initial if mode == "factual" else state ^ initial

    _freeze_array(core_round_states)
    _freeze_array(block_states)
    for detail in selected_blocks:
        _freeze_selected_block_trace(detail)
    return ChaCha20BatchTrace(
        mode=mode,
        rounds=checked_rounds,
        key_count=key_count,
        counters=tuple(int(value) for value in checked_counters),
        feedforward_operation="add_mod2_32" if mode == "factual" else "xor",
        core_round_states=core_round_states,
        block_states=block_states,
        selected_blocks=selected_blocks,
    )


__all__ = [
    "AdditionTrace",
    "CHACHA20_CONSTANTS",
    "ChaCha20BatchTrace",
    "ChaCha20BlockTrace",
    "ChaCha20SelectedBlockBatchTrace",
    "MASK32",
    "QuarterRoundStepTrace",
    "QuarterRoundTrace",
    "XorRotateTrace",
    "trace_chacha20_block",
    "trace_chacha20_batch_words",
    "trace_chacha20_block_words",
]
