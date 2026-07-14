"""Exact semantic taps for the split-18 ChaCha20-R20 CNF.

The frozen symbolic formula names every 32-bit quarter-round result ``v0``
through ``v639``.  Directly constraining one of those definitions is not a
stable DIMACS mapping operation: the bit-vector rewriter can simplify the
internal expression.  This module instead adds declared public tap words and
equalities to the named results.  With preprocessing disabled, the original
CNF is retained byte-for-byte as the clause prefix and tap assignments become
pure unit-clause deltas.

All taps can be decoded with sixteen exports: one all-zero baseline, five bit
coordinate patterns, and ten tap-index patterns.  The resulting mapping is
target-value blind and identifies every one of 640 x 32 operation coordinates.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from arx_carry_leak.cnf_semantic_topology import CNFSemanticTopology

TAP_COUNT = 640
WORD_BITS = 32
TAP_INDEX_BITS = 10
MAPPING_DIMENSIONS = tuple(range(-1, WORD_BITS.bit_length() - 1 + TAP_INDEX_BITS))

EVEN_QRS = (
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
)
ODD_QRS = (
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
)

FORWARD_STEPS = (
    ("add_a_1", "add", "none", 0),
    ("xor_rot_d_16", "xor_rot", "16", 3),
    ("add_c_1", "add", "none", 2),
    ("xor_rot_b_12", "xor_rot", "12", 1),
    ("add_a_2", "add", "none", 0),
    ("xor_rot_d_08", "xor_rot", "08", 3),
    ("add_c_2", "add", "none", 2),
    ("xor_rot_b_07", "xor_rot", "07", 1),
)
INVERSE_STEPS = (
    ("xor_rotr_b_07", "xor_rotr", "07", 1, 7),
    ("sub_c_d_2", "sub", "none", 2, 6),
    ("xor_rotr_d_08", "xor_rotr", "08", 3, 5),
    ("sub_a_b_2", "sub", "none", 0, 4),
    ("xor_rotr_b_12", "xor_rotr", "12", 1, 3),
    ("sub_c_d_1", "sub", "none", 2, 2),
    ("xor_rotr_d_16", "xor_rotr", "16", 3, 1),
    ("sub_a_b_1", "sub", "none", 0, 0),
)


@dataclass(frozen=True)
class OperationTap:
    """One named 32-bit intermediate in the split-18 formula."""

    index: int
    word_name: str
    tap_name: str
    direction: str
    round_index: int
    round_number: int
    phase: str
    qr_index: int
    qr_lanes: tuple[int, int, int, int]
    encoded_step: int
    canonical_step: int
    operation: str
    family: str
    rotation: str
    updated_lane: int


def _round_qrs(round_index: int) -> tuple[tuple[int, int, int, int], ...]:
    return EVEN_QRS if round_index % 2 == 0 else ODD_QRS


def operation_taps(*, rounds: int = 20, split: int = 18) -> tuple[OperationTap, ...]:
    """Reconstruct the exact ``vN`` assignment order of the frozen formula."""

    if rounds != 20 or split != 18:
        raise ValueError("operation-tap semantics are frozen to ChaCha20-R20 split18")
    taps: list[OperationTap] = []

    for round_index in range(split):
        phase = "column" if round_index % 2 == 0 else "diagonal"
        for qr_index, qr_lanes in enumerate(_round_qrs(round_index)):
            for encoded_step, (operation, family, rotation, lane_slot) in enumerate(
                FORWARD_STEPS
            ):
                index = len(taps)
                taps.append(
                    OperationTap(
                        index=index,
                        word_name=f"v{index}",
                        tap_name=f"op{index:03d}",
                        direction="forward",
                        round_index=round_index,
                        round_number=round_index + 1,
                        phase=phase,
                        qr_index=qr_index,
                        qr_lanes=qr_lanes,
                        encoded_step=encoded_step,
                        canonical_step=encoded_step,
                        operation=operation,
                        family=family,
                        rotation=rotation,
                        updated_lane=qr_lanes[lane_slot],
                    )
                )

    for round_index in reversed(range(split, rounds)):
        phase = "column" if round_index % 2 == 0 else "diagonal"
        qrs = _round_qrs(round_index)
        for qr_index in reversed(range(len(qrs))):
            qr_lanes = qrs[qr_index]
            for encoded_step, (
                operation,
                family,
                rotation,
                lane_slot,
                canonical_step,
            ) in enumerate(INVERSE_STEPS):
                index = len(taps)
                taps.append(
                    OperationTap(
                        index=index,
                        word_name=f"v{index}",
                        tap_name=f"op{index:03d}",
                        direction="inverse",
                        round_index=round_index,
                        round_number=round_index + 1,
                        phase=phase,
                        qr_index=qr_index,
                        qr_lanes=qr_lanes,
                        encoded_step=encoded_step,
                        canonical_step=canonical_step,
                        operation=operation,
                        family=family,
                        rotation=rotation,
                        updated_lane=qr_lanes[lane_slot],
                    )
                )

    if (
        len(taps) != TAP_COUNT
        or [tap.index for tap in taps] != list(range(TAP_COUNT))
        or taps[575].direction != "forward"
        or taps[576].direction != "inverse"
        or taps[-1].word_name != "v639"
    ):
        raise RuntimeError("ChaCha20 operation-tap schedule differs")
    return tuple(taps)


def augment_formula(formula: str, taps: Sequence[OperationTap]) -> str:
    """Add declared tap words and exact equalities before ``check-sat``."""

    expected = operation_taps()
    if tuple(taps) != expected:
        raise ValueError("operation-tap schedule differs from the frozen formula")
    declaration_anchor = "(declare-fun k0 () (_ BitVec 32))"
    if formula.count(declaration_anchor) != 1 or formula.count("(check-sat)") != 1:
        raise ValueError("symbolic formula anchors differ")
    declarations = "\n".join(
        f"(declare-fun {tap.tap_name} () (_ BitVec 32))" for tap in taps
    )
    equalities = "\n".join(
        f"(assert (= {tap.tap_name} {tap.word_name}))" for tap in taps
    )
    result = formula.replace(
        declaration_anchor,
        declaration_anchor + "\n" + declarations,
        1,
    )
    return result.replace("(check-sat)", equalities + "\n(check-sat)", 1)


def mapping_assertions(taps: Sequence[OperationTap], dimension: int) -> str:
    """Encode one vectorized coordinate pattern over every tap word."""

    if tuple(taps) != operation_taps() or dimension not in MAPPING_DIMENSIONS:
        raise ValueError("operation-tap mapping dimension differs")
    rows = []
    for tap in taps:
        if dimension == -1:
            pattern = 0
        elif dimension < 5:
            pattern = sum(1 << bit for bit in range(WORD_BITS) if (bit >> dimension) & 1)
        else:
            pattern = 0xFFFFFFFF if (tap.index >> (dimension - 5)) & 1 else 0
        rows.append(f"(assert (= {tap.tap_name} #x{pattern:08x}))")
    return "\n".join(rows)


def decode_vectorized_mapping(
    rows: Mapping[int, Sequence[int]],
    *,
    tap_count: int = TAP_COUNT,
) -> tuple[tuple[int, ...], ...]:
    """Decode signed one-literals for all ``tap x bit`` coordinates."""

    expected_dimensions = tuple(range(-1, 5 + math.ceil(math.log2(tap_count))))
    if tuple(sorted(rows)) != expected_dimensions:
        raise ValueError("operation-tap mapping probe dimensions differ")
    baseline = tuple(int(value) for value in rows[-1])
    expected_units = tap_count * WORD_BITS
    if len(baseline) != expected_units or len({abs(value) for value in baseline}) != expected_units:
        raise ValueError("operation-tap baseline unit set differs")
    baseline_by_variable = {abs(value): value for value in baseline}
    signs_by_dimension: dict[int, dict[int, int]] = {}
    for dimension in expected_dimensions:
        values = tuple(int(value) for value in rows[dimension])
        mapping = {abs(value): 1 if value > 0 else -1 for value in values}
        if len(values) != expected_units or set(mapping) != set(baseline_by_variable):
            raise ValueError("operation-tap probe variable set differs")
        signs_by_dimension[dimension] = mapping

    decoded: list[list[int | None]] = [
        [None for _ in range(WORD_BITS)] for _ in range(tap_count)
    ]
    for variable, baseline_literal in baseline_by_variable.items():
        baseline_sign = 1 if baseline_literal > 0 else -1
        coordinate = 0
        for dimension in range(5 + math.ceil(math.log2(tap_count))):
            if signs_by_dimension[dimension][variable] != baseline_sign:
                coordinate |= 1 << dimension
        bit = coordinate & 31
        tap_index = coordinate >> 5
        if tap_index >= tap_count or decoded[tap_index][bit] is not None:
            raise ValueError("operation-tap coordinate decoding is not bijective")
        decoded[tap_index][bit] = -baseline_literal
    if any(value is None for word in decoded for value in word):
        raise ValueError("operation-tap coordinate mapping is incomplete")
    return tuple(tuple(int(value) for value in word) for word in decoded)


def operation_anchor_groups(
    mapping: Sequence[Sequence[int]],
    taps: Sequence[OperationTap],
) -> dict[str, list[int]]:
    """Build exact semantic anchor sets without exposing target bit values."""

    if tuple(taps) != operation_taps() or len(mapping) != TAP_COUNT:
        raise ValueError("operation-tap anchor schedule differs")
    variables = [
        tuple(abs(int(value)) for value in word)
        for word in mapping
    ]
    if any(len(word) != WORD_BITS for word in variables):
        raise ValueError("operation-tap anchor word width differs")
    flat = [value for word in variables for value in word]
    if len(set(flat)) != TAP_COUNT * WORD_BITS:
        raise ValueError("operation-tap anchor variables are not bijective")

    groups: dict[str, list[int]] = {"operation_all": sorted(flat)}

    def add(name: str, selected: Sequence[int]) -> None:
        values = sorted(
            value
            for index in selected
            for value in variables[index]
        )
        if not values:
            raise RuntimeError(f"empty operation anchor group: {name}")
        groups[name] = values

    for direction in ("forward", "inverse"):
        add(
            f"operation_direction_{direction}",
            [tap.index for tap in taps if tap.direction == direction],
        )
    for round_index in range(20):
        add(
            f"operation_round_{round_index:02d}",
            [tap.index for tap in taps if tap.round_index == round_index],
        )
    for lane in range(16):
        add(
            f"operation_lane_{lane:02d}",
            [tap.index for tap in taps if tap.updated_lane == lane],
        )
    for stage in range(8):
        add(
            f"operation_stage_{stage:02d}",
            [tap.index for tap in taps if tap.canonical_step == stage],
        )
    for bit in range(WORD_BITS):
        groups[f"operation_bit_{bit:02d}"] = sorted(
            variables[tap.index][bit] for tap in taps
        )
    for family in sorted({tap.family for tap in taps}):
        add(
            f"operation_family_{family}",
            [tap.index for tap in taps if tap.family == family],
        )
    for rotation in sorted({tap.rotation for tap in taps}):
        add(
            f"operation_rotation_{rotation}",
            [tap.index for tap in taps if tap.rotation == rotation],
        )
    for phase in ("column", "diagonal"):
        add(
            f"operation_phase_{phase}",
            [tap.index for tap in taps if tap.phase == phase],
        )
    if len(groups) != 90:
        raise RuntimeError("operation semantic anchor-group count differs")
    return groups


def _digest(values: Sequence[str]) -> str:
    return hashlib.sha256("\x00".join(values).encode()).hexdigest()


class CNFOperationTopology(CNFSemanticTopology):
    """Public CNF topology with compact operation-semantic readouts."""

    def semantic_readout_features(self, variable: int) -> tuple[str, ...]:
        cached = self._readout_cache.get(variable)
        if cached is not None:
            return cached
        raw = self.variable_features(variable)
        local = raw[:8]
        distance_by_name = {
            feature.removeprefix("distance_").split("=", 1)[0]: feature.split("=", 1)[1]
            for feature in raw[8:]
        }

        def profile(prefix: str, names: Sequence[str]) -> tuple[str, ...]:
            return tuple(distance_by_name.get(f"{prefix}{name}", "far") for name in names)

        def nearest(values: Sequence[str], labels: Sequence[str]) -> str:
            finite = [
                (int(value), label)
                for value, label in zip(values, labels, strict=True)
                if value != "far"
            ]
            if not finite:
                return "far"
            distance = min(value for value, _ in finite)
            tied = [label for value, label in finite if value == distance]
            return f"d{distance}:{','.join(tied)}"

        output_lanes = tuple(f"{index:02d}" for index in range(16))
        output_bits = tuple(f"{index:02d}" for index in range(32))
        directions = ("forward", "inverse")
        rounds = tuple(f"{index:02d}" for index in range(20))
        lanes = tuple(f"{index:02d}" for index in range(16))
        stages = tuple(f"{index:02d}" for index in range(8))
        bits = tuple(f"{index:02d}" for index in range(32))
        families = ("add", "sub", "xor_rot", "xor_rotr")
        rotations = ("07", "08", "12", "16", "none")
        phases = ("column", "diagonal")

        output_lane_profile = profile("output_lane_", output_lanes)
        output_bit_profile = profile("output_bit_", output_bits)
        direction_profile = profile("operation_direction_", directions)
        round_profile = profile("operation_round_", rounds)
        lane_profile = profile("operation_lane_", lanes)
        stage_profile = profile("operation_stage_", stages)
        bit_profile = profile("operation_bit_", bits)
        family_profile = profile("operation_family_", families)
        rotation_profile = profile("operation_rotation_", rotations)
        phase_profile = profile("operation_phase_", phases)
        operation_profiles = (
            *direction_profile,
            *round_profile,
            *lane_profile,
            *stage_profile,
            *bit_profile,
            *family_profile,
            *rotation_profile,
            *phase_profile,
        )
        result = (
            f"local_profile={_digest(local)}",
            f"distance_key_candidate_prefix={distance_by_name.get('key_candidate_prefix', 'far')}",
            f"distance_key_suffix={distance_by_name.get('key_suffix', 'far')}",
            f"distance_output_all={distance_by_name.get('output_all', 'far')}",
            f"distance_operation_all={distance_by_name.get('operation_all', 'far')}",
            f"nearest_output_lane={nearest(output_lane_profile, output_lanes)}",
            f"nearest_output_bit={nearest(output_bit_profile, output_bits)}",
            f"nearest_operation_direction={nearest(direction_profile, directions)}",
            f"nearest_operation_round={nearest(round_profile, rounds)}",
            f"nearest_operation_lane={nearest(lane_profile, lanes)}",
            f"nearest_operation_stage={nearest(stage_profile, stages)}",
            f"nearest_operation_bit={nearest(bit_profile, bits)}",
            f"nearest_operation_family={nearest(family_profile, families)}",
            f"nearest_operation_rotation={nearest(rotation_profile, rotations)}",
            f"nearest_operation_phase={nearest(phase_profile, phases)}",
            f"output_lane_profile={_digest(output_lane_profile)}",
            f"output_bit_profile={_digest(output_bit_profile)}",
            f"operation_round_profile={_digest(round_profile)}",
            f"operation_lane_profile={_digest(lane_profile)}",
            f"operation_stage_profile={_digest(stage_profile)}",
            f"operation_bit_profile={_digest(bit_profile)}",
            f"operation_joint_profile={_digest(operation_profiles)}",
            f"complete_topology_signature={self.variable_signature(variable)}",
        )
        self._readout_cache[variable] = result
        return result


def operation_topology_manifest(topology: CNFOperationTopology) -> dict[str, Any]:
    """Hash every operation distance coordinate and declare compact readouts."""

    distance_hashes = {
        name: hashlib.sha256(values.tobytes()).hexdigest()
        for name, values in sorted(topology.anchor_distances.items())
    }
    return {
        "variable_count": topology.variable_count,
        "clause_count": len(topology.clauses),
        "literal_occurrences": int(topology.incidence_clause_ids.size),
        "maximum_distance": topology.maximum_distance,
        "anchor_distance_sha256": distance_hashes,
        "structural_coordinate_count_per_variable": 8 + len(distance_hashes),
        "semantic_readout_feature_count_per_variable": 23,
        "distance_metric": "minimum_variable_to_variable_steps_through_public_augmented_CNF_clauses",
        "candidate_assumption_variables_are_not_topology_tokens": True,
        "target_output_bit_values_are_not_topology_features": True,
        "finite": all(
            math.isfinite(float(value))
            for values in topology.anchor_distances.values()
            for value in (values.min(), values.max())
        ),
    }
