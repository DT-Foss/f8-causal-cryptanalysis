"""Directed ChaCha20 operation-flow residuals for learned clauses.

Node distance alone discards whether two learned literals sit on a valid
producer-to-consumer path.  This module reconstructs the exact 640-word
split-18 operation DAG, propagates nearest-tap identities through the public
augmented CNF, and converts learned clauses into target-label-blind quantitative
flow counters.  Counts are normalized within each complete 256-candidate cover
before any known-key label is consulted.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

import numpy as np

from arx_carry_leak.chacha20_operation_taps import (
    TAP_COUNT,
    OperationTap,
    operation_taps,
)
from arx_carry_leak.cnf_semantic_topology import CNFSemanticTopology
from arx_carry_leak.learned_clause_reader import (
    HORIZONS,
    PAIR_MAXIMUM_CLAUSE_SIZE,
    ClauseIdentityTable,
)

FAR = 255


def _bucket(value: int, boundaries: Sequence[int]) -> str:
    for boundary in boundaries:
        if value <= boundary:
            return str(boundary)
    return f"gt{boundaries[-1]}"


@dataclass(frozen=True)
class OperationFlowGraph:
    taps: tuple[OperationTap, ...]
    parents: tuple[tuple[int, ...], ...]
    directed_distances: np.ndarray
    forward_split_end: tuple[int, ...]
    inverse_split_end: tuple[int, ...]

    def relation(self, left: int, right: int) -> str:
        if left == right:
            return "same_tap"
        forward = int(self.directed_distances[left, right])
        backward = int(self.directed_distances[right, left])
        if forward != FAR:
            return f"ancestor_d{_bucket(forward, (1, 2, 4, 8, 16, 32))}"
        if backward != FAR:
            return f"descendant_d{_bucket(backward, (1, 2, 4, 8, 16, 32))}"
        a = self.taps[left]
        b = self.taps[right]
        if a.direction != b.direction:
            lane = "same_lane" if a.updated_lane == b.updated_lane else "cross_lane"
            return f"split_cross_{lane}"
        if a.round_index == b.round_index:
            return "same_round_unconnected"
        return f"unconnected_round_delta_{_bucket(abs(a.round_index - b.round_index), (1, 2, 4, 8, 16))}"


def _operand_lanes(tap: OperationTap) -> tuple[int, int]:
    a, b, c, d = tap.qr_lanes
    if tap.direction == "forward":
        return (
            (a, b),
            (d, a),
            (c, d),
            (b, c),
            (a, b),
            (d, a),
            (c, d),
            (b, c),
        )[tap.encoded_step]
    return (
        (b, c),
        (c, d),
        (d, a),
        (a, b),
        (b, c),
        (c, d),
        (d, a),
        (a, b),
    )[tap.encoded_step]


def operation_flow_graph() -> OperationFlowGraph:
    """Build exact data dependencies for all forward and inverse definitions."""

    taps = operation_taps()
    parents: list[tuple[int, ...]] = []
    state: list[int | None] = [None] * 16
    for tap in taps:
        if tap.index == 576:
            state = [None] * 16
        operand_lanes = _operand_lanes(tap)
        row = tuple(
            sorted(
                {
                    int(state[lane])
                    for lane in operand_lanes
                    if state[lane] is not None
                }
            )
        )
        if any(parent >= tap.index for parent in row):
            raise RuntimeError("operation flow is not topological")
        parents.append(row)
        state[tap.updated_lane] = tap.index
        if tap.index == 575:
            forward_end = tuple(int(value) for value in state)
    inverse_end = tuple(int(value) for value in state)
    distances = np.full((TAP_COUNT, TAP_COUNT), FAR, dtype=np.uint8)
    np.fill_diagonal(distances, 0)
    for child, row in enumerate(parents):
        for parent in row:
            distances[parent, child] = 1
            ancestors = np.flatnonzero(distances[:, parent] != FAR)
            for ancestor_value in ancestors:
                ancestor = int(ancestor_value)
                candidate = int(distances[ancestor, parent]) + 1
                if candidate < int(distances[ancestor, child]):
                    distances[ancestor, child] = candidate
    if (
        len(parents) != TAP_COUNT
        or len(forward_end) != 16
        or len(inverse_end) != 16
        or not all(taps[index].direction == "forward" for index in forward_end)
        or not all(taps[index].direction == "inverse" for index in inverse_end)
    ):
        raise RuntimeError("operation flow endpoint geometry differs")
    return OperationFlowGraph(
        taps=taps,
        parents=tuple(parents),
        directed_distances=distances,
        forward_split_end=forward_end,
        inverse_split_end=inverse_end,
    )


@dataclass
class NearestOperationTaps:
    distances: np.ndarray
    label_masks: tuple[int, ...]
    maximum_distance: int
    tap_count: int
    _indices_cache: dict[int, tuple[int, ...]] = field(
        default_factory=dict, init=False, repr=False
    )

    def tap_indices(self, variable: int) -> tuple[int, ...]:
        if variable < 1 or variable >= len(self.label_masks):
            raise ValueError("nearest-operation variable is outside the CNF")
        cached = self._indices_cache.get(variable)
        if cached is not None:
            return cached
        mask = self.label_masks[variable]
        result: list[int] = []
        while mask:
            low = mask & -mask
            result.append(low.bit_length() - 1)
            mask ^= low
        value = tuple(result)
        self._indices_cache[variable] = value
        return value


def nearest_operation_taps(
    topology: CNFSemanticTopology,
    mapping: Sequence[Sequence[int]],
) -> NearestOperationTaps:
    """Propagate exact nearest tap identities with level-synchronous bitsets."""

    if len(mapping) != TAP_COUNT or any(len(word) != 32 for word in mapping):
        raise ValueError("nearest-operation mapping geometry differs")
    far = topology.maximum_distance + 1
    distances = np.full(topology.variable_count + 1, far, dtype=np.uint8)
    labels = [0] * (topology.variable_count + 1)
    frontier: set[int] = set()
    for tap_index, word in enumerate(mapping):
        label = 1 << tap_index
        for literal in word:
            variable = abs(int(literal))
            if variable < 1 or variable > topology.variable_count:
                raise ValueError("operation tap source is outside the augmented CNF")
            distances[variable] = 0
            labels[variable] |= label
            frontier.add(variable)
    for distance in range(topology.maximum_distance):
        clause_ids: set[int] = set()
        for variable in frontier:
            start = int(topology.incidence_offsets[variable])
            stop = int(topology.incidence_offsets[variable + 1])
            clause_ids.update(
                int(value) for value in topology.incidence_clause_ids[start:stop]
            )
        next_frontier: set[int] = set()
        for clause_index in clause_ids:
            clause = topology.clauses[clause_index]
            source_labels = 0
            for literal in clause:
                variable = abs(literal)
                if int(distances[variable]) == distance:
                    source_labels |= labels[variable]
            if not source_labels:
                continue
            next_distance = distance + 1
            for literal in clause:
                variable = abs(literal)
                observed = int(distances[variable])
                if observed > next_distance:
                    distances[variable] = next_distance
                    labels[variable] = source_labels
                    next_frontier.add(variable)
                elif observed == next_distance:
                    updated = labels[variable] | source_labels
                    if updated != labels[variable]:
                        labels[variable] = updated
                        next_frontier.add(variable)
        frontier = next_frontier
        if not frontier:
            break
    return NearestOperationTaps(
        distances=distances,
        label_masks=tuple(labels),
        maximum_distance=topology.maximum_distance,
        tap_count=TAP_COUNT,
    )


def nearest_manifest(
    nearest: NearestOperationTaps,
    *,
    original_variable_count: int,
) -> dict[str, Any]:
    if original_variable_count < 1 or original_variable_count >= len(nearest.label_masks):
        raise ValueError("nearest-operation manifest range differs")
    digest = hashlib.sha256()
    bytes_per_mask = (nearest.tap_count + 7) // 8
    tie_histogram: Counter[str] = Counter()
    distance_histogram: Counter[str] = Counter()
    mapped = 0
    for variable in range(1, original_variable_count + 1):
        mask = nearest.label_masks[variable]
        digest.update(mask.to_bytes(bytes_per_mask, "little"))
        count = mask.bit_count()
        if count:
            mapped += 1
        tie_histogram[_bucket(count, (0, 1, 2, 4, 8, 16, 32))] += 1
        distance = int(nearest.distances[variable])
        distance_histogram[
            "far" if distance > nearest.maximum_distance else str(distance)
        ] += 1
    return {
        "original_variable_count": original_variable_count,
        "mapped_original_variables": mapped,
        "mapped_fraction": mapped / original_variable_count,
        "distance_uint8_sha256": hashlib.sha256(
            nearest.distances[: original_variable_count + 1].tobytes()
        ).hexdigest(),
        "nearest_tap_bitset_sha256": digest.hexdigest(),
        "tie_count_histogram": dict(sorted(tie_histogram.items())),
        "distance_histogram": dict(sorted(distance_histogram.items())),
    }


def _set_text(values: Sequence[Any], *, maximum: int = 6) -> str:
    unique = sorted({str(value) for value in values})
    if len(unique) <= maximum:
        return ",".join(unique)
    return f"many{_bucket(len(unique), (8, 16, 32, 64))}"


def _tap_profile(indices: Sequence[int], graph: OperationFlowGraph) -> dict[str, str]:
    if not indices:
        return {
            "ties": "0",
            "direction": "unmapped",
            "round": "unmapped",
            "lane": "unmapped",
            "stage": "unmapped",
            "family": "unmapped",
            "rotation": "unmapped",
            "phase": "unmapped",
        }
    taps = [graph.taps[index] for index in indices]
    return {
        "ties": _bucket(len(indices), (1, 2, 4, 8, 16, 32)),
        "direction": _set_text([tap.direction for tap in taps]),
        "round": _set_text([f"{tap.round_index:02d}" for tap in taps]),
        "lane": _set_text([f"{tap.updated_lane:02d}" for tap in taps]),
        "stage": _set_text([f"{tap.canonical_step:02d}" for tap in taps]),
        "family": _set_text([tap.family for tap in taps]),
        "rotation": _set_text([tap.rotation for tap in taps]),
        "phase": _set_text([tap.phase for tap in taps]),
    }


def _node_features(
    literal: int,
    nearest: NearestOperationTaps,
    graph: OperationFlowGraph,
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    variable = abs(literal)
    indices = nearest.tap_indices(variable)
    profile = _tap_profile(indices, graph)
    distance = int(nearest.distances[variable])
    distance_text = "far" if distance > nearest.maximum_distance else str(distance)
    sign = "pos" if literal > 0 else "neg"
    unsigned = tuple(
        f"node_{key}={value}"
        for key, value in profile.items()
    ) + (f"node_distance={distance_text}",)
    signed = tuple(f"{value}|sign={sign}" for value in unsigned)
    return indices, (*unsigned, *signed)


def _pair_features(
    left_literal: int,
    left_indices: Sequence[int],
    right_literal: int,
    right_indices: Sequence[int],
    graph: OperationFlowGraph,
) -> tuple[str, ...]:
    signs = "".join("p" if literal > 0 else "n" for literal in (left_literal, right_literal))
    if not left_indices or not right_indices:
        return (f"flow_relation=unmapped|signs={signs}",)
    combinations_count = len(left_indices) * len(right_indices)
    if combinations_count <= 64:
        pairs = [(left, right) for left in left_indices for right in right_indices]
    else:
        pairs = [
            (left_indices[0], right_indices[0]),
            (left_indices[-1], right_indices[-1]),
        ]
    relations = _set_text([graph.relation(left, right) for left, right in pairs], maximum=12)
    left_taps = [graph.taps[index] for index in left_indices]
    right_taps = [graph.taps[index] for index in right_indices]
    direction_pairs = _set_text(
        [f"{left.direction}>{right.direction}" for left in left_taps for right in right_taps]
    )
    family_pairs = _set_text(
        [f"{left.family}>{right.family}" for left in left_taps for right in right_taps]
    )
    lane_relation = _set_text(
        [
            "same" if left.updated_lane == right.updated_lane else "cross"
            for left in left_taps
            for right in right_taps
        ]
    )
    round_deltas = _set_text(
        [
            _bucket(abs(left.round_index - right.round_index), (0, 1, 2, 4, 8, 16))
            for left in left_taps
            for right in right_taps
        ]
    )
    stage_pairs = _set_text(
        [
            f"{left.canonical_step}>{right.canonical_step}"
            for left in left_taps
            for right in right_taps
        ]
    )
    return (
        f"flow_relation={relations}|signs={signs}",
        f"flow_direction={direction_pairs}|relation={relations}",
        f"flow_family={family_pairs}|relation={relations}",
        f"flow_lane={lane_relation}|relation={relations}",
        f"flow_round_delta={round_deltas}|relation={relations}",
        f"flow_stage={stage_pairs}|relation={relations}",
    )


def _clause_features(
    projected: Sequence[int],
    indices: Sequence[Sequence[int]],
    graph: OperationFlowGraph,
) -> tuple[str, ...]:
    flattened = sorted({index for values in indices for index in values})
    taps = [graph.taps[index] for index in flattened]
    mapped = sum(bool(values) for values in indices)
    round_span = (
        max(tap.round_index for tap in taps) - min(tap.round_index for tap in taps)
        if taps
        else 0
    )
    connected = 0
    total = 0
    for left, right in combinations(flattened[:32], 2):
        total += 1
        relation = graph.relation(left, right)
        if relation.startswith(("ancestor", "descendant", "same_tap")):
            connected += 1
    ratio_bucket = 0 if total == 0 else min(4, (4 * connected) // total)
    return (
        f"clause_size={_bucket(len(projected), (1, 2, 4, 8, 16, 32, 64))}",
        f"clause_mapped={mapped}/{len(projected)}",
        f"clause_unique_taps={_bucket(len(flattened), (1, 2, 4, 8, 16, 32, 64))}",
        f"clause_round_span={_bucket(round_span, (0, 1, 2, 4, 8, 16))}",
        f"clause_directions={_set_text([tap.direction for tap in taps]) if taps else 'unmapped'}",
        f"clause_families={_set_text([tap.family for tap in taps]) if taps else 'unmapped'}",
        f"clause_connected_quartile={ratio_bucket}",
    )


def _candidate_flow_counters(
    measurement: Mapping[str, Any],
    nearest: NearestOperationTaps,
    graph: OperationFlowGraph,
) -> tuple[list[Counter[str]], dict[str, Any]]:
    run = measurement.get("run", {})
    stages = run.get("stages", []) if isinstance(run, Mapping) else []
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in stages
        if isinstance(row, Mapping)
    }
    expected = {(candidate, horizon) for candidate in range(256) for horizon in HORIZONS}
    if set(rows) != expected:
        raise ValueError("operation-flow measurement stage cover differs")
    assumption_sets = {
        frozenset(abs(int(literal)) for literal in row.get("assumptions", []))
        for row in rows.values()
    }
    if len(assumption_sets) != 1 or len(next(iter(assumption_sets), ())) != 8:
        raise ValueError("operation-flow assumption-variable set differs")
    excluded = next(iter(assumption_sets))
    counters: list[Counter[str]] = []
    projected_clause_count = 0
    for candidate in range(256):
        counter: Counter[str] = Counter()
        for horizon in HORIZONS:
            clauses = rows[(candidate, horizon)].get("learned_clauses_stage")
            if not isinstance(clauses, Sequence):
                raise ValueError("operation-flow learned-clause payload differs")
            for clause in clauses:
                projected = [
                    int(literal)
                    for literal in clause
                    if abs(int(literal)) not in excluded
                ]
                if not projected:
                    continue
                projected_clause_count += 1
                atom_indices: list[tuple[int, ...]] = []
                for literal in projected:
                    indices, features = _node_features(literal, nearest, graph)
                    atom_indices.append(indices)
                    for feature in features:
                        family = (
                            "stage_signed_variable"
                            if "|sign=" in feature
                            else "stage_unsigned_variable"
                        )
                        counter[f"{family}|h{horizon}|{feature}"] += 1
                        collapsed = family.replace("stage_", "all_", 1)
                        counter[f"{collapsed}|{feature}"] += 1
                if len(projected) <= PAIR_MAXIMUM_CLAUSE_SIZE:
                    for left, right in combinations(range(len(projected)), 2):
                        for feature in _pair_features(
                            projected[left],
                            atom_indices[left],
                            projected[right],
                            atom_indices[right],
                            graph,
                        ):
                            counter[f"stage_pair|h{horizon}|{feature}"] += 1
                            counter[f"all_pair|{feature}"] += 1
                for feature in _clause_features(projected, atom_indices, graph):
                    counter[f"stage_clause|h{horizon}|{feature}"] += 1
                    counter[f"all_clause|{feature}"] += 1
        counters.append(counter)
    return counters, {
        "projected_clause_count": projected_clause_count,
        "candidate_count": len(counters),
        "assumption_variable_count": len(excluded),
    }


def _residual_tokens(
    counters: Sequence[Counter[str]],
    *,
    maximum_features: int,
    quantile_bins: int,
    minimum_nonzero_candidates: int,
) -> tuple[tuple[frozenset[str], ...], dict[str, Any]]:
    if len(counters) != 256 or quantile_bins < 2 or maximum_features < 1:
        raise ValueError("operation-flow residual geometry differs")
    features = sorted({feature for counter in counters for feature in counter})
    rows = []
    for feature in features:
        values = np.fromiter(
            (counter.get(feature, 0) for counter in counters),
            dtype=np.int32,
            count=256,
        )
        nonzero = int(np.count_nonzero(values))
        if nonzero < minimum_nonzero_candidates or int(values.min()) == int(values.max()):
            continue
        ordered = np.sort(values)
        median_twice = int(ordered[127]) + int(ordered[128])
        dispersion_twice = int(
            np.abs(2 * values.astype(np.int64) - median_twice).sum()
        )
        rows.append(
            (
                dispersion_twice,
                int(np.unique(values).size),
                nonzero,
                median_twice,
                feature,
                values,
            )
        )
    rows.sort(key=lambda row: (-row[0], -row[1], -row[2], row[4]))
    selected = rows[:maximum_features]
    documents = [set() for _ in range(256)]
    feature_ledger = []
    for dispersion_twice, unique_count, nonzero, median_twice, feature, values in selected:
        family, rest = feature.split("|", 1)
        if family not in {
            "stage_signed_variable",
            "stage_unsigned_variable",
            "stage_clause",
            "stage_pair",
            "all_signed_variable",
            "all_unsigned_variable",
            "all_clause",
            "all_pair",
        }:
            raise RuntimeError("operation-flow token family differs")
        for candidate, value in enumerate(values):
            less = int(np.count_nonzero(values < value))
            ties = int(np.count_nonzero(values == value))
            midrank = 1.0 + less + 0.5 * (ties - 1)
            quantile = min(quantile_bins - 1, int((midrank - 1.0) * quantile_bins / 256.0))
            documents[candidate].add(
                f"{family}|residual_q{quantile_bins}={quantile}|{rest}"
            )
            residual_twice = 2 * int(value) - median_twice
            residual_side = (
                "zero"
                if residual_twice == 0
                else "positive"
                if residual_twice > 0
                else "negative"
            )
            documents[candidate].add(
                f"{family}|residual_side={residual_side}"
                f"|residual_abs_log2={abs(residual_twice).bit_length()}|{rest}"
            )
        feature_ledger.append(
            {
                "feature": feature,
                "dispersion_twice": dispersion_twice,
                "unique_counts": unique_count,
                "nonzero_candidates": nonzero,
                "median_twice": median_twice,
                "counts_int32le_sha256": hashlib.sha256(values.tobytes()).hexdigest(),
            }
        )
    return tuple(frozenset(document) for document in documents), {
        "raw_feature_count": len(features),
        "varying_eligible_feature_count": len(rows),
        "selected_feature_count": len(selected),
        "maximum_features": maximum_features,
        "quantile_bins": quantile_bins,
        "minimum_nonzero_candidates": minimum_nonzero_candidates,
        "feature_ledger_sha256": hashlib.sha256(
            json_bytes(feature_ledger)
        ).hexdigest(),
        "candidate_token_counts": [len(document) for document in documents],
    }


def json_bytes(value: Any) -> bytes:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def build_operation_flow_table(
    measurement: Mapping[str, Any],
    nearest: NearestOperationTaps,
    graph: OperationFlowGraph,
    *,
    maximum_features: int = 1024,
    quantile_bins: int = 8,
    minimum_nonzero_candidates: int = 4,
) -> tuple[ClauseIdentityTable, dict[str, Any]]:
    """Build one label-blind within-key flow-residual candidate table."""

    design = measurement.get("known_key_design", {})
    run = measurement.get("run", {})
    label = measurement.get("label")
    true_prefix = design.get("prefix8") if isinstance(design, Mapping) else None
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
        or not isinstance(run, Mapping)
        or run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
    ):
        raise ValueError("operation-flow measurement identity differs")
    counters, counter_manifest = _candidate_flow_counters(measurement, nearest, graph)
    documents, residual_manifest = _residual_tokens(
        counters,
        maximum_features=maximum_features,
        quantile_bins=quantile_bins,
        minimum_nonzero_candidates=minimum_nonzero_candidates,
    )
    return (
        ClauseIdentityTable(
            label=label,
            true_prefix=true_prefix,
            candidates=tuple(range(256)),
            candidate_tokens=documents,
        ),
        {
            "counter_manifest": counter_manifest,
            "residual_manifest": residual_manifest,
            "true_prefix_used_during_counter_or_residual_construction": False,
        },
    )


def flow_graph_manifest(graph: OperationFlowGraph) -> dict[str, Any]:
    parents = [list(row) for row in graph.parents]
    return {
        "tap_count": len(graph.taps),
        "directed_edge_count": sum(len(row) for row in graph.parents),
        "parent_ledger_sha256": hashlib.sha256(json_bytes(parents)).hexdigest(),
        "directed_distance_sha256": hashlib.sha256(
            graph.directed_distances.tobytes()
        ).hexdigest(),
        "forward_split_end": list(graph.forward_split_end),
        "inverse_split_end": list(graph.inverse_split_end),
    }
