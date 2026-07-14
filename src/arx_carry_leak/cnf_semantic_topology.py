"""Public-CNF semantic topology for smoothing learned-clause identities.

Exact learned variable IDs can differ even when two solver trajectories occupy
the same public constraint-graph region.  This module maps every original CNF
variable to candidate-independent structural coordinates and converts learned
clauses into the same eight token families used by the exact-identity reader.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import numpy as np

from arx_carry_leak.exact_cnf import ExactCNF
from arx_carry_leak.learned_clause_reader import (
    HORIZONS,
    PAIR_MAXIMUM_CLAUSE_SIZE,
    ClauseIdentityTable,
)

ANCHOR_NAME = re.compile(r"[a-z0-9_]+")
CLAUSE_BUCKETS = (1, 2, 3, 4)


def _log2_bucket(value: int) -> int:
    return 0 if value <= 0 else int(value).bit_length()


def _balance_bucket(positive: int, negative: int) -> str:
    if positive == negative:
        return "equal"
    if positive >= 2 * max(1, negative):
        return "positive_2x"
    if negative >= 2 * max(1, positive):
        return "negative_2x"
    return "positive" if positive > negative else "negative"


@dataclass
class CNFSemanticTopology:
    variable_count: int
    clauses: tuple[tuple[int, ...], ...]
    incidence_offsets: np.ndarray
    incidence_clause_ids: np.ndarray
    positive_occurrences: np.ndarray
    negative_occurrences: np.ndarray
    clause_length_occurrences: np.ndarray
    anchor_distances: Mapping[str, np.ndarray]
    maximum_distance: int
    _feature_cache: dict[int, tuple[str, ...]] = field(
        default_factory=dict, init=False, repr=False
    )
    _signature_cache: dict[int, str] = field(
        default_factory=dict, init=False, repr=False
    )
    _readout_cache: dict[int, tuple[str, ...]] = field(
        default_factory=dict, init=False, repr=False
    )
    _literal_token_cache: dict[tuple[int, int], frozenset[str]] = field(
        default_factory=dict, init=False, repr=False
    )

    @classmethod
    def from_dimacs(
        cls,
        raw: bytes,
        *,
        anchor_groups: Mapping[str, Sequence[int]],
        maximum_distance: int = 8,
    ) -> CNFSemanticTopology:
        cnf = ExactCNF.from_dimacs(raw)
        if (
            not isinstance(maximum_distance, int)
            or isinstance(maximum_distance, bool)
            or maximum_distance < 1
            or maximum_distance > 254
            or not anchor_groups
        ):
            raise ValueError("CNF topology distance contract differs")
        groups: dict[str, tuple[int, ...]] = {}
        for name, values in anchor_groups.items():
            anchors = tuple(sorted(set(int(value) for value in values)))
            if (
                ANCHOR_NAME.fullmatch(name) is None
                or not anchors
                or any(value < 1 or value > cnf.variable_count for value in anchors)
            ):
                raise ValueError(f"invalid CNF topology anchor group: {name}")
            groups[name] = anchors

        counts = np.zeros(cnf.variable_count + 1, dtype=np.int64)
        positive = np.zeros(cnf.variable_count + 1, dtype=np.int32)
        negative = np.zeros(cnf.variable_count + 1, dtype=np.int32)
        length_counts = np.zeros((cnf.variable_count + 1, 4), dtype=np.int32)
        for clause in cnf.clauses:
            bucket = min(len(clause), 4) - 1
            for literal in clause:
                variable = abs(literal)
                counts[variable] += 1
                length_counts[variable, bucket] += 1
                if literal > 0:
                    positive[variable] += 1
                else:
                    negative[variable] += 1
        offsets = np.zeros(cnf.variable_count + 2, dtype=np.int64)
        offsets[2:] = np.cumsum(counts[1:])
        incidence = np.empty(int(offsets[-1]), dtype=np.int32)
        cursor = offsets[:-1].copy()
        for clause_index, clause in enumerate(cnf.clauses):
            for literal in clause:
                variable = abs(literal)
                incidence[int(cursor[variable])] = clause_index
                cursor[variable] += 1
        if not np.array_equal(cursor[1:], offsets[2:]):
            raise RuntimeError("CNF topology incidence construction differs")

        topology = cls(
            variable_count=cnf.variable_count,
            clauses=cnf.clauses,
            incidence_offsets=offsets,
            incidence_clause_ids=incidence,
            positive_occurrences=positive,
            negative_occurrences=negative,
            clause_length_occurrences=length_counts,
            anchor_distances={},
            maximum_distance=maximum_distance,
        )
        distances = {
            name: topology._multi_source_distance(anchors)
            for name, anchors in sorted(groups.items())
        }
        topology.anchor_distances = distances
        return topology

    def _multi_source_distance(self, sources: Sequence[int]) -> np.ndarray:
        far = self.maximum_distance + 1
        distances = np.full(self.variable_count + 1, far, dtype=np.uint8)
        seen_clauses = np.zeros(len(self.clauses), dtype=np.bool_)
        pending: deque[int] = deque()
        for source in sources:
            distances[source] = 0
            pending.append(source)
        while pending:
            variable = pending.popleft()
            distance = int(distances[variable])
            if distance >= self.maximum_distance:
                continue
            start = int(self.incidence_offsets[variable])
            stop = int(self.incidence_offsets[variable + 1])
            for clause_value in self.incidence_clause_ids[start:stop]:
                clause_index = int(clause_value)
                if seen_clauses[clause_index]:
                    continue
                seen_clauses[clause_index] = True
                next_distance = distance + 1
                for literal in self.clauses[clause_index]:
                    neighbor = abs(literal)
                    if int(distances[neighbor]) > next_distance:
                        distances[neighbor] = next_distance
                        pending.append(neighbor)
        return distances

    def variable_features(self, variable: int) -> tuple[str, ...]:
        if variable < 1 or variable > self.variable_count:
            raise ValueError("CNF topology variable is outside the public formula")
        cached = self._feature_cache.get(variable)
        if cached is not None:
            return cached
        positive = int(self.positive_occurrences[variable])
        negative = int(self.negative_occurrences[variable])
        features = [
            f"degree_log2={_log2_bucket(positive + negative)}",
            f"positive_log2={_log2_bucket(positive)}",
            f"negative_log2={_log2_bucket(negative)}",
            f"polarity_balance={_balance_bucket(positive, negative)}",
        ]
        for index, label in enumerate(CLAUSE_BUCKETS):
            features.append(
                f"clause_len_{label}_log2={_log2_bucket(int(self.clause_length_occurrences[variable, index]))}"
            )
        for name, distances in sorted(self.anchor_distances.items()):
            distance = int(distances[variable])
            value = "far" if distance > self.maximum_distance else str(distance)
            features.append(f"distance_{name}={value}")
        result = tuple(features)
        self._feature_cache[variable] = result
        return result

    def variable_signature(self, variable: int) -> str:
        cached = self._signature_cache.get(variable)
        if cached is not None:
            return cached
        raw = "\x00".join(self.variable_features(variable)).encode()
        result = hashlib.sha256(raw).hexdigest()
        self._signature_cache[variable] = result
        return result

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
        lane_profile = tuple(
            distance_by_name.get(f"output_lane_{lane:02d}", "far")
            for lane in range(16)
        )
        bit_profile = tuple(
            distance_by_name.get(f"output_bit_{bit:02d}", "far")
            for bit in range(32)
        )

        def nearest(profile: tuple[str, ...]) -> str:
            finite = [
                (int(value), index)
                for index, value in enumerate(profile)
                if value != "far"
            ]
            if not finite:
                return "far"
            distance = min(value for value, _ in finite)
            indices = [index for value, index in finite if value == distance]
            return f"d{distance}:i{','.join(str(index) for index in indices)}"

        def digest(values: Sequence[str]) -> str:
            return hashlib.sha256("\x00".join(values).encode()).hexdigest()

        result = (
            f"local_profile={digest(local)}",
            f"distance_key_candidate_prefix={distance_by_name.get('key_candidate_prefix', 'far')}",
            f"distance_key_suffix={distance_by_name.get('key_suffix', 'far')}",
            f"distance_output_all={distance_by_name.get('output_all', distance_by_name.get('public_output', 'far'))}",
            f"nearest_output_lane={nearest(lane_profile)}",
            f"nearest_output_bit={nearest(bit_profile)}",
            f"output_lane_profile={digest(lane_profile)}",
            f"output_bit_profile={digest(bit_profile)}",
            f"complete_topology_signature={self.variable_signature(variable)}",
        )
        self._readout_cache[variable] = result
        return result


def _semantic_clause_tokens(
    topology: CNFSemanticTopology,
    horizon: int,
    clause: Sequence[int],
) -> set[str]:
    signed_signatures = []
    result: set[str] = set()
    for literal in clause:
        variable = abs(int(literal))
        sign = "+" if literal > 0 else "-"
        signature = topology.variable_signature(variable)
        signed = f"{sign}{signature}"
        signed_signatures.append(signed)
        cache_key = (horizon, int(literal))
        literal_tokens = topology._literal_token_cache.get(cache_key)
        if literal_tokens is None:
            values = {
                f"stage_signed_variable|h{horizon}|sig:{signed}",
                f"stage_unsigned_variable|h{horizon}|sig:{signature}",
                f"all_signed_variable|sig:{signed}",
                f"all_unsigned_variable|sig:{signature}",
            }
            for feature in topology.semantic_readout_features(variable):
                values.update(
                    {
                        f"stage_signed_variable|h{horizon}|{sign}|{feature}",
                        f"stage_unsigned_variable|h{horizon}|{feature}",
                        f"all_signed_variable|{sign}|{feature}",
                        f"all_unsigned_variable|{feature}",
                    }
                )
            literal_tokens = frozenset(values)
            topology._literal_token_cache[cache_key] = literal_tokens
        result.update(literal_tokens)
    ordered = sorted(signed_signatures)
    clause_raw = len(ordered).to_bytes(2, "little") + "\x00".join(ordered).encode()
    clause_digest = hashlib.sha256(clause_raw).hexdigest()
    result.update(
        {
            f"stage_clause|h{horizon}|semantic:{clause_digest}",
            f"all_clause|semantic:{clause_digest}",
        }
    )
    if len(ordered) <= PAIR_MAXIMUM_CLAUSE_SIZE:
        for first in range(len(ordered)):
            for second in range(first + 1, len(ordered)):
                left, right = ordered[first], ordered[second]
                result.update(
                    {
                        f"stage_pair|h{horizon}|semantic:{left}|{right}",
                        f"all_pair|semantic:{left}|{right}",
                    }
                )
    return result


def build_topology_clause_table(
    measurement: Mapping[str, object],
    topology: CNFSemanticTopology,
) -> ClauseIdentityTable:
    design = measurement.get("known_key_design", {})
    run = measurement.get("run", {})
    label = measurement.get("label")
    if not isinstance(design, Mapping) or not isinstance(run, Mapping):
        raise ValueError("CNF topology measurement structure differs")
    true_prefix = design.get("prefix8")
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
        or run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
    ):
        raise ValueError("CNF topology measurement identity differs")
    stages = run.get("stages", [])
    if not isinstance(stages, Sequence):
        raise ValueError("CNF topology measurement stages differ")
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in stages
        if isinstance(row, Mapping)
    }
    expected = {(candidate, horizon) for candidate in range(256) for horizon in HORIZONS}
    if set(rows) != expected:
        raise ValueError("CNF topology measurement stage cover differs")
    assumption_sets = {
        frozenset(abs(int(literal)) for literal in row.get("assumptions", []))
        for row in rows.values()
    }
    if len(assumption_sets) != 1 or len(next(iter(assumption_sets), ())) != 8:
        raise ValueError("CNF topology assumption-variable set differs")
    excluded = next(iter(assumption_sets))
    documents = []
    for candidate in range(256):
        tokens: set[str] = set()
        for horizon in HORIZONS:
            clauses = rows[(candidate, horizon)].get("learned_clauses_stage")
            if not isinstance(clauses, Sequence):
                raise ValueError("CNF topology learned-clause payload differs")
            for clause in clauses:
                if not isinstance(clause, Sequence):
                    raise ValueError("CNF topology learned clause differs")
                projected = [
                    int(literal)
                    for literal in clause
                    if abs(int(literal)) not in excluded
                ]
                if not projected:
                    continue
                if any(abs(literal) > topology.variable_count for literal in projected):
                    raise ValueError("learned clause leaves the public CNF variable domain")
                tokens.update(_semantic_clause_tokens(topology, horizon, projected))
        documents.append(frozenset(tokens))
    return ClauseIdentityTable(
        label=label,
        true_prefix=true_prefix,
        candidates=tuple(range(256)),
        candidate_tokens=tuple(documents),
    )


def topology_manifest(topology: CNFSemanticTopology) -> dict[str, object]:
    distance_hashes = {
        name: hashlib.sha256(np.asarray(values, dtype=np.uint8).tobytes()).hexdigest()
        for name, values in sorted(topology.anchor_distances.items())
    }
    return {
        "variable_count": topology.variable_count,
        "clause_count": len(topology.clauses),
        "literal_occurrences": int(topology.incidence_clause_ids.size),
        "maximum_distance": topology.maximum_distance,
        "anchor_distance_sha256": distance_hashes,
        "structural_coordinate_count_per_variable": 8
        + len(topology.anchor_distances),
        "semantic_readout_feature_count_per_variable": 9,
        "distance_metric": "minimum_variable_to_variable_steps_through_public_CNF_clauses",
        "candidate_assumption_variables_are_not_topology_tokens": True,
        "finite": all(
            math.isfinite(float(value))
            for values in topology.anchor_distances.values()
            for value in (values.min(), values.max())
        ),
    }
