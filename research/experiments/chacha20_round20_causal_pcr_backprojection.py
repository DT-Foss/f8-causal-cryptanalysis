#!/usr/bin/env python3
"""Exact multi-view Causal-PCR backprojection over the frozen R20 CNF."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)
from arx_carry_leak.exact_cnf import ExactCNF, PropagationState, literal_node


ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
R20_RUNNER = RESEARCH / "experiments" / "chacha20_round20_global_incremental_transfer.py"

ATTEMPT_ID = "A213"
SCHEMA = "chacha20-round20-causal-pcr-backprojection-v1"
PROTOCOL_FILENAME = "chacha20_round20_causal_pcr_backprojection_v1.json"
PROTOCOL_SHA256 = "d84e69246b1d78499f464184f1e5d841e36cef5ea3849f150ebdba0094703d47"
R20_RUNNER_SHA256 = "1825035b90317e9d6c8a2ee0894f2569eada44177ee01ced49d043ca37ec881d"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
    )


def _load_protocol() -> dict[str, Any]:
    path = RESEARCH / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A213 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    anchors = protocol.get("anchors", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-causal-pcr-backprojection-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_R20_numeric_and_reflected_gray_execution_started_but_before_any_atomic_mode_output_or_status_or_model_was_available_or_read"
        or anchors.get("R20_global_transfer_protocol", {}).get("sha256")
        != "64470896de99dacabb0b53f81d8c94c2da82e7088be09c8e1b4d38665ae09946"
        or anchors.get("R20_global_transfer_runner_frozen_semantics", {}).get("sha256")
        != R20_RUNNER_SHA256
        or anchors.get("public_challenge_sha256")
        != "98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762"
        or anchors.get("transformed_R20_CNF", {}).get("sha256")
        != "2c33afd9f78ed3e1a2180313571918af51d5eaf2e1cd3b09fb588b86745f19b1"
        or boundary.get("R20_atomic_mode_outputs_existed_before_this_freeze") is not False
        or boundary.get("R20_status_or_model_or_correct_cell_read_before_this_freeze")
        is not False
        or boundary.get("hidden_20_bit_assignment_available_to_A213") is not False
        or boundary.get("orders_rules_budgets_or_evidence_thresholds_may_change_after_freeze")
        is not False
        or len(protocol.get("exact_views", [])) != 5
        or protocol.get("dependence_policy", {}).get(
            "view_counts_may_not_be_multiplied_as_independent_probabilities"
        )
        is not True
        or protocol.get("dependence_policy", {}).get("fuzzy_or_semantic_entity_matching")
        is not False
    ):
        raise RuntimeError("A213 frozen protocol identity gate failed")
    return protocol


def _load_r20() -> Any:
    if _file_sha256(R20_RUNNER) != R20_RUNNER_SHA256:
        raise RuntimeError("A213 pinned R20 helper runner hash differs")
    spec = importlib.util.spec_from_file_location("a213_pinned_r20_runner", R20_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import pinned R20 runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _rebuild_cnf(
    protocol: dict[str, Any], r20: Any, directory: Path
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    analysis = r20.analyze()
    mapping, base_path = r20._derive_signed_mapping(
        formula=analysis["source_formula"],
        protocol=analysis["protocol"],
        directory=directory,
    )
    transformed, transformed_path = r20._build_R20_specific_global_base(
        base_path=base_path,
        mapping_manifest=mapping,
        protocol=analysis["protocol"],
        directory=directory,
    )
    expected = protocol["anchors"]["transformed_R20_CNF"]
    raw = transformed_path.read_bytes()
    if (
        transformed["transformed_header"] != expected["header"]
        or len(raw) != expected["bytes"]
        or _sha256(raw) != expected["sha256"]
        or transformed["transformed_one_literals_bit0_through_bit19"]
        != expected["transformed_one_literals_bit0_through_bit19"]
        or analysis["solver_execution_started"] is not False
    ):
        raise RuntimeError("A213 deterministic R20 CNF rebuild gate failed")
    return analysis, transformed, transformed_path


def _literal_for(bit: int, value: int, one_literals: Sequence[int]) -> int:
    literal = int(one_literals[bit])
    return literal if value else -literal


def _key_value(state: PropagationState, one_literal: int) -> int | None:
    assignment = int(state.assignment[abs(one_literal)])
    if assignment == 0:
        return None
    one_sign = 1 if one_literal > 0 else -1
    return int(assignment == one_sign)


def _key_values(
    state: PropagationState, one_literals: Sequence[int]
) -> dict[int, int]:
    result: dict[int, int] = {}
    for bit, one_literal in enumerate(one_literals):
        value = _key_value(state, int(one_literal))
        if value is not None:
            result[bit] = value
    return result


def _clause_reason(
    clause_ids: Iterable[int], cnf: ExactCNF
) -> dict[str, Any]:
    ids = tuple(sorted(set(int(value) for value in clause_ids)))
    raw = np.asarray(ids, dtype="<u4").tobytes()
    return {
        "reason_clause_count": len(ids),
        "reason_clause_ids": list(ids),
        "reason_clause_ids_sha256": _sha256(raw),
    }


def _base_view(cnf: ExactCNF, one_literals: Sequence[int]) -> tuple[PropagationState, dict[str, Any]]:
    base = cnf.propagate()
    if base.conflicted:
        raise RuntimeError("A213 frozen R20 CNF conflicts under base unit closure")
    forced = _key_values(base, one_literals)
    rows = []
    for bit, value in sorted(forced.items()):
        literal = _literal_for(bit, value, one_literals)
        rows.append(
            {
                "bit": bit,
                "value": value,
                "literal": literal,
                **_clause_reason(cnf.explain_literal(base, literal), cnf),
            }
        )
    return base, {
        "view": "V1_base_unit_closure",
        "base_conflict": False,
        "assigned_variable_count": base.assigned_count,
        "forced_key_bit_count": len(rows),
        "forced_key_bits": rows,
    }


def _single_view(
    cnf: ExactCNF, base: PropagationState, one_literals: Sequence[int]
) -> tuple[dict[str, Any], set[tuple[int, int, int, int]]]:
    base_values = _key_values(base, one_literals)
    conflicts: list[dict[str, Any]] = []
    implications: list[dict[str, Any]] = []
    implication_set: set[tuple[int, int, int, int]] = set()
    assigned_counts: list[int] = []
    for bit in range(20):
        for value in (0, 1):
            assumption = _literal_for(bit, value, one_literals)
            state = cnf.propagate([assumption], base=base)
            assigned_counts.append(state.assigned_count)
            if state.conflicted:
                conflicts.append(
                    {
                        "bit": bit,
                        "value": value,
                        "assumption_literal": assumption,
                        **_clause_reason(cnf.explain_conflict(state), cnf),
                    }
                )
                continue
            values = _key_values(state, one_literals)
            for target_bit, target_value in sorted(values.items()):
                if target_bit == bit or target_bit in base_values:
                    continue
                key = (bit, value, target_bit, target_value)
                if key in implication_set:
                    continue
                implication_set.add(key)
                implied_literal = _literal_for(target_bit, target_value, one_literals)
                implications.append(
                    {
                        "if_bit": bit,
                        "if_value": value,
                        "then_bit": target_bit,
                        "then_value": target_value,
                        "assumption_literal": assumption,
                        "implied_literal": implied_literal,
                        **_clause_reason(cnf.explain_literal(state, implied_literal), cnf),
                    }
                )
    return {
        "view": "V2_single_literal_backprojection",
        "probe_count": 40,
        "conflict_count": len(conflicts),
        "implication_count": len(implications),
        "assigned_variable_count_min": min(assigned_counts),
        "assigned_variable_count_max": max(assigned_counts),
        "conflicts": conflicts,
        "implications": implications,
    }, implication_set


def _pair_view(
    cnf: ExactCNF,
    base: PropagationState,
    one_literals: Sequence[int],
    single_implications: set[tuple[int, int, int, int]],
) -> dict[str, Any]:
    base_values = _key_values(base, one_literals)
    nogoods: list[dict[str, Any]] = []
    implications: list[dict[str, Any]] = []
    implication_keys: set[tuple[int, int, int, int, int, int]] = set()
    probe_count = 0
    assigned_min = cnf.variable_count
    assigned_max = 0
    for first_bit in range(20):
        for second_bit in range(first_bit + 1, 20):
            for first_value in (0, 1):
                for second_value in (0, 1):
                    probe_count += 1
                    assumptions = (
                        _literal_for(first_bit, first_value, one_literals),
                        _literal_for(second_bit, second_value, one_literals),
                    )
                    state = cnf.propagate(assumptions, base=base)
                    assigned_min = min(assigned_min, state.assigned_count)
                    assigned_max = max(assigned_max, state.assigned_count)
                    if state.conflicted:
                        nogoods.append(
                            {
                                "first_bit": first_bit,
                                "first_value": first_value,
                                "second_bit": second_bit,
                                "second_value": second_value,
                                "assumption_literals": list(assumptions),
                                **_clause_reason(cnf.explain_conflict(state), cnf),
                            }
                        )
                        continue
                    values = _key_values(state, one_literals)
                    for target_bit, target_value in sorted(values.items()):
                        if target_bit in {first_bit, second_bit} or target_bit in base_values:
                            continue
                        if (
                            (first_bit, first_value, target_bit, target_value)
                            in single_implications
                            or (second_bit, second_value, target_bit, target_value)
                            in single_implications
                        ):
                            continue
                        key = (
                            first_bit,
                            first_value,
                            second_bit,
                            second_value,
                            target_bit,
                            target_value,
                        )
                        if key in implication_keys:
                            continue
                        implication_keys.add(key)
                        implied_literal = _literal_for(target_bit, target_value, one_literals)
                        implications.append(
                            {
                                "first_bit": first_bit,
                                "first_value": first_value,
                                "second_bit": second_bit,
                                "second_value": second_value,
                                "then_bit": target_bit,
                                "then_value": target_value,
                                "assumption_literals": list(assumptions),
                                "implied_literal": implied_literal,
                                **_clause_reason(
                                    cnf.explain_literal(state, implied_literal), cnf
                                ),
                            }
                        )
    if probe_count != 760:
        raise RuntimeError("A213 pair-probe cover is incomplete")
    return {
        "view": "V3_pair_literal_backprojection",
        "probe_count": probe_count,
        "pair_nogood_count": len(nogoods),
        "incremental_pair_implication_count": len(implications),
        "assigned_variable_count_min": assigned_min,
        "assigned_variable_count_max": assigned_max,
        "pair_nogoods": nogoods,
        "incremental_pair_implications": implications,
    }


def _bfs_paths(
    adjacency: Sequence[Sequence[tuple[int, int]]], source: int
) -> tuple[np.ndarray, np.ndarray]:
    previous_node = np.full(len(adjacency), -1, dtype=np.int32)
    previous_clause = np.full(len(adjacency), -1, dtype=np.int32)
    previous_node[source] = source
    queue: deque[int] = deque([source])
    while queue:
        current = queue.popleft()
        for target, clause_id in adjacency[current]:
            if previous_node[target] != -1:
                continue
            previous_node[target] = current
            previous_clause[target] = clause_id
            queue.append(target)
    return previous_node, previous_clause


def _path_clause_ids(
    source: int, target: int, previous_node: np.ndarray, previous_clause: np.ndarray
) -> tuple[int, ...]:
    if previous_node[target] == -1:
        return ()
    clauses: list[int] = []
    current = target
    while current != source:
        clauses.append(int(previous_clause[current]))
        current = int(previous_node[current])
    clauses.reverse()
    return tuple(clauses)


def _binary_view(
    cnf: ExactCNF, base: PropagationState, one_literals: Sequence[int]
) -> dict[str, Any]:
    binaries = cnf.residual_binary_clauses(base)
    node_count = 2 * cnf.variable_count
    adjacency: list[list[tuple[int, int]]] = [[] for _ in range(node_count)]
    rows: list[int] = []
    columns: list[int] = []
    for first, second, clause_id in binaries:
        for source_literal, target_literal in ((-first, second), (-second, first)):
            source = literal_node(source_literal)
            target = literal_node(target_literal)
            adjacency[source].append((target, clause_id))
            rows.append(source)
            columns.append(target)
    for edges in adjacency:
        edges.sort()
    graph = coo_matrix(
        (np.ones(len(rows), dtype=np.uint8), (rows, columns)),
        shape=(node_count, node_count),
    ).tocsr()
    component_count, labels = connected_components(
        graph, directed=True, connection="strong", return_labels=True
    )
    counts = np.bincount(labels, minlength=component_count)

    signed_keys = [
        (bit, value, _literal_for(bit, value, one_literals))
        for bit in range(20)
        for value in (0, 1)
    ]
    path_cache: dict[int, tuple[np.ndarray, np.ndarray]] = {}
    implications: list[dict[str, Any]] = []
    reachability: set[tuple[int, int, int, int]] = set()
    forced: list[dict[str, Any]] = []
    for bit, value, source_literal in signed_keys:
        source = literal_node(source_literal)
        previous_node, previous_clause = _bfs_paths(adjacency, source)
        path_cache[source] = (previous_node, previous_clause)
        complement = literal_node(-source_literal)
        if previous_node[complement] != -1:
            clauses = _path_clause_ids(source, complement, previous_node, previous_clause)
            forced.append(
                {
                    "forbidden_bit": bit,
                    "forbidden_value": value,
                    "forced_value": 1 - value,
                    "source_literal": source_literal,
                    "reaches_complement_literal": -source_literal,
                    **_clause_reason(clauses, cnf),
                }
            )
        for target_bit, target_value, target_literal in signed_keys:
            if target_bit == bit and target_value == value:
                continue
            target = literal_node(target_literal)
            if previous_node[target] == -1:
                continue
            reachability.add((bit, value, target_bit, target_value))
            clauses = _path_clause_ids(source, target, previous_node, previous_clause)
            implications.append(
                {
                    "if_bit": bit,
                    "if_value": value,
                    "then_bit": target_bit,
                    "then_value": target_value,
                    "source_literal": source_literal,
                    "target_literal": target_literal,
                    **_clause_reason(clauses, cnf),
                }
            )
    equivalences: list[dict[str, Any]] = []
    seen_equivalences: set[tuple[tuple[int, int], tuple[int, int]]] = set()
    for bit, value, target_bit, target_value in sorted(reachability):
        if (target_bit, target_value, bit, value) not in reachability:
            continue
        left, right = sorted(((bit, value), (target_bit, target_value)))
        key = (left, right)
        if left == right or key in seen_equivalences:
            continue
        seen_equivalences.add(key)
        equivalences.append(
            {
                "left_bit": left[0],
                "left_value": left[1],
                "right_bit": right[0],
                "right_value": right[1],
                "scc_label": int(labels[literal_node(_literal_for(left[0], left[1], one_literals))]),
            }
        )
    return {
        "view": "V4_binary_implication_closure",
        "residual_binary_clause_count": len(binaries),
        "implication_edge_count": len(rows),
        "strongly_connected_component_count": int(component_count),
        "largest_strongly_connected_component_nodes": int(counts.max(initial=0)),
        "signed_key_implication_count": len(implications),
        "signed_key_equivalence_count": len(equivalences),
        "binary_forced_key_value_count": len(forced),
        "implications": implications,
        "equivalences": equivalences,
        "forced_key_values": forced,
    }


def _normalize_nogood(items: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...] | None:
    values: dict[int, int] = {}
    for bit, value in items:
        bit, value = int(bit), int(value)
        current = values.get(bit)
        if current is not None and current != value:
            return None
        values[bit] = value
    return tuple(sorted(values.items()))


def _minimal_nogoods(rows: Iterable[Iterable[tuple[int, int]]]) -> list[tuple[tuple[int, int], ...]]:
    unique = {
        normalized
        for row in rows
        if (normalized := _normalize_nogood(row)) is not None
    }
    retained: list[tuple[tuple[int, int], ...]] = []
    retained_sets: list[frozenset[tuple[int, int]]] = []
    for row in sorted(unique, key=lambda item: (len(item), item)):
        row_set = frozenset(row)
        if any(existing.issubset(row_set) for existing in retained_sets):
            continue
        retained.append(row)
        retained_sets.append(row_set)
    return retained


def _domain_view(
    base_view: dict[str, Any],
    single_view: dict[str, Any],
    pair_view: dict[str, Any],
    binary_view: dict[str, Any],
) -> dict[str, Any]:
    raw_nogoods: list[list[tuple[int, int]]] = []
    sources: dict[str, int] = {}

    def add(source: str, row: Iterable[tuple[int, int]]) -> None:
        raw_nogoods.append(list(row))
        sources[source] = sources.get(source, 0) + 1

    for row in base_view["forced_key_bits"]:
        add("V1_forced", [(row["bit"], 1 - row["value"])])
    for row in single_view["conflicts"]:
        add("V2_conflict", [(row["bit"], row["value"])])
    for row in single_view["implications"]:
        add(
            "V2_implication",
            [(row["if_bit"], row["if_value"]), (row["then_bit"], 1 - row["then_value"])],
        )
    for row in pair_view["pair_nogoods"]:
        add(
            "V3_pair_nogood",
            [(row["first_bit"], row["first_value"]), (row["second_bit"], row["second_value"])],
        )
    for row in pair_view["incremental_pair_implications"]:
        add(
            "V3_pair_implication",
            [
                (row["first_bit"], row["first_value"]),
                (row["second_bit"], row["second_value"]),
                (row["then_bit"], 1 - row["then_value"]),
            ],
        )
    for row in binary_view["forced_key_values"]:
        add("V4_forced", [(row["forbidden_bit"], row["forbidden_value"])])
    for row in binary_view["implications"]:
        add(
            "V4_implication",
            [(row["if_bit"], row["if_value"]), (row["then_bit"], 1 - row["then_value"])],
        )

    minimal = _minimal_nogoods(raw_nogoods)
    candidates = np.arange(1 << 20, dtype=np.uint32)
    bit_values = [((candidates >> bit) & 1).astype(np.bool_) for bit in range(20)]
    survivors = np.ones(len(candidates), dtype=np.bool_)
    for nogood in minimal:
        matched = np.ones(len(candidates), dtype=np.bool_)
        for bit, value in nogood:
            matched &= bit_values[bit] if value else ~bit_values[bit]
        survivors &= ~matched
    values = candidates[survivors].astype("<u4", copy=False)
    count = len(values)
    if count == 0:
        raise RuntimeError("A213 exact constraints eliminated the complete key domain")
    entropy = math.log2(count)
    return {
        "view": "V5_exact_domain_overlay",
        "initial_candidate_count": 1 << 20,
        "raw_exact_constraint_count": len(raw_nogoods),
        "raw_constraint_source_counts": dict(sorted(sources.items())),
        "minimal_nonredundant_nogood_count": len(minimal),
        "minimal_nogoods": [
            [{"bit": bit, "value": value} for bit, value in row] for row in minimal
        ],
        "surviving_candidate_count": count,
        "surviving_entropy_bits": entropy,
        "entropy_reduction_bits": 20.0 - entropy,
        "survivor_uint32_le_sha256": _sha256(values.tobytes()),
        "survivor_preview_low20": [int(value) for value in values[:32]],
        "preview_is_complete": count <= 32,
        "unique_candidate_low20": int(values[0]) if count == 1 else None,
        "exact_set_intersection_only": True,
        "independence_probability_multiplication_used": False,
    }


def _confirmation(
    domain: dict[str, Any], challenge: dict[str, Any], r20: Any
) -> dict[str, Any] | None:
    candidate = domain["unique_candidate_low20"]
    if candidate is None:
        return None
    model = r20._decode_model(challenge, [(candidate >> bit) & 1 for bit in range(20)])
    prefix = f"{(candidate >> 12) & 0xFF:08b}"
    confirmation = r20._confirm_model(
        challenge,
        mode="A213_exact_domain_overlay",
        prefix8=prefix,
        model=model,
    )
    if not confirmation["all_blocks_match"] or confirmation["control_first_block_match"]:
        raise RuntimeError("A213 unique candidate failed independent confirmation")
    return confirmation


def _evidence_stage(
    views: Sequence[dict[str, Any]], confirmation: dict[str, Any] | None
) -> str:
    base, single, pair, binary, domain = views
    relation_count = (
        base["forced_key_bit_count"]
        + single["conflict_count"]
        + single["implication_count"]
        + pair["pair_nogood_count"]
        + pair["incremental_pair_implication_count"]
        + binary["signed_key_implication_count"]
        + binary["binary_forced_key_value_count"]
    )
    if confirmation is not None:
        return "INDEPENDENTLY_CONFIRMED_PARTIAL_KEY_RECOVERY"
    if domain["surviving_candidate_count"] == 1:
        return "UNIQUE_CANDIDATE_DISCOVERY"
    if domain["surviving_candidate_count"] < 1 << 20:
        return "EXACT_KEY_DOMAIN_REDUCTION"
    if relation_count:
        return "EXACT_CAUSAL_RELATION_GRAPH"
    return "PROPAGATION_BOUNDARY"


def _provenance_ledger(cnf: ExactCNF, views: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ids: set[int] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "reason_clause_ids":
                    ids.update(int(item) for item in child)
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(list(views))
    rows = [
        {"clause_id": clause_id, "literals": list(cnf.clauses[clause_id])}
        for clause_id in sorted(ids)
    ]
    return {
        "referenced_clause_count": len(rows),
        "clauses": rows,
        "ledger_sha256": _canonical_sha256(rows),
    }


def _build_causal(
    *, payload: dict[str, Any], measurement_sha256: str, output: Path
) -> dict[str, Any]:
    views = payload["views"]
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_causal_pcr_backprojection",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "measurement_sha256": measurement_sha256,
            "R20_CNF_sha256": payload["cnf"]["sha256"],
            "fuzzy_matching": False,
            "independence_probability_multiplication": False,
        },
    )
    builder.add_rule(
        ExactRule(
            name="public_constraints_to_base_backprojection",
            first="encoded_as_exact_R20_CNF",
            second="exact_base_unit_closure",
            conclusion="exact_base_backprojection",
        )
    )
    builder.add_rule(
        ExactRule(
            name="exact_views_to_domain_overlay",
            first="exact_base_backprojection",
            second="intersected_with_exact_multiview_constraints",
            conclusion="exact_key_domain_backprojection",
        )
    )
    builder.add_triplet(
        edge_id="a213-public-standard-output-constraints",
        trigger="ChaCha20:R20:eight_public_input_output_blocks",
        mechanism="encoded_as_exact_R20_CNF",
        outcome="A213:frozen_R20_CNF",
        confidence=1.0,
        evidence_kind="byte_hash_gated_exact_encoding",
        source=f"measurement:sha256:{measurement_sha256}",
        attrs=payload["cnf"],
    )
    mechanisms = (
        "exact_base_unit_closure",
        "exact_single_literal_backprojection",
        "exact_pair_literal_backprojection",
        "exact_binary_implication_closure",
        "intersected_with_exact_multiview_constraints",
    )
    previous = "A213:frozen_R20_CNF"
    for index, (view, mechanism) in enumerate(zip(views, mechanisms, strict=True), start=1):
        outcome = f"A213:{view['view']}:result"
        attrs = {
            key: value
            for key, value in view.items()
            if key
            not in {
                "conflicts",
                "implications",
                "pair_nogoods",
                "incremental_pair_implications",
                "minimal_nogoods",
                "survivor_preview_low20",
            }
        }
        builder.add_triplet(
            edge_id=f"a213-view-{index}",
            trigger=previous,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind="exact_constraint_computation",
            source=f"measurement:sha256:{measurement_sha256}",
            attrs=attrs,
        )
        previous = outcome

    relation_groups = (
        (views[0].get("forced_key_bits", []), "V1", "forced_key_literal"),
        (views[1].get("conflicts", []), "V2c", "contradictory_key_literal"),
        (views[1].get("implications", []), "V2i", "implied_key_literal"),
        (views[2].get("pair_nogoods", []), "V3n", "contradictory_key_literal_pair"),
        (
            views[2].get("incremental_pair_implications", []),
            "V3i",
            "pair_conditioned_key_literal",
        ),
        (views[3].get("forced_key_values", []), "V4f", "binary_forced_key_literal"),
        (views[3].get("implications", []), "V4i", "binary_implied_key_literal"),
    )
    for rows, label, mechanism in relation_groups:
        for index, row in enumerate(rows):
            builder.add_triplet(
                edge_id=f"a213-relation-{label}-{index:05d}",
                trigger=f"A213:{label}:assumption:{index}",
                mechanism=mechanism,
                outcome=f"A213:{label}:exact_relation:{index}",
                confidence=1.0,
                evidence_kind="clause_reason_dag",
                source=f"measurement:sha256:{measurement_sha256}",
                attrs=row,
            )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A213 causal readback provenance gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    base, single, pair, binary, domain = payload["views"]
    confirmation = payload["confirmation"]
    lines = [
        "# ChaCha20 R20 Causal-PCR Exact Backprojection (A213)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A213 treats the key signal as joint compatibility with the public standard-output constraints, "
        "not as compressibility of the key bytes themselves. The five views share one exact CNF; their "
        "constraints are intersected, never multiplied as independent probabilities.",
        "",
        "## Exact readout",
        "",
        f"- V1 base closure: {base['assigned_variable_count']} assigned variables; "
        f"{base['forced_key_bit_count']} forced key bits.",
        f"- V2 singles: {single['conflict_count']} contradictions; "
        f"{single['implication_count']} key implications across 40 probes.",
        f"- V3 pairs: {pair['pair_nogood_count']} pair nogoods; "
        f"{pair['incremental_pair_implication_count']} genuinely pair-conditioned implications across 760 probes.",
        f"- V4 binary graph: {binary['residual_binary_clause_count']} residual binary clauses; "
        f"{binary['signed_key_implication_count']} signed-key implications; "
        f"{binary['signed_key_equivalence_count']} equivalences.",
        f"- V5 overlay: {domain['surviving_candidate_count']} / 1,048,576 candidates; "
        f"entropy reduction {domain['entropy_reduction_bits']:.12f} bits.",
        "",
        "## Scope",
        "",
        "This experiment uses eight public standard ChaCha20 R20 input-output blocks and 236 declared "
        "known key bits. Secret-key R1-R19 states are not observed and candidate-generated trajectories "
        "are not relabeled as observations. A per-round versus jointly stacked CASI/F8/Kolmogorov arm "
        "therefore remains a separately labeled cross-round-oracle experiment.",
        "",
        "## Reproduction anchors",
        "",
        f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
        f"- R20 CNF SHA-256: `{payload['cnf']['sha256']}`",
        f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
        f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        f"- Causal reader provenance verified: `{payload['causal_artifact']['reader_verified']}`",
    ]
    if confirmation is not None:
        lines.extend(
            [
                "",
                "## Independent confirmation",
                "",
                f"The unique low-20 candidate is `0x{confirmation['recovered_unknown_low20']:05x}` and "
                f"matches all {confirmation['output_bits_checked']} independently recomputed output bits; "
                "the frozen flipped control rejects.",
            ]
        )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(*, output: Path, causal_output: Path, report_output: Path) -> dict[str, Any]:
    protocol = _load_protocol()
    r20 = _load_r20()
    with tempfile.TemporaryDirectory(prefix="a213-causal-pcr-") as temporary:
        analysis, transformed, cnf_path = _rebuild_cnf(
            protocol, r20, Path(temporary)
        )
        raw = cnf_path.read_bytes()
        cnf = ExactCNF.from_dimacs(raw)
        expected_counts = {
            int(key): int(value)
            for key, value in protocol["dimacs_gates"]["expected_clause_length_counts"].items()
        }
        if (
            cnf.variable_count != 68783
            or cnf.clause_count != 216461
            or cnf.length_counts != expected_counts
        ):
            raise RuntimeError("A213 strict DIMACS semantic gates failed")
        one_literals = transformed["transformed_one_literals_bit0_through_bit19"]
        base_state, base_view = _base_view(cnf, one_literals)
        single_view, single_implications = _single_view(cnf, base_state, one_literals)
        pair_view = _pair_view(
            cnf, base_state, one_literals, single_implications
        )
        binary_view = _binary_view(cnf, base_state, one_literals)
        domain_view = _domain_view(base_view, single_view, pair_view, binary_view)
        views = [base_view, single_view, pair_view, binary_view, domain_view]
        confirmation = _confirmation(domain_view, analysis["public_challenge"], r20)
        ledger = _provenance_ledger(cnf, views)

    measurement = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "public_challenge_sha256": protocol["anchors"]["public_challenge_sha256"],
        "cnf": {
            "header": raw.splitlines()[0].decode(),
            "bytes": len(raw),
            "sha256": _sha256(raw),
            "variable_count": cnf.variable_count,
            "clause_count": cnf.clause_count,
            "clause_length_counts": {
                str(key): value for key, value in cnf.length_counts.items()
            },
        },
        "views": views,
        "provenance_clause_ledger": ledger,
        "confirmation": confirmation,
        "information_boundary": protocol["information_boundary"],
        "observable_scope": protocol["observable_scope"],
        "evidence_stage": _evidence_stage(views, confirmation),
    }
    measurement_sha256 = _canonical_sha256(measurement)
    causal_stats = _build_causal(
        payload=measurement,
        measurement_sha256=measurement_sha256,
        output=causal_output,
    )
    payload = {
        **measurement,
        "measurement_sha256": measurement_sha256,
        "causal_artifact": causal_stats,
    }
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH / "results" / "v1" / "chacha20_round20_causal_pcr_backprojection_v1.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH / "results" / "v1" / "chacha20_round20_causal_pcr_backprojection_v1.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_PCR_BACKPROJECTION_V1.md",
    )
    args = parser.parse_args()
    payload = run(
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
    )
    domain = payload["views"][4]
    print(
        f"{payload['evidence_stage']}: "
        f"{domain['surviving_candidate_count']}/1048576 candidates, "
        f"{domain['entropy_reduction_bits']:.6f} bits reduced"
    )
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output}")
    print(f"wrote {args.report_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
