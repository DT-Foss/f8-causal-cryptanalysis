#!/usr/bin/env python3
"""Formula-derived structural CNF ordering calibration on the A188 anchor."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import (
    connected_components,
    laplacian,
    reverse_cuthill_mckee,
)
from scipy.sparse.linalg import eigsh

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A204 = _import_sibling(
    "chacha20_round10_external_cnf_reverse.py",
    "chacha20_a188_cnf_structural_a204_anchor",
)
_A188 = _A204._A188

ATTEMPT_ID = "A205"
SCHEMA = "chacha20-a188-cnf-structural-ordering-calibration-v1"
PROTOCOL_SCHEMA = "chacha20-a188-cnf-structural-ordering-calibration-protocol-v1"
PROTOCOL_FILENAME = "chacha20_a188_cnf_structural_ordering_v1.json"
PROTOCOL_SHA256 = "53a7f8a7527218e8db386d62cbc082466050b5b62eee3798edb808602e058730"
RESULT_FILENAME = "chacha20_a188_cnf_structural_ordering_v1.json"
CAUSAL_FILENAME = "chacha20_a188_cnf_structural_ordering_v1.causal"

A204_FILENAME = _A204.RESULT_FILENAME
A204_SHA256 = "603eaf8a2a6bb85c3c4bb2fdf4b7466205ffd1d8005593d987c8a6461b7c8c22"
A204_CAUSAL_FILENAME = _A204.CAUSAL_FILENAME
A204_CAUSAL_SHA256 = "f1ca39f964640d8aa2a5c6f6dab9bcfb48dfaddf6dda2e399275f77235ca71c3"
A204_CAUSAL_GRAPH_SHA256 = "0cbdde4c25a7c804706a9e8b9823c71ec9bc74046191526cae4a7a55b5dbdc73"
FORMULA_ATLAS_REPORT = "reports/FORMULA_ATLAS_FULL_REAUDIT_V1.md"
FORMULA_ATLAS_REPORT_SHA256 = "a4d43be43e56590402cf74febcdb5faf40de9b7640bb47ca32e7779f5d4a5d87"
FORMULA_ATLAS_COVERAGE = "results/v1/formula_atlas_transfer_coverage_v1.json"
FORMULA_ATLAS_COVERAGE_SHA256 = "feadca39a2cdb0caf38018e9d28ed6aecd56384f5771d7a6e6ab261f87ee1cc2"

SOLVER_LIMIT_SECONDS = 5
EXTERNAL_TIMEOUT_SECONDS = 8
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CONTROL_CANDIDATES = {
    "identity_control",
    "reverse_id_control",
    "shake256_random_control",
}
METRIC_PATTERN = re.compile(r"^c (conflicts|decisions|propagations|restarts):\s+([0-9]+)", re.M)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A205 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    plan = protocol.get("execution_plan", {})
    source = protocol.get("source", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A204_r3_and_formula_atlas_transfer_design_before_any_A205_structural_solver_execution"
        or len(protocol.get("candidates", [])) != 23
        or protocol.get("candidate_order")
        != [row["name"] for row in protocol.get("candidates", [])]
        or plan.get("total_variant_count") != 46
        or plan.get("solver_time_limit_seconds_per_variant") != SOLVER_LIMIT_SECONDS
        or source.get("cnf_sha256")
        != "a49e7ec1ea7135b760d732855fe05b91ac85c56cf786e0777bb9a2188d6a3216"
        or boundary.get("any_new_A205_structural_candidate_outcome_known_before_freeze")
        is not False
        or boundary.get("known_positive_model_in_protocol") is not True
        or boundary.get("known_positive_model_available_to_runner_before_execution") is not True
        or boundary.get("model_used_only_for_post_witness_confirmation") is not True
        or boundary.get("model_not_used_in_order_construction_or_solver_input") is not True
        or boundary.get("mapping_candidates_or_solver_modes_changed_after_any_new_A205_outcome")
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A205 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A204_FILENAME
    causal_path = results_dir / A204_CAUSAL_FILENAME
    if _file_sha256(result_path) != A204_SHA256 or _file_sha256(causal_path) != A204_CAUSAL_SHA256:
        raise RuntimeError("A205 A204 anchor hash gate failed")
    payload = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    if (
        payload.get("evidence_stage") != "ROUND10_EXTERNAL_CNF_COMPLETE_PARTITION_BOUNDARY_RETAINED"
        or payload.get("calibration_replay", {}).get("retained") is not True
        or payload.get("mapping_replay", {}).get("all_70_probes_exactly_one_unit_clause")
        is not True
        or payload.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
        or reader.file_sha256 != A204_CAUSAL_SHA256
        or reader.graph_sha256 != A204_CAUSAL_GRAPH_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A205 A204 anchor content gate failed")
    research_root = Path(__file__).parents[1]
    report_path = research_root / FORMULA_ATLAS_REPORT
    coverage_path = research_root / FORMULA_ATLAS_COVERAGE
    if (
        _file_sha256(report_path) != FORMULA_ATLAS_REPORT_SHA256
        or _file_sha256(coverage_path) != FORMULA_ATLAS_COVERAGE_SHA256
    ):
        raise RuntimeError("A205 formula-atlas anchor hash gate failed")
    coverage = json.loads(coverage_path.read_bytes())
    if (
        coverage.get("summary", {}).get("entries") != 2411
        or coverage.get("summary", {}).get("pages") != 113
    ):
        raise RuntimeError("A205 formula-atlas content gate failed")
    return {
        "A204_result_sha256": A204_SHA256,
        "A204_causal_sha256": A204_CAUSAL_SHA256,
        "A204_causal_graph_sha256": A204_CAUSAL_GRAPH_SHA256,
        "A204_causal_provenance_verified": True,
        "A204_full_calibration_mapping_and_round10_boundary_retained": True,
        "formula_atlas_report_sha256": FORMULA_ATLAS_REPORT_SHA256,
        "formula_atlas_coverage_sha256": FORMULA_ATLAS_COVERAGE_SHA256,
        "formula_atlas_2411_entries_113_pages_retained": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    a204 = _A204.analyze(results_dir)
    if (
        _sha256(a204["a188_formula"].encode()) != protocol["source"]["formula_sha256"]
        or len(a204["a188_formula"].encode()) != protocol["source"]["formula_bytes"]
        or a204["a188_public_challenge"]["unknown_assignment_included"] is not False
        or a204["a188_public_challenge"]["unknown_key_word0_included"] is not False
    ):
        raise RuntimeError("A205 A188 source challenge gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "a188_formula": a204["a188_formula"],
        "a188_public_challenge": a204["a188_public_challenge"],
        "solver_execution_started": False,
    }


def _parse_cnf(raw: bytes) -> dict[str, Any]:
    lines = raw.splitlines()
    header = lines[0].split()
    if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
        raise RuntimeError("A205 invalid DIMACS header")
    variable_count = int(header[2])
    declared_clauses = int(header[3])
    clauses = []
    occurrence = np.zeros(variable_count, dtype=np.int64)
    first = np.full(variable_count, declared_clauses, dtype=np.int64)
    last = np.full(variable_count, -1, dtype=np.int64)
    units = []
    rows = []
    columns = []
    length_counts: dict[int, int] = {}
    for clause_index, line in enumerate(lines[1:]):
        values = tuple(int(raw_value) for raw_value in line.split())
        if not values or values[-1] != 0:
            raise RuntimeError("A205 invalid DIMACS clause")
        clause = values[:-1]
        clauses.append(clause)
        length_counts[len(clause)] = length_counts.get(len(clause), 0) + 1
        absolute = [abs(literal) for literal in clause]
        for variable in absolute:
            index = variable - 1
            occurrence[index] += 1
            first[index] = min(first[index], clause_index)
            last[index] = max(last[index], clause_index)
        if len(absolute) == 1:
            units.append(absolute[0])
        for left_index in range(len(absolute)):
            for right_index in range(left_index + 1, len(absolute)):
                left = absolute[left_index] - 1
                right = absolute[right_index] - 1
                rows.extend((left, right))
                columns.extend((right, left))
    if len(clauses) != declared_clauses:
        raise RuntimeError("A205 DIMACS clause count differs")
    graph = coo_matrix(
        (np.ones(len(rows), dtype=np.uint8), (rows, columns)),
        shape=(variable_count, variable_count),
    ).tocsr()
    graph.sum_duplicates()
    graph.data[:] = 1
    component_count, labels = connected_components(graph, directed=False)
    degrees = np.diff(graph.indptr).astype(np.int64)
    return {
        "raw": raw,
        "variable_count": variable_count,
        "clause_count": len(clauses),
        "clauses": clauses,
        "occurrence": occurrence,
        "first": first,
        "last": last,
        "span": last - first,
        "units": np.array(sorted(set(units)), dtype=np.int64),
        "length_counts": length_counts,
        "graph": graph,
        "degrees": degrees,
        "component_count": int(component_count),
        "component_sizes": np.bincount(labels),
    }


def _multi_source_bfs(graph: Any, sources_one_based: np.ndarray) -> np.ndarray:
    distances = np.full(graph.shape[0], -1, dtype=np.int64)
    queue: deque[int] = deque()
    for source in sources_one_based:
        index = int(source) - 1
        if distances[index] == -1:
            distances[index] = 0
            queue.append(index)
    while queue:
        current = queue.popleft()
        start, end = graph.indptr[current], graph.indptr[current + 1]
        for neighbor in graph.indices[start:end]:
            if distances[neighbor] == -1:
                distances[neighbor] = distances[current] + 1
                queue.append(int(neighbor))
    distances[distances < 0] = graph.shape[0] + 1
    return distances


def _alternate_orders(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    seen = np.zeros(len(first) + 1, dtype=bool)
    result = []
    left_index = 0
    right_index = 0
    while len(result) < len(first):
        for order, index_name in ((first, "left"), (second, "right")):
            index = left_index if index_name == "left" else right_index
            while index < len(order) and seen[int(order[index])]:
                index += 1
            if index < len(order):
                value = int(order[index])
                result.append(value)
                seen[value] = True
                index += 1
            if index_name == "left":
                left_index = index
            else:
                right_index = index
            if len(result) == len(first):
                break
    return np.asarray(result, dtype=np.int64)


def _candidate_orders(
    parsed: dict[str, Any], protocol: dict[str, Any]
) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    variable_count = parsed["variable_count"]
    ids = np.arange(1, variable_count + 1, dtype=np.int64)
    graph = parsed["graph"]
    mapping = protocol["source"]["key_variable_one_literal_mapping"]
    key_sources = np.array(
        sorted({abs(value) for values in mapping.values() for value in values}), dtype=np.int64
    )
    unit_distance = _multi_source_bfs(graph, parsed["units"])
    key_distance = _multi_source_bfs(graph, key_sources)
    distance_sum = unit_distance + key_distance
    signed_distance = key_distance - unit_distance

    unit_near = ids[np.lexsort((ids, unit_distance))]
    unit_far = ids[np.lexsort((ids, -unit_distance))]
    key_near = ids[np.lexsort((ids, key_distance))]
    key_far = ids[np.lexsort((ids, -key_distance))]

    normalized_laplacian = laplacian(graph.astype(np.float64), normed=True)
    old = ids.astype(np.float64)
    v0 = np.sin(old * math.sqrt(2.0)) + np.cos(old * math.sqrt(3.0))
    eigenvalues, eigenvectors = eigsh(
        normalized_laplacian,
        k=2,
        which="SM",
        tol=protocol["spectral_construction"]["tolerance"],
        maxiter=protocol["spectral_construction"]["max_iterations"],
        v0=v0,
    )
    order = np.argsort(eigenvalues)
    eigenvalues = eigenvalues[order]
    fiedler = eigenvectors[:, order[1]]
    if float(np.dot(fiedler, v0)) < 0:
        fiedler = -fiedler

    random_label = b"f8-causal:A205:shake256-random-control:v1:"
    random_keys = np.fromiter(
        (
            int.from_bytes(
                hashlib.shake_256(random_label + int(value).to_bytes(4, "little")).digest(8),
                "little",
            )
            for value in ids
        ),
        dtype=np.uint64,
        count=variable_count,
    )

    candidates = {
        "identity_control": ids,
        "reverse_id_control": ids[::-1],
        "occurrence_degree_ascending": ids[np.lexsort((ids, parsed["occurrence"]))],
        "occurrence_degree_descending": ids[np.lexsort((ids, -parsed["occurrence"]))],
        "adjacency_degree_ascending": ids[np.lexsort((ids, parsed["degrees"]))],
        "adjacency_degree_descending": ids[np.lexsort((ids, -parsed["degrees"]))],
        "last_occurrence_descending": ids[np.lexsort((ids, -parsed["last"]))],
        "last_occurrence_ascending": ids[np.lexsort((ids, parsed["last"]))],
        "occurrence_span_ascending": ids[np.lexsort((ids, parsed["span"]))],
        "output_unit_bfs_near": unit_near,
        "output_unit_bfs_far": unit_far,
        "key_bfs_near": key_near,
        "key_bfs_far": key_far,
        "bidirectional_min_distance": ids[
            np.lexsort((ids, signed_distance, np.minimum(unit_distance, key_distance)))
        ],
        "alternating_key_output_bfs": _alternate_orders(key_near, unit_near),
        "signed_key_minus_output_ascending": ids[np.lexsort((ids, distance_sum, signed_distance))],
        "signed_key_minus_output_descending": ids[
            np.lexsort((ids, distance_sum, -signed_distance))
        ],
        "output_layer_parity_interleave": ids[np.lexsort((ids, unit_distance, unit_distance % 2))],
        "reverse_cuthill_mckee": reverse_cuthill_mckee(graph, symmetric_mode=True).astype(np.int64)
        + 1,
        "fiedler_ascending": ids[np.lexsort((ids, fiedler))],
        "fiedler_descending": ids[np.lexsort((ids, -fiedler))],
        "fiedler_center_out": ids[np.lexsort((ids, fiedler, np.abs(fiedler)))],
        "shake256_random_control": ids[np.lexsort((ids, random_keys))],
    }
    if list(candidates) != protocol["candidate_order"]:
        raise RuntimeError("A205 generated candidate order differs from freeze")
    expected = np.arange(1, variable_count + 1, dtype=np.int64)
    for name, candidate in candidates.items():
        if len(candidate) != variable_count or not np.array_equal(np.sort(candidate), expected):
            raise RuntimeError(f"A205 {name} is not a bijective variable order")
    hashes = {
        name: _sha256(candidate.astype("<u4", copy=False).tobytes())
        for name, candidate in candidates.items()
    }
    if len(set(hashes.values())) != len(hashes):
        groups: dict[str, list[str]] = {}
        for name, digest in hashes.items():
            groups.setdefault(digest, []).append(name)
        duplicates = [names for names in groups.values() if len(names) > 1]
        raise RuntimeError(
            "A205 candidate orders are not pairwise distinct: "
            + json.dumps(duplicates, sort_keys=True)
        )
    diagnostics = {
        "key_source_count": len(key_sources),
        "unit_source_count": len(parsed["units"]),
        "key_distance_min": int(key_distance.min()),
        "key_distance_max": int(key_distance.max()),
        "unit_distance_min": int(unit_distance.min()),
        "unit_distance_max": int(unit_distance.max()),
        "fiedler_eigenvalues": [float(value) for value in eigenvalues],
        "fiedler_residual": float(
            np.linalg.norm(normalized_laplacian @ fiedler - eigenvalues[1] * fiedler)
        ),
        "candidate_order_sha256": hashes,
    }
    return candidates, diagnostics


def _old_to_new(order: np.ndarray) -> np.ndarray:
    mapping = np.zeros(len(order) + 1, dtype=np.int64)
    mapping[order] = np.arange(1, len(order) + 1, dtype=np.int64)
    return mapping


def _reindex_cnf(raw: bytes, old_to_new: np.ndarray) -> bytes:
    lines = raw.splitlines()
    output = bytearray(lines[0] + b"\n")
    for line in lines[1:]:
        values = [int(value) for value in line.split()]
        if not values or values[-1] != 0:
            raise RuntimeError("A205 cannot reindex malformed DIMACS")
        mapped = [
            int(old_to_new[abs(literal)]) if literal > 0 else -int(old_to_new[abs(literal)])
            for literal in values[:-1]
        ]
        output.extend((" ".join(str(value) for value in [*mapped, 0]) + "\n").encode())
    return bytes(output)


def _transform_candidates(
    parsed: dict[str, Any], candidates: dict[str, np.ndarray], directory: Path
) -> tuple[list[dict[str, Any]], dict[str, Path], dict[str, np.ndarray]]:
    original = parsed["raw"]
    original_sha256 = _sha256(original)
    plan = []
    paths = {}
    mappings = {}
    for name, order in candidates.items():
        mapping = _old_to_new(order)
        inverse = np.zeros_like(mapping)
        inverse[mapping[1:]] = np.arange(1, len(mapping), dtype=np.int64)
        transformed = _reindex_cnf(original, mapping)
        restored = _reindex_cnf(transformed, inverse)
        if _sha256(restored) != original_sha256 or restored != original:
            raise RuntimeError(f"A205 {name} inverse semantic gate failed")
        path = directory / f"{name}.cnf"
        path.write_bytes(transformed)
        plan.append(
            {
                "candidate": name,
                "order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
                "old_to_new_sha256": _sha256(mapping.astype("<u4", copy=False).tobytes()),
                "cnf_sha256": _sha256(transformed),
                "cnf_bytes": len(transformed),
                "inverse_restored_sha256": _sha256(restored),
                "inverse_byte_identical": True,
            }
        )
        paths[name] = path
        mappings[name] = mapping
    return plan, paths, mappings


def _solver_metrics(stdout: str) -> dict[str, int]:
    return {name: int(value) for name, value in METRIC_PATTERN.findall(stdout)}


def _run_variant(
    *,
    candidate: str,
    mode: dict[str, Any],
    cnf_path: Path,
    mapping: np.ndarray,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    command = [
        cadical_path,
        *mode["arguments"],
        "-t",
        str(SOLVER_LIMIT_SECONDS),
        str(cnf_path),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = _A204._as_text(error.stdout)
        stderr = _A204._as_text(error.stderr)
        returncode = None
    status = _A204._cadical_status(stdout, returncode)
    status_lines = [line.strip() for line in stdout.splitlines() if line.startswith("s ")]
    witness = _A204._parse_cadical_witness(stdout) if status == "sat" else {}
    model = None
    confirmation = None
    if status == "sat":
        source_mapping = protocol["source"]["key_variable_one_literal_mapping"]
        transformed_literals = {
            symbol: [
                int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
                for literal in literals
            ]
            for symbol, literals in source_mapping.items()
        }
        key_word0 = _A204._decode_literals(witness, transformed_literals["k0"])
        key_word1_low_value = _A204._decode_literals(witness, transformed_literals["lo8"])
        model = {
            "key_word0": key_word0,
            "key_word1_low_value": key_word1_low_value,
            "combined_assignment": (key_word1_low_value << 32) | key_word0,
        }
        confirmation = _A188._A187._confirm_model(challenge, 8, model)
        expected = protocol["source"]["recovered_model"]
        if (
            model["key_word0"] != expected["key_word0"]
            or model["key_word1_low_value"] != expected["key_word1_low_value"]
            or confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError(f"A205 {candidate}/{mode['name']} model confirmation failed")
    observation = {
        "variant": f"{candidate}__{mode['name']}",
        "candidate": candidate,
        "solver_mode": mode["name"],
        "command": command,
        "status": status,
        "status_line": status_lines[0] if len(status_lines) == 1 else None,
        "internal_timeout_marker": any(
            line.startswith("c Timeout reached!") for line in stdout.splitlines()
        ),
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "witness_assignment_count": len(witness),
        "metrics": _solver_metrics(stdout),
        "model": model,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }
    if status == "unknown" and (
        observation["returncode"] != 0
        or observation["internal_timeout_marker"] is not True
        or observation["externally_timed_out"] is not False
    ):
        raise RuntimeError(f"A205 {candidate}/{mode['name']} invalid UNKNOWN boundary")
    return observation, confirmation


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_a188_cnf_structural_ordering",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "candidate_count": 23,
            "variant_count": 46,
            "unknown_key_bits": 40,
        },
    )
    ids = [
        "chacha20-a205-formula-atlas-transfer",
        "chacha20-a205-a204-exact-cnf-anchor",
        "chacha20-a205-primal-graph",
        "chacha20-a205-structural-orders",
        "chacha20-a205-bijective-reindex",
        "chacha20-a205-complete-calibration",
        "chacha20-a205-confirmed-outliers",
    ]
    rows = [
        (
            "formula_atlas:2411_source_first_entries",
            "transfer_T01_T04_T05_to_CNF_variable_geometry",
            "A205:frozen_structural_order_family",
            "formula_transfer",
            FORMULA_ATLAS_COVERAGE_SHA256,
            [],
            {"protocol_candidates": payload["protocol_gate"]["candidate_order"]},
        ),
        (
            "A205:frozen_structural_order_family",
            "anchor_A204_full_calibration_literal_map_and_round10_boundary",
            "A205:exact_A188_CNF_source",
            "retained_CNF_anchor",
            A204_CAUSAL_SHA256,
            [ids[0]],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A205:exact_A188_CNF_source",
            "construct_connected_clause_primal_graph_and_two_source_distances",
            "A205:structural_graph_diagnostics",
            "exact_sparse_graph",
            payload["graph_sha256"],
            [ids[1]],
            {"graph": payload["graph"]},
        ),
        (
            "A205:structural_graph_diagnostics",
            "derive_23_frozen_degree_BFS_RCM_Fiedler_and_control_orders",
            "A205:pairwise_distinct_variable_orders",
            "structural_order_derivation",
            payload["candidate_diagnostics_sha256"],
            [ids[2]],
            {"candidate_diagnostics": payload["candidate_diagnostics"]},
        ),
        (
            "A205:pairwise_distinct_variable_orders",
            "bijectively_reindex_and_inverse_restore_every_DIMACS_instance",
            "A205:semantics_preserved_candidate_CNF_family",
            "byte_exact_inverse_semantic_gate",
            payload["transform_plan_sha256"],
            [ids[3]],
            {"transform_plan": payload["transform_plan"]},
        ),
        (
            "A205:semantics_preserved_candidate_CNF_family",
            "execute_all_46_mapping_mode_variants_at_fixed_5_second_budget",
            "A205:complete_structural_calibration",
            "complete_predeclared_calibration",
            payload["execution_sha256"],
            [ids[4]],
            {"execution": payload["execution"]},
        ),
        (
            "A205:complete_structural_calibration",
            "decode_every_SAT_witness_and_recompute_all_4096_target_bits",
            "A205:confirmed_structural_outlier_result",
            "independent_model_confirmation",
            payload["comparison_sha256"],
            [ids[5]],
            {"confirmations": payload["confirmations"], "comparisons": payload["comparisons"]},
        ),
    ]
    if "metadata_correction" in payload:
        ids.append("chacha20-a205-boundary-metadata-correction")
        rows.append(
            (
                "A205:confirmed_structural_outlier_result",
                "correct_the_known_positive_model_boundary_without_changing_solver_observations",
                "A205:internally_consistent_known_positive_calibration_record",
                "provenance_metadata_correction",
                payload["metadata_correction_sha256"],
                [ids[-2]],
                {"metadata_correction": payload["metadata_correction"]},
            )
        )
    for index, row in enumerate(rows):
        trigger, mechanism, outcome, kind, source, provenance, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
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
    if len(reader.triplets(include_inferred=False)) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("A205 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    protocol = analysis["protocol"]
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    with tempfile.TemporaryDirectory(prefix="a205-structural-cnf-") as raw_directory:
        directory = Path(raw_directory)
        cnf_path = directory / "A188.cnf"
        exported = _A204._export_cnf(
            variant="A188_structural_source",
            formula=analysis["a188_formula"],
            output=cnf_path,
            bitwuzla_path=identities["bitwuzla"]["path"],
            limit_ms=1_000,
        )
        if (
            exported["sha256"] != protocol["source"]["cnf_sha256"]
            or exported["bytes"] != protocol["source"]["cnf_bytes"]
            or exported["header"] != protocol["source"]["cnf_header"]
        ):
            raise RuntimeError("A205 source CNF identity gate failed")
        parsed = _parse_cnf(cnf_path.read_bytes())
        graph = parsed["graph"]
        graph_payload = {
            "variable_count": parsed["variable_count"],
            "clause_count": parsed["clause_count"],
            "clause_length_counts": {
                str(key): value for key, value in sorted(parsed["length_counts"].items())
            },
            "unit_clause_variable_count": len(parsed["units"]),
            "undirected_edges": int(graph.nnz // 2),
            "connected_components": parsed["component_count"],
            "largest_component": int(parsed["component_sizes"].max()),
            "isolated_vertices": int(np.sum(parsed["component_sizes"] == 1)),
            "minimum_degree": int(parsed["degrees"].min()),
            "maximum_degree": int(parsed["degrees"].max()),
            "csr_indptr_sha256": _sha256(graph.indptr.astype("<i8", copy=False).tobytes()),
            "csr_indices_sha256": _sha256(graph.indices.astype("<i4", copy=False).tobytes()),
        }
        expected_graph = protocol["graph_construction"]
        if (
            graph_payload["variable_count"] != expected_graph["vertices"]
            or graph_payload["undirected_edges"] != expected_graph["undirected_edges"]
            or graph_payload["connected_components"] != expected_graph["connected_components"]
            or graph_payload["minimum_degree"] != expected_graph["minimum_degree"]
            or graph_payload["maximum_degree"] != expected_graph["maximum_degree"]
            or graph_payload["unit_clause_variable_count"]
            != protocol["source"]["unit_clause_variable_count"]
        ):
            raise RuntimeError("A205 graph structural gate failed")
        candidates, candidate_diagnostics = _candidate_orders(parsed, protocol)
        transform_plan, paths, mappings = _transform_candidates(parsed, candidates, directory)
        observations = []
        confirmations = []
        for candidate in protocol["candidate_order"]:
            for mode in protocol["solver_modes"]:
                observation, confirmation = _run_variant(
                    candidate=candidate,
                    mode=mode,
                    cnf_path=paths[candidate],
                    mapping=mappings[candidate],
                    protocol=protocol,
                    challenge=analysis["a188_public_challenge"],
                    cadical_path=identities["cadical"]["path"],
                )
                observations.append(observation)
                if confirmation is not None:
                    confirmations.append(
                        {
                            "variant": observation["variant"],
                            "candidate": candidate,
                            "solver_mode": mode["name"],
                            **confirmation,
                        }
                    )

    expected_variants = [
        f"{candidate}__{mode['name']}"
        for candidate in protocol["candidate_order"]
        for mode in protocol["solver_modes"]
    ]
    if [row["variant"] for row in observations] != expected_variants:
        raise RuntimeError("A205 complete execution order differs from freeze")
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    confirmed_variants = [row["variant"] for row in confirmations]
    confirmed_candidates = [
        candidate
        for candidate in protocol["candidate_order"]
        if any(row["candidate"] == candidate for row in confirmations)
    ]
    structural_outliers = [
        candidate for candidate in confirmed_candidates if candidate not in CONTROL_CANDIDATES
    ]
    robust = [
        candidate
        for candidate in structural_outliers
        if {row["solver_mode"] for row in confirmations if row["candidate"] == candidate}
        == {"default", "reverse"}
    ]
    comparisons = {
        "complete_variant_count": len(observations),
        "complete_predeclared_execution": len(observations) == 46,
        "early_stop_used": False,
        "status_counts": status_counts,
        "confirmed_variants": confirmed_variants,
        "confirmed_candidates": confirmed_candidates,
        "structural_outlier_candidates": structural_outliers,
        "robust_both_mode_structural_candidates": robust,
        "A206_transfer_selection": structural_outliers,
        "primary_prediction_retained": len(structural_outliers) >= 1,
        "robust_prediction_retained": len(robust) >= 1,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "A188_CNF_ROBUST_STRUCTURAL_ORDERING_OUTLIER_RETAINED"
        if robust
        else (
            "A188_CNF_STRUCTURAL_ORDERING_OUTLIER_RETAINED"
            if structural_outliers
            else "A188_CNF_STRUCTURAL_ORDERING_BOUNDARY_RETAINED"
        )
    )
    execution = {
        "variant_order": expected_variants,
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "known_positive_model_available_to_runner_before_execution": True,
        "model_used_only_for_post_witness_confirmation": True,
        "model_not_used_in_order_construction_or_solver_input": True,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Twenty-three formula-derived structural CNF orders are calibrated in both "
            "default and reverse CaDiCaL modes on the exact A188 known-positive anchor."
        ),
        "scope": "Known-positive ChaCha5 40-bit partial-key recovery calibration.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "candidate_order": protocol["candidate_order"],
            "solver_modes": protocol["solver_modes"],
            "information_boundary": protocol["information_boundary"],
            "prospective_rules": protocol["prospective_rules"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "solver_identities": {
            "bitwuzla": identities["bitwuzla"],
            "cadical": identities["cadical"],
        },
        "source_export": {key: value for key, value in exported.items() if key != "path"},
        "source_export_sha256": _canonical_sha256(
            {key: value for key, value in exported.items() if key != "path"}
        ),
        "graph": graph_payload,
        "graph_sha256": _canonical_sha256(graph_payload),
        "candidate_diagnostics": candidate_diagnostics,
        "candidate_diagnostics_sha256": _canonical_sha256(candidate_diagnostics),
        "transform_plan": transform_plan,
        "transform_plan_sha256": _canonical_sha256(transform_plan),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A204._A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A205 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": status_counts,
        "confirmed_variants": confirmed_variants,
        "structural_outlier_candidates": structural_outliers,
        "robust_both_mode_structural_candidates": robust,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        summary = {
            "protocol_sha256": PROTOCOL_SHA256,
            "candidate_count": len(analysis["protocol"]["candidate_order"]),
            "variant_count": analysis["protocol"]["execution_plan"]["total_variant_count"],
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            output=args.output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
