#!/usr/bin/env python3
"""Derive and archive the exact Round-10 structural-order portfolio before A207."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse.csgraph import connected_components, laplacian
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


_A206 = _import_sibling(
    "chacha20_round10_bidirectional_min_distance.py",
    "chacha20_structural_archive_a206_anchor",
)
_A205 = _A206._A205
_A204 = _A206._A204

ATTEMPT_ID = "A207_PREFLIGHT"
SCHEMA = "chacha20-round10-structural-order-archive-v1"
ARCHIVE_FILENAME = "chacha20_round10_structural_orders_v1.npy"
METADATA_FILENAME = "chacha20_round10_structural_order_archive_v1.json"
CAUSAL_FILENAME = "chacha20_round10_structural_order_archive_v1.causal"

A206_FILENAME = _A206.RESULT_FILENAME
A206_SHA256 = "c2d4b703c463d5cdd2c95f22d9a5627c0cf0157e8929df5090ef2e9fe8e02c25"
A206_CAUSAL_FILENAME = _A206.CAUSAL_FILENAME
A206_CAUSAL_SHA256 = "15d06d3058e8843146366ae84056de66e4c724714e2166ef6ac2d5fdfd3b6046"
A206_CAUSAL_GRAPH_SHA256 = "5c4877af9b0c83fd63a7abb6619d76eb656e74ed29ec3aaf145bb9bb21316e1f"

CANDIDATE_ORDER = (
    "occurrence_degree_ascending",
    "adjacency_degree_ascending",
    "adjacency_degree_descending",
    "occurrence_span_ascending",
    "output_unit_bfs_near",
    "output_unit_bfs_far",
    "bidirectional_min_distance",
    "signed_key_minus_output_ascending",
    "signed_key_minus_output_descending",
    "output_layer_parity_interleave",
    "fiedler_ascending",
    "fiedler_center_out",
)
CALIBRATED_MODES = {
    "occurrence_degree_ascending": "reverse",
    "adjacency_degree_ascending": "reverse",
    "adjacency_degree_descending": "reverse",
    "occurrence_span_ascending": "reverse",
    "output_unit_bfs_near": "reverse",
    "output_unit_bfs_far": "reverse",
    "bidirectional_min_distance": "A206_default_and_reverse_complete",
    "signed_key_minus_output_ascending": "default",
    "signed_key_minus_output_descending": "reverse",
    "output_layer_parity_interleave": "reverse",
    "fiedler_ascending": "reverse",
    "fiedler_center_out": "reverse",
}
SPECTRAL_TOLERANCE = 1e-5
SPECTRAL_MAX_ITERATIONS = 10_000


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _load_a206_gate(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A206_FILENAME
    causal_path = results_dir / A206_CAUSAL_FILENAME
    if _file_sha256(result_path) != A206_SHA256 or _file_sha256(causal_path) != A206_CAUSAL_SHA256:
        raise RuntimeError("A207 preflight A206 anchor hash gate failed")
    payload = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    if (
        payload.get("evidence_stage")
        != "ROUND10_STRUCTURAL_ORDER_COMPLETE_TRANSFER_BOUNDARY_RETAINED"
        or payload.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 64, "invalid": 0}
        or payload.get("execution", {}).get("complete_cell_mode_plan_executed") is not True
        or reader.file_sha256 != A206_CAUSAL_SHA256
        or reader.graph_sha256 != A206_CAUSAL_GRAPH_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A207 preflight A206 content gate failed")
    return {
        "A206_result_sha256": A206_SHA256,
        "A206_causal_sha256": A206_CAUSAL_SHA256,
        "A206_causal_graph_sha256": A206_CAUSAL_GRAPH_SHA256,
        "A206_causal_provenance_verified": True,
        "A206_complete_64_unknown_boundary_retained": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    a206_analysis = _A206.analyze(results_dir)
    anchor = _load_a206_gate(results_dir)
    a205 = json.loads((results_dir / _A205.RESULT_FILENAME).read_bytes())
    if (
        tuple(a205.get("comparisons", {}).get("A206_transfer_selection", [])) != CANDIDATE_ORDER
        or a205.get("comparisons", {}).get("robust_both_mode_structural_candidates")
        != ["bidirectional_min_distance"]
        or tuple(CALIBRATED_MODES) != CANDIDATE_ORDER
        or a206_analysis["public_challenge"]["unknown_assignment_included"] is not False
    ):
        raise RuntimeError("A207 preflight retained portfolio or boundary gate failed")
    return {
        "a206_analysis": a206_analysis,
        "anchor_gates": {**a206_analysis["anchor_gates"], **anchor},
        "candidate_order": list(CANDIDATE_ORDER),
        "calibrated_modes": CALIBRATED_MODES,
        "solver_execution_started": False,
    }


def _derive_orders(
    parsed: dict[str, Any], free_mapping: Sequence[int]
) -> tuple[dict[str, np.ndarray], dict[str, Any], dict[str, Any]]:
    variable_count = parsed["variable_count"]
    ids = np.arange(1, variable_count + 1, dtype=np.int64)
    graph = parsed["graph"]
    key_sources = np.asarray(sorted(set(free_mapping)), dtype=np.int64)
    unit_distance = _A205._multi_source_bfs(graph, parsed["units"])
    key_distance = _A205._multi_source_bfs(graph, key_sources)
    distance_sum = unit_distance + key_distance
    signed_distance = key_distance - unit_distance

    candidates = {
        "occurrence_degree_ascending": ids[np.lexsort((ids, parsed["occurrence"]))],
        "adjacency_degree_ascending": ids[np.lexsort((ids, parsed["degrees"]))],
        "adjacency_degree_descending": ids[np.lexsort((ids, -parsed["degrees"]))],
        "occurrence_span_ascending": ids[np.lexsort((ids, parsed["span"]))],
        "output_unit_bfs_near": ids[np.lexsort((ids, unit_distance))],
        "output_unit_bfs_far": ids[np.lexsort((ids, -unit_distance))],
        "bidirectional_min_distance": ids[
            np.lexsort((ids, signed_distance, np.minimum(unit_distance, key_distance)))
        ],
        "signed_key_minus_output_ascending": ids[np.lexsort((ids, distance_sum, signed_distance))],
        "signed_key_minus_output_descending": ids[
            np.lexsort((ids, distance_sum, -signed_distance))
        ],
        "output_layer_parity_interleave": ids[np.lexsort((ids, unit_distance, unit_distance % 2))],
    }

    component_count, labels = connected_components(graph, directed=False)
    component_sizes = np.bincount(labels)
    main_component_label = int(np.argmax(component_sizes))
    main_zero_based = np.flatnonzero(labels == main_component_label)
    other_zero_based = np.flatnonzero(labels != main_component_label)
    main_ids = main_zero_based.astype(np.int64) + 1
    other_ids = np.sort(other_zero_based.astype(np.int64) + 1)
    subgraph = graph[main_zero_based][:, main_zero_based]
    normalized_laplacian = laplacian(subgraph.astype(np.float64), normed=True)
    old = main_ids.astype(np.float64)
    v0 = np.sin(old * math.sqrt(2.0)) + np.cos(old * math.sqrt(3.0))
    eigenvalues, eigenvectors = eigsh(
        normalized_laplacian,
        k=2,
        which="SM",
        tol=SPECTRAL_TOLERANCE,
        maxiter=SPECTRAL_MAX_ITERATIONS,
        v0=v0,
    )
    eigen_order = np.argsort(eigenvalues)
    eigenvalues = eigenvalues[eigen_order]
    fiedler = eigenvectors[:, eigen_order[1]]
    if float(np.dot(fiedler, v0)) < 0:
        fiedler = -fiedler
    candidates["fiedler_ascending"] = np.concatenate(
        (main_ids[np.lexsort((main_ids, fiedler))], other_ids)
    )
    candidates["fiedler_center_out"] = np.concatenate(
        (main_ids[np.lexsort((main_ids, fiedler, np.abs(fiedler)))], other_ids)
    )
    if tuple(candidates) != CANDIDATE_ORDER:
        raise RuntimeError("A207 preflight candidate order differs")
    for name, order in candidates.items():
        if len(order) != variable_count or not np.array_equal(np.sort(order), ids):
            raise RuntimeError(f"A207 preflight {name} is not a permutation")
    order_hashes = {
        name: _sha256(order.astype("<u4", copy=False).tobytes())
        for name, order in candidates.items()
    }
    if len(set(order_hashes.values())) != len(CANDIDATE_ORDER):
        raise RuntimeError("A207 preflight candidate orders are not pairwise distinct")
    graph_payload = {
        "variable_count": variable_count,
        "clause_count": parsed["clause_count"],
        "unit_clause_variable_count": len(parsed["units"]),
        "undirected_edges": int(graph.nnz // 2),
        "connected_components": parsed["component_count"],
        "largest_component": int(parsed["component_sizes"].max()),
        "isolated_vertices": int(np.sum(parsed["component_sizes"] == 1)),
        "minimum_degree": int(parsed["degrees"].min()),
        "maximum_degree": int(parsed["degrees"].max()),
        "key_distance_min": int(key_distance.min()),
        "key_distance_max": int(key_distance.max()),
        "unit_distance_min": int(unit_distance.min()),
        "unit_distance_max": int(unit_distance.max()),
        "csr_indptr_sha256": _sha256(graph.indptr.astype("<i8", copy=False).tobytes()),
        "csr_indices_sha256": _sha256(graph.indices.astype("<i4", copy=False).tobytes()),
    }
    spectral = {
        "method": "largest_connected_component_normalized_laplacian_then_append_other_components_by_old_id",
        "component_count": int(component_count),
        "component_sizes_descending": [
            int(value) for value in sorted(component_sizes, reverse=True)
        ],
        "main_component_label": main_component_label,
        "main_component_vertices": len(main_zero_based),
        "appended_vertex_ids": [int(value) for value in other_ids],
        "eigensolver": "scipy.sparse.linalg.eigsh",
        "k": 2,
        "which": "SM",
        "tolerance": SPECTRAL_TOLERANCE,
        "max_iterations": SPECTRAL_MAX_ITERATIONS,
        "deterministic_v0": "sin(old_variable_id*sqrt(2))+cos(old_variable_id*sqrt(3))",
        "sign_orientation": "dot_with_deterministic_v0_nonnegative",
        "eigenvalues": [float(value) for value in eigenvalues],
        "residual": float(
            np.linalg.norm(normalized_laplacian @ fiedler - eigenvalues[1] * fiedler)
        ),
        "orientation_dot": float(np.dot(fiedler, v0)),
    }
    return candidates, graph_payload, spectral


def _candidate_manifest(
    *,
    raw: bytes,
    candidates: dict[str, np.ndarray],
    free_mapping: Sequence[int],
) -> list[dict[str, Any]]:
    variable_count = len(next(iter(candidates.values())))
    old_ids = np.arange(1, variable_count + 1, dtype=np.int64)
    manifest = []
    for name in CANDIDATE_ORDER:
        order = candidates[name]
        mapping = _A205._old_to_new(order)
        inverse = np.zeros_like(mapping)
        inverse[mapping[1:]] = old_ids
        transformed = _A205._reindex_cnf(raw, mapping)
        restored = _A205._reindex_cnf(transformed, inverse)
        if restored != raw:
            raise RuntimeError(f"A207 preflight {name} inverse byte gate failed")
        transformed_free_mapping = [
            int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
            for literal in free_mapping
        ]
        manifest.append(
            {
                "candidate": name,
                "calibrated_solver_mode": CALIBRATED_MODES[name],
                "order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
                "old_to_new_sha256": _sha256(mapping.astype("<u4", copy=False).tobytes()),
                "representative_transformed_cnf_sha256": _sha256(transformed),
                "representative_transformed_cnf_bytes": len(transformed),
                "inverse_restored_sha256": _sha256(restored),
                "inverse_byte_identical": True,
                "transformed_free_k0_bit_one_literal_mapping": transformed_free_mapping,
                "transformed_free_mapping_sha256": _canonical_sha256(transformed_free_mapping),
            }
        )
    if len({row["representative_transformed_cnf_sha256"] for row in manifest}) != len(
        CANDIDATE_ORDER
    ):
        raise RuntimeError("A207 preflight representative transformed CNFs are not distinct")
    return manifest


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_structural_order_archive",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "candidate_count": len(CANDIDATE_ORDER),
            "variable_count": payload["graph"]["variable_count"],
            "new_candidate_mode_count": 11,
        },
    )
    ids = [
        "chacha20-a207-preflight-a205-portfolio",
        "chacha20-a207-preflight-a206-boundary",
        "chacha20-a207-preflight-structural-orders",
        "chacha20-a207-preflight-exact-archive",
    ]
    rows = [
        (
            "A205:12_confirmed_noncontrol_structural_candidates",
            "retain_each_candidate_and_its_confirmed_solver_mode",
            "A207:complete_calibrated_structural_portfolio",
            "retained_A205_portfolio",
            _A206.A205_CAUSAL_SHA256,
            [],
            {"calibrated_modes": payload["calibrated_modes"]},
        ),
        (
            "A207:complete_calibrated_structural_portfolio",
            "retain_the_complete_A206_both_mode_round10_boundary_without_reexecution",
            "A207:11_remaining_candidate_modes",
            "retained_A206_boundary",
            A206_CAUSAL_SHA256,
            [ids[0]],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A207:11_remaining_candidate_modes",
            "derive_degree_BFS_sum_difference_layer_and_component_aware_Fiedler_orders",
            "A207:12_pairwise_distinct_exact_round10_orders",
            "formula_derived_order_archive",
            payload["candidate_manifest_sha256"],
            [ids[1]],
            {
                "graph": payload["graph"],
                "spectral": payload["spectral"],
                "candidate_manifest": payload["candidate_manifest"],
            },
        ),
        (
            "A207:12_pairwise_distinct_exact_round10_orders",
            "store_one_deterministic_little_endian_int32_NPY_matrix_and_reopen_every_row",
            "A207:exact_reusable_structural_order_archive",
            "byte_exact_order_archive",
            payload["archive_sha256"],
            [ids[2]],
            {
                "archive": payload["archive"],
                "information_boundary": payload["information_boundary"],
            },
        ),
    ]
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
        raise RuntimeError("A207 preflight Causal Reader gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(
    *,
    results_dir: Path,
    archive_output: Path,
    metadata_output: Path,
    causal_output: Path,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    a206_analysis = analysis["a206_analysis"]
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    with tempfile.TemporaryDirectory(prefix="a207-order-archive-") as raw_directory:
        representative_path = Path(raw_directory) / "cse_prefix_11111.cnf"
        source_export = _A204._export_cnf(
            variant="cse_prefix_11111",
            formula=a206_analysis["formulas"]["cse_prefix_11111"],
            output=representative_path,
            bitwuzla_path=identities["bitwuzla"]["path"],
            limit_ms=_A204.CNF_EXPORT_LIMIT_MS,
        )
        expected_source = a206_analysis["a204_analysis"]["protocol"]["A202_round10_cnf_freeze"][
            "per_cell_manifest"
        ][-1]
        retained_source = {
            key: source_export[key]
            for key in (
                "variant",
                "prefix",
                "bytes",
                "sha256",
                "header",
                "normalized_sha256",
                "tail_units",
            )
        }
        if retained_source != expected_source:
            raise RuntimeError("A207 preflight representative source identity gate failed")
        raw = representative_path.read_bytes()
        parsed = _A205._parse_cnf(raw)
        free_mapping = a206_analysis["protocol"]["round10_source"][
            "free_k0_bit_one_literal_mapping"
        ]
        candidates, graph, spectral = _derive_orders(parsed, free_mapping)
        manifest = _candidate_manifest(
            raw=raw,
            candidates=candidates,
            free_mapping=free_mapping,
        )

    matrix = np.stack(
        [candidates[name].astype("<i4", copy=False) for name in CANDIDATE_ORDER], axis=0
    )
    archive_output.parent.mkdir(parents=True, exist_ok=True)
    archive_temp = archive_output.with_suffix(".npy.tmp")
    with archive_temp.open("wb") as stream:
        np.save(stream, matrix, allow_pickle=False)
    archive_temp.replace(archive_output)
    reopened = np.load(archive_output, mmap_mode="r", allow_pickle=False)
    if reopened.shape != matrix.shape or reopened.dtype != np.dtype("<i4"):
        raise RuntimeError("A207 preflight archived matrix shape or dtype differs")
    for index, row in enumerate(manifest):
        observed = _sha256(np.asarray(reopened[index], dtype="<u4").tobytes())
        if observed != row["order_sha256"]:
            raise RuntimeError(f"A207 preflight archived row {index} differs")
    archive = {
        "filename": ARCHIVE_FILENAME,
        "format": "NumPy_NPY_v1_little_endian_int32_C_order_no_pickle",
        "shape": list(reopened.shape),
        "dtype": str(reopened.dtype),
        "bytes": archive_output.stat().st_size,
        "row_candidate_order": list(CANDIDATE_ORDER),
        "sha256": _file_sha256(archive_output),
        "all_rows_reopened_and_hash_verified": True,
    }
    information_boundary = {
        "A205_and_A206_outcomes_known_before_archive_derivation": True,
        "any_A207_remaining_portfolio_solver_outcome_known_before_archive_derivation": False,
        "round10_unknown_assignment_in_source_or_archive": False,
        "round10_unknown_assignment_available_to_archive_runner": False,
        "bitwuzla_used_only_for_exact_CNF_export": True,
        "external_CaDiCaL_A207_execution_started": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ROUND10_STRUCTURAL_ORDER_ARCHIVE_RETAINED_BEFORE_A207_EXECUTION",
        "result": (
            "Twelve exact formula-derived Round-10 CNF orders are archived; A206 already "
            "covers the unique both-mode candidate and eleven calibrated modes remain for A207."
        ),
        "anchor_gates": analysis["anchor_gates"],
        "source_export": {key: value for key, value in source_export.items() if key != "path"},
        "source_export_sha256": _canonical_sha256(
            {key: value for key, value in source_export.items() if key != "path"}
        ),
        "graph": graph,
        "graph_sha256": _canonical_sha256(graph),
        "spectral": spectral,
        "spectral_sha256": _canonical_sha256(spectral),
        "calibrated_modes": CALIBRATED_MODES,
        "calibrated_modes_sha256": _canonical_sha256(CALIBRATED_MODES),
        "candidate_manifest": manifest,
        "candidate_manifest_sha256": _canonical_sha256(manifest),
        "archive": archive,
        "archive_sha256": archive["sha256"],
        "information_boundary": information_boundary,
        "information_boundary_sha256": _canonical_sha256(information_boundary),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw_metadata = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A204._A198._A185._atomic_write(metadata_output, raw_metadata)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(metadata_output) != _sha256(raw_metadata)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A207 preflight final artifact reopen gate failed")
    return {
        "archive_sha256": archive["sha256"],
        "metadata_sha256": _sha256(raw_metadata),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "candidate_count": len(CANDIDATE_ORDER),
        "new_candidate_mode_count": 11,
        "archive_output": str(archive_output),
        "metadata_output": str(metadata_output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    results_dir = research_root / "results" / "v1"
    parser.add_argument("--results-dir", type=Path, default=results_dir)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--archive-output", type=Path, default=results_dir / ARCHIVE_FILENAME)
    parser.add_argument("--metadata-output", type=Path, default=results_dir / METADATA_FILENAME)
    parser.add_argument("--causal-output", type=Path, default=results_dir / CAUSAL_FILENAME)
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        summary = {
            "candidate_order": analysis["candidate_order"],
            "candidate_count": len(analysis["candidate_order"]),
            "new_candidate_mode_count": 11,
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            archive_output=args.archive_output.resolve(),
            metadata_output=args.metadata_output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
