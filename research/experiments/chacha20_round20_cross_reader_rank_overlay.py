#!/usr/bin/env python3
"""Execute the frozen A265 selection-corrected cross-reader rank overlay."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.cross_reader_rank_ensemble import (  # noqa: E402
    build_rank_overlay_corpus,
    selection_corrected_rank_overlay,
    ternary_coefficient_modes,
)

PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_cross_reader_rank_overlay_v1.json"
)
PROTOCOL_SHA256 = "58ba2d05b43363f272db06336b0d8e437c3e64fe4156e969a458616176cb17f7"
RESULT = (
    ROOT / "research/results/v1/chacha20_round20_cross_reader_rank_overlay_v1.json"
)
CAUSAL = (
    ROOT / "research/results/v1/chacha20_round20_cross_reader_rank_overlay_v1.causal"
)
REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_CROSS_READER_RANK_OVERLAY_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A265"
RESULT_SCHEMA = "chacha20-round20-cross-reader-rank-overlay-result-v1"


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


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], dict[str, Any]]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A265 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-cross-reader-rank-overlay-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_reader_geometry_and_complete_ternary_mode_family_preflight_before_any_cross_reader_score_combination_coefficient_selection_or_selection_corrected_curve_evaluation"
        or operator.get("coefficient_alphabet") != [-1, 0, 1]
        or operator.get("complete_mode_count") != 2186
        or operator.get("no_continuous_weight_optimization") is not True
        or boundary.get("any_cross_reader_scores_combined_before_protocol_freeze")
        is not False
        or boundary.get("any_ternary_mode_applied_or_evaluated_before_protocol_freeze")
        is not False
        or boundary.get("any_selected_coefficients_known_before_protocol_freeze")
        is not False
        or boundary.get("any_selection_corrected_XOR_curve_known_before_protocol_freeze")
        is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A265 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str):
            raise RuntimeError(f"A265 anchor lacks hash: {path_key}")
        if _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A265 anchored dependency hash differs: {path_key}")
    preflight = json.loads(_anchor_path(anchors["preflight_path"]).read_bytes())
    if (
        preflight.get("schema")
        != "chacha20-round20-cross-reader-rank-overlay-preflight-v1"
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight["geometry"]["reader_count"] != 7
        or preflight["geometry"]["known_key_count"] != 20
        or preflight["mode_family"]["complete_mode_count"] != 2186
        or preflight["information_boundary"]["any_cross_reader_scores_combined"]
        is not False
        or preflight["information_boundary"]["any_ternary_mode_applied_or_evaluated"]
        is not False
    ):
        raise RuntimeError("A265 preflight semantic gate failed")
    return protocol, preflight


def _load_corpus(
    protocol: Mapping[str, Any], preflight: Mapping[str, Any]
) -> tuple[Any, list[dict[str, Any]]]:
    reader_rows: dict[str, list[dict[str, Any]]] = {}
    source_ledger = []
    for row in preflight["reader_ledger"]:
        reader_id = str(row["reader_id"])
        path = _anchor_path(str(row["path"]))
        if _file_sha256(path) != row["result_sha256"]:
            raise RuntimeError(f"A265 source reader result hash differs: {reader_id}")
        payload = json.loads(path.read_bytes())
        rows = payload.get("evaluation", {}).get("outer_holdout_rows")
        if not isinstance(rows, list):
            raise RuntimeError(f"A265 source reader rows differ: {reader_id}")
        matrix = np.asarray([item["scores"] for item in rows], dtype="<f8")
        if _sha256(matrix.tobytes()) != row["score_matrix_float64le_sha256"]:
            raise RuntimeError(f"A265 source reader score matrix differs: {reader_id}")
        reader_rows[reader_id] = rows
        source_ledger.append(
            {
                "reader_id": reader_id,
                "attempt_id": payload["attempt_id"],
                "path": str(row["path"]),
                "result_sha256": row["result_sha256"],
                "source_mean_log2_rank_bit_gain": row[
                    "mean_log2_rank_bit_gain"
                ],
                "source_exact_shared_xor_p": row["exact_shared_xor_p"],
            }
        )
    corpus = build_rank_overlay_corpus(reader_rows)
    geometry = preflight["geometry"]
    modes = ternary_coefficient_modes(len(corpus.reader_ids))
    if (
        list(corpus.reader_ids) != protocol["input"]["required_reader_ids"]
        or len(corpus.labels) != protocol["input"]["required_known_key_count"]
        or _sha256(corpus.rank_scores.astype("<f4").tobytes())
        != geometry["rank_scores_float32le_sha256"]
        or _sha256("\n".join(corpus.labels).encode()) != geometry["labels_sha256"]
        or _sha256(corpus.true_prefixes.tobytes())
        != geometry["true_prefixes_uint8_sha256"]
        or _sha256(np.asarray(modes, dtype=np.int8).tobytes())
        != protocol["operator"]["mode_int8_sha256"]
    ):
        raise RuntimeError("A265 reconstructed overlay corpus differs")
    return corpus, source_ledger


def analyze() -> dict[str, Any]:
    protocol, preflight = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "reader_count": preflight["geometry"]["reader_count"],
        "known_key_count": preflight["geometry"]["known_key_count"],
        "complete_mode_count": protocol["operator"]["complete_mode_count"],
        "shared_xor_offsets": protocol["evaluation"]["shared_xor_offsets"],
        "new_solver_measurements_permitted": False,
        "cross_reader_score_combination_started": False,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A265 authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    retained = bool(payload["retention_gate"]["passed"])
    terminal = (
        "A265:selection_corrected_cross_reader_signal"
        if retained
        else "A265:selection_corrected_cross_reader_boundary"
    )
    writer = CausalWriter(api_id="a265")
    writer._rules = []
    writer.add_rule(
        name="reader_rank_normalization_removes_scale",
        description="Every reader contributes only centered within-cover candidate ranks, preventing arbitrary score magnitude from dominating the overlay.",
        pattern=["seven_out_of_fold_reader_scores", "within_row_midranks"],
        conclusion="scale_free_reader_rank_tensor",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_null_search_pays_for_overlay_selection",
        description="The complete signed reader-mode search is repeated under every shared-XOR offset before the observed selected statistic is assigned an exact p-value.",
        pattern=["complete_ternary_mode_family", "all_shared_XOR_offsets"],
        conclusion="selection_corrected_overlay_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A249+A250+A251+A259+A260+A261+A262:out_of_fold_rank_evidence",
        mechanism="center_each_complete_cover_by_descending_candidate_midranks",
        outcome="A265:seven_reader_scale_free_rank_tensor",
        confidence=1.0,
        source=payload["source_reader_ledger_sha256"],
        quantification="7 readers; 20 keys; 256 candidates per reader-key row",
        evidence=json.dumps(payload["source_reader_ledger"], sort_keys=True),
        domain="full-round ChaCha20-R20 reader overlay",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A265:seven_reader_scale_free_rank_tensor",
        mechanism="search_complete_nonzero_signed_ternary_reader_family",
        outcome="A265:observed_best_signed_rank_overlay",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="2186 coefficient modes",
        evidence=json.dumps(
            {
                "selected_coefficients": payload["evaluation"][
                    "selected_coefficients"
                ],
                "mean_log2_rank": payload["evaluation"]["mean_log2_rank"],
                "bit_gain": payload["evaluation"][
                    "mean_log2_rank_bit_gain"
                ],
            },
            sort_keys=True,
        ),
        domain="signed cross-reader inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A265:observed_best_signed_rank_overlay",
        mechanism="repeat_complete_mode_search_for_all_256_shared_XOR_offsets",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(
            {
                "selection_corrected_exact_shared_xor_p": payload["evaluation"][
                    "selection_corrected_exact_shared_xor_p"
                ],
                "positive_outer_prefix_folds": payload["evaluation"][
                    "outer_prefix_folds_with_positive_bit_gain"
                ],
                "selection_corrected_best_xor_offset": payload["evaluation"][
                    "selection_corrected_best_xor_offset"
                ],
            },
            sort_keys=True,
        ),
        domain="exact selection-corrected XOR control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A249+A250+A251+A259+A260+A261+A262:out_of_fold_rank_evidence",
        mechanism="materialized_scale_free_signed_overlay_and_complete_selection_null",
        outcome=terminal,
        confidence=1.0,
        source="materialized:seven_reader_rank_overlay_plus_selection_corrected_XOR_null",
        quantification="complete three-edge closure retained in-file",
        evidence="Materialized after all 2186 modes and all 256 selection-matched offsets were evaluated.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A265 selection-corrected cross-reader overlay",
        entities=[
            "A249+A250+A251+A259+A260+A261+A262:out_of_fold_rank_evidence",
            "center_each_complete_cover_by_descending_candidate_midranks",
            "A265:seven_reader_scale_free_rank_tensor",
            "search_complete_nonzero_signed_ternary_reader_family",
            "A265:observed_best_signed_rank_overlay",
            "repeat_complete_mode_search_for_all_256_shared_XOR_offsets",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_known_key_validation_of_frozen_signed_overlay"
            if retained
            else "exact_clause_continuous_frequency_or_solver_native_trajectory_delta_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the selected coefficients before generating disjoint key-prefix groups.",
                "Does the selected rank overlay preserve gain on entirely new keys?",
            ]
            if retained
            else [
                "Which exact clause-frequency coordinates were destroyed by all semantic projections?",
                "Do candidate-conditioned solver trajectory deltas align across unseen prefix groups?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a265"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A265 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "amplified_state_materialized_in_file": True,
        "inference_recomputed_on_reader_open": False,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    evaluation = payload["evaluation"]
    causal = payload["causal"]
    selected = ", ".join(
        f"{row['reader_id']}:{row['coefficient']:+d}"
        for row in evaluation["selected_readers"]
    )
    lines = [
        "# A265 — ChaCha20-R20 selection-corrected cross-reader rank overlay",
        "",
        "A265 overlays seven distinct out-of-fold full-round readers after removing their score scales, searches every nonzero signed ternary coefficient vector, and charges the exact shared-XOR control for that complete selection.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Selected signed readers: **{selected}**",
        f"- Mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Bit gain: **{evaluation['mean_log2_rank_bit_gain']:+.12f}**",
        f"- Positive outer folds: **{evaluation['outer_prefix_folds_with_positive_bit_gain']}/5**",
        f"- Selection-corrected exact shared-XOR p: **{evaluation['selection_corrected_exact_shared_xor_p']:.12f}**",
        f"- Frozen gate passed: **{payload['retention_gate']['passed']}**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
        f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
        f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
    ]
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, preflight = _load_protocol()
    started = time.perf_counter()
    corpus, source_ledger = _load_corpus(protocol, preflight)
    evaluation = selection_corrected_rank_overlay(corpus)
    gate = protocol["retention_gate"]
    retained = (
        evaluation["selection_corrected_exact_shared_xor_p"]
        <= gate["maximum_selection_corrected_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["outer_prefix_folds_with_positive_bit_gain"]
        >= gate["minimum_outer_prefix_folds_with_positive_bit_gain"]
    )
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_SELECTION_CORRECTED_CROSS_READER_SIGNAL"
            if retained
            else "FULLROUND_R20_SELECTION_CORRECTED_CROSS_READER_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "source_reader_ledger": source_ledger,
        "source_reader_ledger_sha256": _canonical_sha256(source_ledger),
        "operator": protocol["operator"],
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "new_solver_measurements": 0,
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(CAUSAL, payload, dotcausal_src)
    _atomic_json(RESULT, payload)
    _atomic_bytes(REPORT, _report(payload).encode())
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                "selected_coefficients": evaluation["selected_coefficients"],
                "mean_log2_rank": evaluation["mean_log2_rank"],
                "bit_gain": evaluation["mean_log2_rank_bit_gain"],
                "selection_corrected_exact_shared_xor_p": evaluation[
                    "selection_corrected_exact_shared_xor_p"
                ],
                "positive_prefix_folds": evaluation[
                    "outer_prefix_folds_with_positive_bit_gain"
                ],
                "new_solver_measurements": 0,
                "result": str(RESULT),
                "causal": str(CAUSAL),
                "report": str(REPORT),
            },
            indent=2,
        ),
        flush=True,
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args()
    if args.run:
        execute(dotcausal_src=args.dotcausal_src)
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
