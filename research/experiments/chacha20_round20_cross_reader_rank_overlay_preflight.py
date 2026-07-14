#!/usr/bin/env python3
"""Freeze geometry for the A265 selection-corrected reader overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.cross_reader_rank_ensemble import (  # noqa: E402
    build_rank_overlay_corpus,
    ternary_coefficient_modes,
)

ATTEMPT_ID = "A265"
SCHEMA = "chacha20-round20-cross-reader-rank-overlay-preflight-v1"
OUTPUT = (
    ROOT
    / "research/provenance/chacha20_round20_a265_cross_reader_rank_overlay_preflight_v1.json"
)
READER_RESULTS = {
    "A249_multichannel_linear": "research/results/v1/chacha20_round20_fresh_multichannel_reader_v1.json",
    "A250_nonlinear_poe": "research/results/v1/chacha20_round20_fresh_nonlinear_poe_v1.json",
    "A251_exact_clause_identity": "research/results/v1/chacha20_round20_fresh_clause_identity_reader_v1.json",
    "A259_public_cnf_topology": "research/results/v1/chacha20_round20_fresh_clause_topology_reader_v1.json",
    "A260_exact_operation_topology": "research/results/v1/chacha20_round20_fresh_clause_operation_reader_v1.json",
    "A261_directed_flow_tokens": "research/results/v1/chacha20_round20_fresh_clause_operation_flow_reader_v1.json",
    "A262_continuous_flow": "research/results/v1/chacha20_round20_fresh_clause_continuous_flow_reader_v1.json",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def build_preflight() -> dict[str, Any]:
    reader_rows = {}
    ledger = []
    for reader_id, relative in READER_RESULTS.items():
        path = ROOT / relative
        payload = json.loads(path.read_bytes())
        evaluation = payload.get("evaluation", {})
        rows = evaluation.get("outer_holdout_rows")
        if not isinstance(rows, list):
            raise RuntimeError(f"A265 reader lacks outer score rows: {reader_id}")
        reader_rows[reader_id] = rows
        score_matrix = np.asarray([row["scores"] for row in rows], dtype="<f8")
        if score_matrix.shape != (20, 256) or not np.isfinite(score_matrix).all():
            raise RuntimeError(f"A265 reader score geometry differs: {reader_id}")
        ledger.append(
            {
                "reader_id": reader_id,
                "attempt_id": payload.get("attempt_id"),
                "evidence_stage": payload.get("evidence_stage"),
                "path": relative,
                "result_sha256": _file_sha256(path),
                "score_matrix_float64le_sha256": _sha256(score_matrix.tobytes()),
                "mean_log2_rank": evaluation.get("mean_log2_rank"),
                "mean_log2_rank_bit_gain": evaluation.get(
                    "mean_log2_rank_bit_gain"
                ),
                "exact_shared_xor_p": evaluation.get("exact_shared_xor_p"),
            }
        )
    corpus = build_rank_overlay_corpus(reader_rows)
    modes = ternary_coefficient_modes(len(corpus.reader_ids))
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "reader_geometry_and_complete_mode_family_frozen_before_any_cross_reader_score_combination_or_mode_evaluation",
        "reader_ledger": ledger,
        "reader_ledger_sha256": _sha256(
            json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode()
        ),
        "geometry": {
            "reader_count": len(corpus.reader_ids),
            "reader_ids": list(corpus.reader_ids),
            "known_key_count": len(corpus.labels),
            "candidates_per_key": 256,
            "prefix_groups": sorted(set(int(value) for value in corpus.prefix_groups)),
            "keys_per_prefix_group": 4,
            "rank_scores_float32le_sha256": _sha256(
                corpus.rank_scores.astype("<f4").tobytes()
            ),
            "labels_sha256": _sha256("\n".join(corpus.labels).encode()),
            "true_prefixes_uint8_sha256": _sha256(corpus.true_prefixes.tobytes()),
        },
        "mode_family": {
            "coefficient_alphabet": [-1, 0, 1],
            "zero_vector_excluded": True,
            "complete_mode_count": len(modes),
            "expected_mode_count": 3 ** len(corpus.reader_ids) - 1,
            "mode_int8_sha256": _sha256(np.asarray(modes, dtype=np.int8).tobytes()),
            "same_complete_mode_search_required_for_all_256_shared_XOR_offsets": True,
        },
        "information_boundary": {
            "any_cross_reader_scores_combined": False,
            "any_ternary_mode_applied_or_evaluated": False,
            "any_selected_coefficients_known": False,
            "any_selection_corrected_XOR_curve_known": False,
            "individual_reader_results_already_known": True,
            "future_prospective_unknown_target_generated_or_opened": False,
        },
    }
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    payload = build_preflight()
    _atomic_json(OUTPUT, payload)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "sha256": _file_sha256(OUTPUT),
                "reader_count": payload["geometry"]["reader_count"],
                "mode_count": payload["mode_family"]["complete_mode_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
