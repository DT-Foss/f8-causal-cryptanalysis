#!/usr/bin/env python3
"""Prospective public holdout for ChaCha column/diagonal operator conjugacy."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A199 = _import_sibling(
    "chacha20_formula_operator_atlas.py",
    "chacha20_phase_conjugacy_a199_anchor",
)

ATTEMPT_ID = "A201"
SCHEMA = "chacha20-phase-conjugacy-holdout-v1"
PROTOCOL_SCHEMA = "chacha20-phase-conjugacy-holdout-protocol-v1"
PROTOCOL_FILENAME = "chacha20_phase_conjugacy_holdout_v1.json"
PROTOCOL_SHA256 = "6a07e560faeb35883ce56d6f98f697c25d16c600e6a5eeb8d642d3f1e95212b1"
A199_FILENAME = _A199.RESULT_FILENAME
A199_SHA256 = "16c1025308bae64e2c45339804ec0a39d5fcb927c1cd0a1dcbf2ca8dfd3d5c48"
A199_CAUSAL_FILENAME = _A199.CAUSAL_FILENAME
A199_CAUSAL_SHA256 = "bb509b61239bf3bc4396bac2b882820204deba6683186f9f5a89f65c1968fc89"
BATCH_COUNT = 8
SAMPLES_PER_BATCH = 16
ROUNDS = 20
PERMUTATION = np.array(
    [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14],
    dtype=np.int64,
)
RESULT_FILENAME = "chacha20_phase_conjugacy_holdout_v1.json"
CAUSAL_FILENAME = "chacha20_phase_conjugacy_holdout_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _A199._canonical_sha256(value)


def _load_protocol(results_dir: Path) -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A201 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A199_discovery_conjugacy_audit_before_any_A201_holdout_measurement"
        or protocol.get("holdout_plan", {}).get("batch_count") != BATCH_COUNT
        or protocol.get("holdout_plan", {}).get("sample_count_per_batch") != SAMPLES_PER_BATCH
        or protocol.get("holdout_plan", {}).get("word_permutation_new_position_gets_old_position")
        != PERMUTATION.tolist()
        or boundary.get("A201_holdout_measurements_used_before_protocol_freeze") is not False
        or boundary.get("hidden_cipher_assignment_used") is not False
        or boundary.get("permutation_fitted_to_holdout_data") is not False
        or boundary.get("seed_batch_or_threshold_changed_after_any_holdout_measurement")
        is not False
    ):
        raise RuntimeError("A201 frozen protocol identity gate failed")
    result_path = results_dir / A199_FILENAME
    causal_path = results_dir / A199_CAUSAL_FILENAME
    if _file_sha256(result_path) != A199_SHA256 or _file_sha256(causal_path) != A199_CAUSAL_SHA256:
        raise RuntimeError("A201 A199 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    if (
        result.get("evidence_stage") != "PUBLIC_FORMULA_OPERATOR_ATLAS_MIXED_BOUNDARY_RETAINED"
        or result.get("T01", {}).get("prediction_retained") is not True
        or reader.file_sha256 != A199_CAUSAL_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A201 A199 anchor content gate failed")
    return protocol


def _public_states(batch_index: int) -> tuple[str, np.ndarray]:
    label = f"f8-causal/A201/chacha20-phase-conjugacy-holdout/v1/batch/{batch_index}"
    raw = hashlib.shake_256(label.encode()).digest(SAMPLES_PER_BATCH * 12 * 4)
    words = np.frombuffer(raw, dtype="<u4").reshape(SAMPLES_PER_BATCH, 12).copy()
    states = np.empty((SAMPLES_PER_BATCH, 16), dtype=np.uint32)
    states[:, :4] = _A199.CONSTANTS
    states[:, 4:] = words
    return label, states


def _commutator(left: np.ndarray, right: np.ndarray, label: str) -> float:
    forward = _A199._finite_matmul(left, right, f"{label}-left-right")
    backward = _A199._finite_matmul(right, left, f"{label}-right-left")
    return _A199._relative_frobenius(forward, backward)


def _batch_metrics(batch_index: int) -> dict[str, Any]:
    label, states = _public_states(batch_index)
    cuts = _A199._base_cuts(states)
    inverse_gate = _A199._inverse_gates(states, cuts)
    operators, _, operator_gate = _A199._local_operators(cuts)
    permutation = np.zeros((16, 16), dtype=np.float64)
    permutation[np.arange(16), PERMUTATION] = 1.0

    correctly_aligned = operators.copy()
    wrongly_aligned = operators.copy()
    for round_index in range(1, ROUNDS, 2):
        correctly_aligned[round_index] = _A199._finite_matmul(
            _A199._finite_matmul(
                permutation,
                operators[round_index],
                f"batch-{batch_index}-correct-left-{round_index}",
            ),
            permutation.T,
            f"batch-{batch_index}-correct-right-{round_index}",
        )
        wrongly_aligned[round_index] = _A199._finite_matmul(
            _A199._finite_matmul(
                permutation.T,
                operators[round_index],
                f"batch-{batch_index}-wrong-left-{round_index}",
            ),
            permutation,
            f"batch-{batch_index}-wrong-right-{round_index}",
        )

    raw_adjacent = [
        _commutator(operators[index + 1], operators[index], f"raw-{batch_index}-{index}")
        for index in range(ROUNDS - 1)
    ]
    aligned_adjacent = [
        _commutator(
            correctly_aligned[index + 1],
            correctly_aligned[index],
            f"aligned-{batch_index}-{index}",
        )
        for index in range(ROUNDS - 1)
    ]
    wrong_adjacent = [
        _commutator(
            wrongly_aligned[index + 1],
            wrongly_aligned[index],
            f"wrong-{batch_index}-{index}",
        )
        for index in range(ROUNDS - 1)
    ]
    same_phase_lag2 = [
        _commutator(operators[index + 2], operators[index], f"lag2-{batch_index}-{index}")
        for index in range(ROUNDS - 2)
    ]
    column_mean = operators[0::2].mean(axis=0)
    aligned_diagonal_mean = correctly_aligned[1::2].mean(axis=0)
    raw_mean = float(np.mean(raw_adjacent))
    aligned_mean = float(np.mean(aligned_adjacent))
    lag2_mean = float(np.mean(same_phase_lag2))
    wrong_mean = float(np.mean(wrong_adjacent))
    mean_operator_distance = _A199._relative_frobenius(column_mean, aligned_diagonal_mean)
    predictions = {
        "H1_layout_dominance": raw_mean / aligned_mean > 20.0,
        "H2_same_phase_scale": 0.5 * lag2_mean <= aligned_mean <= 2.0 * lag2_mean,
        "H3_operator_alignment": mean_operator_distance < 0.02,
        "H4_wrong_direction_control": wrong_mean > 0.10,
        "H5_residual_channel": aligned_mean > 0.003,
    }
    return {
        "batch_index": batch_index,
        "seed_label": label,
        "public_states_sha256": _sha256(states.astype("<u4").tobytes()),
        "inverse_roundtrip_exact": inverse_gate["all_exact"],
        "operator_forward_sha256": operator_gate["forward_matrix_sha256"],
        "raw_adjacent_commutator_mean": round(raw_mean, 12),
        "correctly_aligned_adjacent_commutator_mean": round(aligned_mean, 12),
        "same_phase_lag2_commutator_mean": round(lag2_mean, 12),
        "wrongly_aligned_adjacent_commutator_mean": round(wrong_mean, 12),
        "raw_to_correctly_aligned_ratio": round(raw_mean / aligned_mean, 12),
        "aligned_to_lag2_ratio": round(aligned_mean / lag2_mean, 12),
        "aligned_column_diagonal_mean_operator_distance": round(mean_operator_distance, 12),
        "predictions": predictions,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_phase_conjugacy_holdout",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "batches": BATCH_COUNT,
            "samples_per_batch": SAMPLES_PER_BATCH,
            "rounds": ROUNDS,
        },
    )
    ids = [
        "chacha20-a201-a199-order-anchor",
        "chacha20-a201-public-layout-conjugacy",
        "chacha20-a201-eight-holdout-batches",
        "chacha20-a201-correct-wrong-conjugation-controls",
        "chacha20-a201-phase-mechanism-attribution",
    ]
    rows = [
        (
            "A199:raw_adjacent_commutator_factor40_over_lag2",
            "separate_schedule_layout_from_data_dependent_residual",
            "A201:public_phase_conjugacy_question",
            "retained_public_operator_discovery",
            A199_CAUSAL_SHA256,
            [],
            {"discovery": payload["discovery_observation"]},
        ),
        (
            "A201:public_phase_conjugacy_question",
            "derive_the_exact_ChaCha_row_rotation_permutation_from_the_round_schedule",
            "A201:frozen_correct_and_wrong_conjugations",
            "public_schedule_conjugacy_construction",
            payload["protocol_gate"]["artifact_sha256"],
            [ids[0]],
            {"permutation": PERMUTATION.tolist()},
        ),
        (
            "A201:frozen_correct_and_wrong_conjugations",
            "build_twenty_operators_on_each_of_eight_unseen_SHAKE256_batches",
            "A201:complete_public_holdout_operator_set",
            "prospective_public_holdout_execution",
            payload["batch_sha256"],
            [ids[1]],
            {"batches": BATCH_COUNT, "samples_per_batch": SAMPLES_PER_BATCH},
        ),
        (
            "A201:complete_public_holdout_operator_set",
            "compare_raw_correct_wrong_and_same_phase_commutators",
            "A201:controlled_phase_conjugacy_metrics",
            "correct_wrong_conjugation_control",
            payload["summary_sha256"],
            [ids[2]],
            {"summary": payload["summary"]},
        ),
        (
            "A201:controlled_phase_conjugacy_metrics",
            "apply_all_five_frozen_rules_in_every_holdout_batch",
            "A201:phase_mechanism_attribution",
            "prospective_layout_and_residual_attribution",
            payload["prediction_sha256"],
            [ids[3]],
            {"predictions": payload["predictions"]},
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
        raise RuntimeError("A201 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    protocol = _load_protocol(results_dir)
    batches = [_batch_metrics(index) for index in range(BATCH_COUNT)]
    prediction_names = list(protocol["prospective_predictions"])
    predictions = {
        name: {
            "retained_in_every_batch": all(batch["predictions"][name] for batch in batches),
            "retained_batch_count": sum(batch["predictions"][name] for batch in batches),
            "batch_count": BATCH_COUNT,
        }
        for name in prediction_names
    }
    all_retained = all(row["retained_in_every_batch"] for row in predictions.values())
    summary = {
        "raw_adjacent_mean_range": [
            min(batch["raw_adjacent_commutator_mean"] for batch in batches),
            max(batch["raw_adjacent_commutator_mean"] for batch in batches),
        ],
        "correctly_aligned_adjacent_mean_range": [
            min(batch["correctly_aligned_adjacent_commutator_mean"] for batch in batches),
            max(batch["correctly_aligned_adjacent_commutator_mean"] for batch in batches),
        ],
        "raw_to_aligned_ratio_range": [
            min(batch["raw_to_correctly_aligned_ratio"] for batch in batches),
            max(batch["raw_to_correctly_aligned_ratio"] for batch in batches),
        ],
        "aligned_to_lag2_ratio_range": [
            min(batch["aligned_to_lag2_ratio"] for batch in batches),
            max(batch["aligned_to_lag2_ratio"] for batch in batches),
        ],
        "aligned_mean_operator_distance_range": [
            min(batch["aligned_column_diagonal_mean_operator_distance"] for batch in batches),
            max(batch["aligned_column_diagonal_mean_operator_distance"] for batch in batches),
        ],
        "wrongly_aligned_adjacent_mean_range": [
            min(batch["wrongly_aligned_adjacent_commutator_mean"] for batch in batches),
            max(batch["wrongly_aligned_adjacent_commutator_mean"] for batch in batches),
        ],
    }
    evidence_stage = (
        "PUBLIC_CHACHA_PHASE_CONJUGACY_HOLDOUT_RETAINED"
        if all_retained
        else "PUBLIC_CHACHA_PHASE_CONJUGACY_MIXED_BOUNDARY_RETAINED"
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Eight unseen public batches separate ChaCha column/diagonal layout "
            "conjugacy from the residual state-dependent operator channel."
        ),
        "scope": "Public known-schedule mechanism attribution; no secret or solver is used.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor": {
            "A199_result_sha256": A199_SHA256,
            "A199_causal_sha256": A199_CAUSAL_SHA256,
        },
        "discovery_observation": protocol["discovery_observation"],
        "parameters": {
            "batch_count": BATCH_COUNT,
            "samples_per_batch": SAMPLES_PER_BATCH,
            "rounds": ROUNDS,
            "permutation": PERMUTATION.tolist(),
            "hidden_assignment_present": False,
        },
        "batches": batches,
        "batch_sha256": _canonical_sha256(batches),
        "summary": summary,
        "summary_sha256": _canonical_sha256(summary),
        "predictions": predictions,
        "prediction_sha256": _canonical_sha256(predictions),
        "all_predictions_retained_in_every_batch": all_retained,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A199._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A201 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "all_predictions_retained_in_every_batch": all_retained,
        "summary": summary,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    summary = run(
        results_dir=args.results_dir.resolve(),
        output=args.output.resolve(),
        causal_output=args.causal_output.resolve(),
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
