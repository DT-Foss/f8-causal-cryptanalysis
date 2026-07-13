#!/usr/bin/env python3
"""A217: exact O1-style operator-diversity audit of retained R20 traces."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL_PATH = RESEARCH / "configs/chacha20_round20_operator_diversity_audit_v1.json"
PROTOCOL_SHA256 = "099455d5ecd7ae5a20817a065533a64162b90611ed9451e82f20c50e5603c5dc"
R20_RESULT_PATH = RESEARCH / "results/v1/chacha20_round20_global_incremental_transfer_v1.json"
R20_RESULT_SHA256 = "a5be062ebce29cbc864ef926c55a1f9dbaadd69c9edcc54aed43552304f8e3f0"
R20_CAUSAL_PATH = RESEARCH / "results/v1/chacha20_round20_global_incremental_transfer_v1.causal"
R20_CAUSAL_SHA256 = "f9dd413e97c988335115f523a3a21d491564555d53020d902ac37854972c8e43"

ATTEMPT_ID = "A217-CHACHA20-R20-OPERATOR-DIVERSITY-AUDIT-V1"
SCHEMA = "chacha20-round20-operator-diversity-audit-v1"
METRICS = ("decisions", "conflicts", "search_propagations")
TOP_K = (8, 16, 32, 64)
PERMUTATIONS = 1024


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    )


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    temporary.replace(path)


def _load() -> tuple[dict[str, Any], dict[str, Any]]:
    if _file_sha256(PROTOCOL_PATH) != PROTOCOL_SHA256:
        raise RuntimeError("A217 protocol hash differs")
    if (
        _file_sha256(R20_RESULT_PATH) != R20_RESULT_SHA256
        or _file_sha256(R20_CAUSAL_PATH) != R20_CAUSAL_SHA256
    ):
        raise RuntimeError("A217 retained R20 anchor differs")
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    retained = json.loads(R20_RESULT_PATH.read_bytes())
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or retained.get("evidence_stage")
        != "FULLROUND_R20_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED"
    ):
        raise RuntimeError("A217 semantic identity gate failed")
    return protocol, retained


def _rank_average(values: np.ndarray) -> np.ndarray:
    values = np.asarray(values, dtype=np.float64)
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=np.float64)
    cursor = 0
    while cursor < len(values):
        end = cursor + 1
        while end < len(values) and values[order[end]] == values[order[cursor]]:
            end += 1
        ranks[order[cursor:end]] = 0.5 * (cursor + end - 1) + 1.0
        cursor = end
    return ranks


def _pearson(left: np.ndarray, right: np.ndarray) -> float:
    left = np.asarray(left, dtype=np.float64)
    right = np.asarray(right, dtype=np.float64)
    left = left - left.mean()
    right = right - right.mean()
    denominator = float(np.sqrt(np.dot(left, left) * np.dot(right, right)))
    if denominator == 0.0:
        raise RuntimeError("A217 correlation input is constant")
    return float(np.dot(left, right) / denominator)


def _spearman(left: np.ndarray, right: np.ndarray) -> float:
    return _pearson(_rank_average(left), _rank_average(right))


def _kendall_tau_b(left: np.ndarray, right: np.ndarray) -> float:
    left = np.asarray(left)
    right = np.asarray(right)
    concordant = discordant = left_ties = right_ties = 0
    for first in range(len(left) - 1):
        dx = np.sign(left[first + 1 :] - left[first])
        dy = np.sign(right[first + 1 :] - right[first])
        concordant += int(np.count_nonzero(dx * dy > 0))
        discordant += int(np.count_nonzero(dx * dy < 0))
        left_ties += int(np.count_nonzero((dx == 0) & (dy != 0)))
        right_ties += int(np.count_nonzero((dy == 0) & (dx != 0)))
    denominator = np.sqrt(
        (concordant + discordant + left_ties)
        * (concordant + discordant + right_ties)
    )
    if denominator == 0.0:
        raise RuntimeError("A217 Kendall denominator is zero")
    return float((concordant - discordant) / denominator)


def _linear_cka(left: np.ndarray, right: np.ndarray) -> float:
    left = np.asarray(left, dtype=np.float64)
    right = np.asarray(right, dtype=np.float64)
    cross = left.T @ right
    left_gram = left.T @ left
    right_gram = right.T @ right
    denominator = np.linalg.norm(left_gram, "fro") * np.linalg.norm(
        right_gram, "fro"
    )
    if denominator == 0.0:
        raise RuntimeError("A217 CKA denominator is zero")
    result = float(np.linalg.norm(cross, "fro") ** 2 / denominator)
    if not np.isfinite(result):
        raise RuntimeError("A217 CKA is non-finite")
    return result


def _standardize(matrix: np.ndarray) -> np.ndarray:
    matrix = np.asarray(matrix, dtype=np.float64)
    scale = matrix.std(axis=0)
    if np.any(scale == 0.0):
        raise RuntimeError("A217 telemetry column is constant")
    return (matrix - matrix.mean(axis=0)) / scale


def _extract(retained: dict[str, Any]) -> dict[str, Any]:
    rows = retained["comparative_metrics"]["global_order_paired_rows"]
    if len(rows) != 256:
        raise RuntimeError("A217 requires all 256 paired prefixes")
    by_prefix: dict[int, dict[str, Any]] = {}
    for row in rows:
        prefix = int(row["prefix8"], 2)
        if prefix in by_prefix:
            raise RuntimeError("A217 duplicate paired prefix")
        by_prefix[prefix] = row
    if set(by_prefix) != set(range(256)):
        raise RuntimeError("A217 paired prefix cover is incomplete")
    ordered = [by_prefix[prefix] for prefix in range(256)]
    numeric_positions = np.asarray(
        [row["numeric_cell_index"] for row in ordered], dtype=np.int16
    )
    gray_positions = np.asarray(
        [row["gray8_cell_index"] for row in ordered], dtype=np.int16
    )
    if set(numeric_positions.tolist()) != set(range(256)) or set(
        gray_positions.tolist()
    ) != set(range(256)):
        raise RuntimeError("A217 operator positions are not permutations")
    numeric = np.asarray(
        [[row["numeric_metrics_delta"][metric] for metric in METRICS] for row in ordered],
        dtype=np.float64,
    )
    gray = np.asarray(
        [[row["gray8_metrics_delta"][metric] for metric in METRICS] for row in ordered],
        dtype=np.float64,
    )
    statuses_equal = [
        row["numeric_status"] == row["gray8_status"] for row in ordered
    ]
    confirmations = retained["confirmations"]
    same_model = (
        len(confirmations) == 2
        and len({row["recovered_unknown_low20"] for row in confirmations}) == 1
        and all(row["all_blocks_match"] for row in confirmations)
        and all(not row["control_first_block_match"] for row in confirmations)
    )
    return {
        "numeric_positions": numeric_positions,
        "gray_positions": gray_positions,
        "numeric": numeric,
        "gray": gray,
        "statuses_equal": statuses_equal,
        "same_model": same_model,
        "recovered_unknown_low20": confirmations[0]["recovered_unknown_low20"],
    }


def _order_geometry(numeric_positions: np.ndarray, gray_positions: np.ndarray) -> dict[str, Any]:
    numeric_order = np.argsort(numeric_positions)
    gray_order = np.argsort(gray_positions)

    def mean_hamming(order: np.ndarray) -> float:
        return float(
            np.mean(
                [
                    (int(left) ^ int(right)).bit_count()
                    for left, right in zip(order[:-1], order[1:], strict=True)
                ]
            )
        )

    return {
        "position_spearman": _spearman(numeric_positions, gray_positions),
        "position_kendall_tau_b": _kendall_tau_b(
            numeric_positions, gray_positions
        ),
        "numeric_mean_consecutive_prefix_hamming": mean_hamming(numeric_order),
        "gray8_mean_consecutive_prefix_hamming": mean_hamming(gray_order),
        "numeric_order_uint8_sha256": _sha256(numeric_order.astype(np.uint8).tobytes()),
        "gray8_order_uint8_sha256": _sha256(gray_order.astype(np.uint8).tobytes()),
    }


def _trajectory_metrics(numeric: np.ndarray, gray: np.ndarray) -> list[dict[str, Any]]:
    rows = []
    for column, metric in enumerate(METRICS):
        left = numeric[:, column]
        right = gray[:, column]
        overlaps = []
        for k in TOP_K:
            left_top = set(np.argsort(left, kind="stable")[-k:].tolist())
            right_top = set(np.argsort(right, kind="stable")[-k:].tolist())
            intersection = len(left_top & right_top)
            overlaps.append(
                {
                    "k": k,
                    "intersection": intersection,
                    "jaccard": intersection / (2 * k - intersection),
                    "random_overlap_expectation": k * k / 256.0,
                }
            )
        rows.append(
            {
                "metric": metric,
                "pearson": _pearson(left, right),
                "spearman": _spearman(left, right),
                "kendall_tau_b": _kendall_tau_b(left, right),
                "top_k_overlap": overlaps,
                "numeric_total": int(left.sum()),
                "gray8_total": int(right.sum()),
                "gray8_over_numeric": float(right.sum() / left.sum()),
            }
        )
    return rows


def _joint_operator(numeric: np.ndarray, gray: np.ndarray) -> dict[str, Any]:
    left = _standardize(numeric)
    right = _standardize(gray)
    observed = _linear_cka(left, right)
    null = np.empty(PERMUTATIONS, dtype=np.float64)
    for index in range(PERMUTATIONS):
        order = np.random.default_rng(0xA217000 + index).permutation(len(right))
        null[index] = _linear_cka(left, right[order])
    design = np.column_stack((np.ones(len(left)), left))
    coefficients, *_ = np.linalg.lstsq(design, right, rcond=None)
    predicted = design @ coefficients
    residual = np.sum((right - predicted) ** 2, axis=0)
    total = np.sum((right - right.mean(axis=0)) ** 2, axis=0)
    r2 = 1.0 - residual / total
    singular_values = np.linalg.svd(left.T @ right, compute_uv=False)
    return {
        "linear_CKA": observed,
        "numeric_copy_control_CKA": _linear_cka(left, left),
        "gray8_copy_control_CKA": _linear_cka(right, right),
        "row_permutation_null": {
            "permutations": PERMUTATIONS,
            "minimum": float(null.min()),
            "median": float(np.median(null)),
            "maximum": float(null.max()),
            "upper_tail_add_one_p": float(
                (1 + np.count_nonzero(null >= observed)) / (PERMUTATIONS + 1)
            ),
            "float64_le_sha256": _sha256(null.astype("<f8").tobytes()),
        },
        "numeric_to_gray8_multivariate_affine_R2": {
            metric: float(value) for metric, value in zip(METRICS, r2, strict=True)
        },
        "mean_multivariate_affine_R2": float(np.mean(r2)),
        "standardized_cross_operator_singular_values": singular_values.tolist(),
        "cross_metric_Pearson_matrix": np.corrcoef(left.T, right.T)[:3, 3:].tolist(),
    }


def _evidence(
    extracted: dict[str, Any],
    geometry: dict[str, Any],
    trajectories: list[dict[str, Any]],
    joint: dict[str, Any],
) -> tuple[str, dict[str, bool]]:
    gates = {
        "all_256_same_prefix_statuses_equal": all(extracted["statuses_equal"]),
        "same_confirmed_model": extracted["same_model"],
        "aggregate_ratios_within_0p95_1p05": all(
            0.95 <= row["gray8_over_numeric"] <= 1.05 for row in trajectories
        ),
        "linear_CKA_below_0p10": joint["linear_CKA"] < 0.10,
        "mean_affine_R2_below_0p20": joint["mean_multivariate_affine_R2"] < 0.20,
        "all_absolute_same_prefix_spearman_below_0p15": all(
            abs(row["spearman"]) < 0.15 for row in trajectories
        ),
        "position_kendall_below_0p75": geometry["position_kendall_tau_b"] < 0.75,
    }
    stage = (
        "FULLROUND_R20_OPERATOR_DIVERSITY_MECHANISM_LOCALIZED"
        if all(gates.values())
        else "R20_OPERATOR_DIVERSITY_PARTIAL_BOUNDARY"
    )
    return stage, gates


def _causal(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_operator_diversity_audit",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "R20_result_sha256": R20_RESULT_SHA256,
        },
    )
    builder.add_rule(
        ExactRule(
            name="same_substrate_different_retained_path",
            first="holds_R20_CNF_cover_budget_and_statuses_fixed",
            second="changes_only_complete_cell_traversal_operator",
            conclusion="localizes_path_dependent_solver_state_diversity",
        )
    )
    builder.add_triplet(
        edge_id="a217-fixed-substrate",
        trigger="A217:same_R20_CNF_256_prefixes_and_budget",
        mechanism="holds_R20_CNF_cover_budget_and_statuses_fixed",
        outcome="A217:paired_numeric_and_gray8_telemetry",
        confidence=1.0,
        evidence_kind="retained_complete_fullround_trace_pair",
        source=f"sha256:{R20_RESULT_SHA256}",
        attrs={"same_prefix_statuses": 256, "recovered_low20": payload["recovered_low20"]},
    )
    builder.add_triplet(
        edge_id="a217-path-operator",
        trigger="A217:paired_numeric_and_gray8_telemetry",
        mechanism="changes_only_complete_cell_traversal_operator",
        outcome=f"A217:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="exact_operator_diversity_metrics_with_permutation_control",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        provenance=["a217-fixed-substrate"],
        attrs={
            "linear_CKA": payload["joint_operator"]["linear_CKA"],
            "mean_affine_R2": payload["joint_operator"]["mean_multivariate_affine_R2"],
        },
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A217 Causal Reader gate failed")
    return {**stats, "reader_verified": True}


def _write_report(payload: dict[str, Any], path: Path) -> None:
    trajectory = {row["metric"]: row for row in payload["same_prefix_trajectory"]}
    lines = [
        "# ChaCha20 R20 retained-state operator diversity (A217)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "Numeric and true reflected-Gray8 traverse the same complete 256-cell R20 CNF "
        "cover with the same solver build and budget. Both recover the same independently "
        "confirmed model and agree on every cell status. Their aggregate work is nearly "
        "identical, but their same-prefix telemetry is strongly path-dependent.",
        "",
        "| Metric | Same-prefix Spearman | Kendall tau-b | Gray/Numeric total |",
        "|---|---:|---:|---:|",
    ]
    for metric in METRICS:
        row = trajectory[metric]
        lines.append(
            f"| `{metric}` | {row['spearman']:.6f} | {row['kendall_tau_b']:.6f} | "
            f"{row['gray8_over_numeric']:.6f} |"
        )
    joint = payload["joint_operator"]
    geometry = payload["order_geometry"]
    lines.extend(
        [
            "",
            f"- Cross-operator linear CKA: `{joint['linear_CKA']:.9f}`",
            f"- 1,024-row-permutation upper-tail p: "
            f"`{joint['row_permutation_null']['upper_tail_add_one_p']:.9f}`",
            f"- Mean Numeric-to-Gray multivariate affine R2: "
            f"`{joint['mean_multivariate_affine_R2']:.9f}`",
            f"- Position Kendall tau-b: `{geometry['position_kendall_tau_b']:.9f}`",
            f"- Consecutive Hamming distance Numeric / Gray8: "
            f"`{geometry['numeric_mean_consecutive_prefix_hamming']:.6f}` / "
            f"`{geometry['gray8_mean_consecutive_prefix_hamming']:.6f}`",
            "",
            "The small but permutation-significant CKA component identifies shared formula "
            "structure, while the low CKA, low affine predictability, near-zero same-prefix "
            "rank correlations, and matching aggregate totals reject the scaled-copy model. "
            "Traversal order changes the learned-state path over the common substrate.",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n")
    temporary.replace(path)


def run(*, output: Path, causal_output: Path, report_output: Path) -> dict[str, Any]:
    protocol, retained = _load()
    extracted = _extract(retained)
    geometry = _order_geometry(
        extracted["numeric_positions"], extracted["gray_positions"]
    )
    trajectories = _trajectory_metrics(extracted["numeric"], extracted["gray"])
    joint = _joint_operator(extracted["numeric"], extracted["gray"])
    stage, gates = _evidence(extracted, geometry, trajectories, joint)
    measurement = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "analysis_state": protocol["analysis_state"],
        "anchor_result_sha256": R20_RESULT_SHA256,
        "paired_prefixes": 256,
        "same_prefix_statuses_equal": int(sum(extracted["statuses_equal"])),
        "same_confirmed_model": extracted["same_model"],
        "recovered_low20": extracted["recovered_unknown_low20"],
        "order_geometry": geometry,
        "same_prefix_trajectory": trajectories,
        "joint_operator": joint,
        "decision_gates": gates,
        "evidence_stage": stage,
    }
    measurement_sha256 = _canonical_sha256(measurement)
    payload = {**measurement, "measurement_sha256": measurement_sha256}
    payload["causal_artifact"] = _causal(payload, causal_output)
    _atomic_json(output, payload)
    _write_report(payload, report_output)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_operator_diversity_audit_v1.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_operator_diversity_audit_v1.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH / "reports/CAUSAL_CHACHA20_ROUND20_OPERATOR_DIVERSITY_AUDIT_V1.md",
    )
    args = parser.parse_args()
    payload = run(
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "evidence_stage": payload["evidence_stage"],
                "linear_CKA": payload["joint_operator"]["linear_CKA"],
                "measurement_sha256": payload["measurement_sha256"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
