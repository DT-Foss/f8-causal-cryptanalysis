#!/usr/bin/env python3
"""A270: fixed hypercube-local intervention on the untouched A268 score fields."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.score_hypercube import (  # noqa: E402
    descending_midrank,
    local_pairwise_residual,
    mean_log2_rank,
    paired_margins,
)

ATTEMPT_ID = "A270"
SCHEMA = "chacha20-round20-local-pairwise-intervention-result-v1"
DEFAULT_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_local_pairwise_intervention_v1.json"
)
DEFAULT_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_local_pairwise_intervention_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_LOCAL_PAIRWISE_INTERVENTION_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


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
    ).encode("ascii")


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
        ).encode("ascii")
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A270 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    gate = protocol.get("retention_gate", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-local-pairwise-intervention-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A268_boundary_before_any_local_pairwise_residual_rank_margin_or_XOR_control"
        or operator.get("name") != "normalized_8cube_graph_laplacian"
        or operator.get("formula") != "local_score[c]=raw_score[c]-mean_b(raw_score[c_xor_2^b])"
        or operator.get("candidate_bits") != 8
        or operator.get("fitted_parameters") != 0
        or operator.get("sign_or_scale_selection_permitted") is not False
        or gate.get("maximum_exact_shared_xor_p") != 0.05
        or gate.get("minimum_positive_prefix_groups") != 3
        or boundary.get("A268_result_known_at_freeze") is not True
        or boundary.get("local_pairwise_residual_computed_at_freeze") is not False
        or boundary.get("operator_selected_from_A268_local_outcome") is not False
        or boundary.get("model_refit_or_coefficient_update_permitted") is not False
    ):
        raise RuntimeError("A270 frozen protocol semantic gate failed")
    for path_key, path_value in protocol["anchors"].items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != protocol["anchors"][hash_key]:
            raise RuntimeError(f"A270 anchored dependency hash differs: {path_key}")
    a268 = json.loads(_anchor_path(protocol["anchors"]["A268_result_path"]).read_bytes())
    if (
        a268.get("attempt_id") != "A268"
        or a268.get("evidence_stage")
        != "FULLROUND_R20_PROSPECTIVE_TRAJECTORY_SHAPE_BOUNDARY"
        or a268.get("retention_gate", {}).get("passed") is not False
        or len(a268.get("evaluation", {}).get("prospective_rows", [])) != 20
        or a268.get("finalization_correction", {}).get(
            "solver_shards_recomputed_for_correction"
        )
        is not False
    ):
        raise RuntimeError("A270 A268 boundary prerequisite differs")
    return protocol, a268


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    protocol, a268 = _load_protocol(protocol_path, expected_protocol_sha256)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "input_score_fields": len(a268["evaluation"]["prospective_rows"]),
        "operator": protocol["operator"],
        "local_residual_computed": False,
    }


def _evaluate(a268: Mapping[str, Any]) -> dict[str, Any]:
    input_rows = a268["evaluation"]["prospective_rows"]
    rows: list[dict[str, Any]] = []
    for row in input_rows:
        raw = np.asarray(row["scores"], dtype=np.float64)
        true_prefix = int(row["true_prefix"])
        local = local_pairwise_residual(raw)
        margins = paired_margins(raw, true_prefix)
        rows.append(
            {
                "label": row["label"],
                "prefix_index": int(row["prefix_index"]),
                "true_prefix": true_prefix,
                "raw_midrank": float(row["midrank"]),
                "local_midrank": descending_midrank(local, true_prefix),
                "true_local_score": float(local[true_prefix]),
                "true_neighbor_margins": margins.tolist(),
                "true_neighbor_wins": int(np.count_nonzero(margins > 0.0)),
                "true_neighbor_ties": int(np.count_nonzero(margins == 0.0)),
                "true_mean_neighbor_margin": float(margins.mean()),
                "local_scores": local.tolist(),
            }
        )
    if len(rows) != 20 or sorted({row["prefix_index"] for row in rows}) != list(range(5)):
        raise RuntimeError("A270 input row geometry differs")

    observed = mean_log2_rank([row["local_midrank"] for row in rows])
    observed_margin = float(
        np.mean([margin for row in rows for margin in row["true_neighbor_margins"]])
    )
    shifted_ranks: list[float] = []
    shifted_margins: list[float] = []
    for offset in range(256):
        ranks = []
        margins = []
        for row in rows:
            pseudo = int(row["true_prefix"]) ^ offset
            local = np.asarray(row["local_scores"], dtype=np.float64)
            raw = np.asarray(
                next(item["scores"] for item in input_rows if item["label"] == row["label"]),
                dtype=np.float64,
            )
            ranks.append(descending_midrank(local, pseudo))
            margins.extend(paired_margins(raw, pseudo).tolist())
        shifted_ranks.append(mean_log2_rank(ranks))
        shifted_margins.append(float(np.mean(margins)))

    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    groups = []
    for prefix_index in range(5):
        group = [row for row in rows if row["prefix_index"] == prefix_index]
        group_mean = mean_log2_rank([row["local_midrank"] for row in group])
        groups.append(
            {
                "prefix_index": prefix_index,
                "true_prefix": group[0]["true_prefix"],
                "local_ranks": [row["local_midrank"] for row in group],
                "mean_log2_rank": group_mean,
                "bit_gain": uniform - group_mean,
            }
        )
    return {
        "rows": rows,
        "prefix_groups": groups,
        "raw_A268_mean_log2_rank": a268["evaluation"]["mean_log2_rank"],
        "raw_A268_bit_gain": a268["evaluation"]["mean_log2_rank_bit_gain"],
        "raw_A268_exact_shared_xor_p": a268["evaluation"]["exact_shared_xor_p"],
        "local_mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "local_mean_log2_rank_bit_gain": uniform - observed,
        "local_minus_raw_bit_gain": (
            uniform - observed - a268["evaluation"]["mean_log2_rank_bit_gain"]
        ),
        "positive_prefix_groups": sum(group["bit_gain"] > 0.0 for group in groups),
        "shared_xor_offset_local_mean_log2_ranks": shifted_ranks,
        "exact_shared_xor_rank_p": sum(
            value <= observed + 1e-15 for value in shifted_ranks
        )
        / 256.0,
        "best_shared_xor_rank_offset": min(
            range(256), key=shifted_ranks.__getitem__
        ),
        "observed_mean_pairwise_margin": observed_margin,
        "shared_xor_offset_mean_pairwise_margins": shifted_margins,
        "exact_shared_xor_pairwise_margin_p": sum(
            value >= observed_margin - 1e-15 for value in shifted_margins
        )
        / 256.0,
        "best_shared_xor_pairwise_margin_offset": max(
            range(256), key=shifted_margins.__getitem__
        ),
        "observed_offset": 0,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(io_module.CausalReader) or "")
    return io_module.CausalWriter, io_module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    retained = bool(payload["retention_gate"]["passed"])
    terminal = (
        "A270:local_pairwise_transfer_signal"
        if retained
        else "A270:local_pairwise_intervention_boundary"
    )
    writer = CausalWriter(api_id="a270")
    writer._rules = []
    writer.add_rule(
        name="fixed_local_intervention_after_transfer_boundary",
        description="A single parameter-free 8-cube Laplacian is frozen after A268 and applied to all twenty untouched score fields without refit or operator selection.",
        pattern=["A268_transfer_boundary", "fixed_8cube_laplacian"],
        conclusion="local_pairwise_intervention_evidence",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="shared_xor_controls_local_geometry",
        description="All 256 shared XOR offsets preserve each score field and its exact neighbor graph while moving only the candidate label.",
        pattern=["complete_local_score_fields", "all_shared_XOR_offsets"],
        conclusion="selection_free_local_rank_control",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A268:prospective_trajectory_shape_transfer_boundary",
        mechanism="freeze_parameter_free_normalized_8cube_graph_laplacian",
        outcome="A270:twenty_local_pairwise_score_fields",
        confidence=1.0,
        source=payload["operator_source_sha256"],
        quantification="20 fields x 256 candidates x 8 exact Hamming-one pairs",
        evidence=json.dumps(payload["operator"], sort_keys=True),
        domain="full-round R20 candidate-score geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A270:twenty_local_pairwise_score_fields",
        mechanism="all_256_shared_XOR_rank_and_pairwise_margin_controls",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="exact local intervention control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A268:prospective_trajectory_shape_transfer_boundary",
        mechanism="materialized_fixed_local_intervention_and_exact_control_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A268_scores_plus_fixed_8cube_laplacian_plus_XOR_controls",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the fixed local transform and all 256 shared-XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A270 local pairwise intervention",
        entities=[
            "A268:prospective_trajectory_shape_transfer_boundary",
            "freeze_parameter_free_normalized_8cube_graph_laplacian",
            "A270:twenty_local_pairwise_score_fields",
            "all_256_shared_XOR_rank_and_pairwise_margin_controls",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_local_pairwise_validation"
            if retained
            else "channel_signed_pairwise_ablation_without_model_refit"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the same local operator before another disjoint known-key panel.",
                "Does local residual rank transfer without changing the A267 model?",
            ]
            if retained
            else [
                "Which individual event-shape channels create transferable pair margins?",
                "Do sign-separated channel residuals cancel in the aggregate logit?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a270"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A270 authentic Causal Reader reopen gate failed")
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
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    h = payload["headline"]
    causal = payload["causal"]
    return "\n".join(
        [
            "# A270 — ChaCha20-R20 local pairwise intervention",
            "",
            "The fixed normalized 8-cube Laplacian subtracts each candidate's eight Hamming-one neighbor mean from its frozen A268 logit. It has no fitted parameters and was frozen before any local residual outcome existed.",
            "",
            "## Result",
            "",
            f"- Evidence stage: **{payload['evidence_stage']}**",
            f"- Raw / local bit gain: **{h['raw_bit_gain']:+.12f} / {h['local_bit_gain']:+.12f}**",
            f"- Local minus raw gain: **{h['local_minus_raw_bit_gain']:+.12f}**",
            f"- Exact local-rank XOR p: **{h['exact_shared_xor_rank_p']:.12f}**",
            f"- Exact pairwise-margin XOR p: **{h['exact_shared_xor_pairwise_margin_p']:.12f}**",
            f"- Positive prefix groups: **{h['positive_prefix_groups']}/5**",
            f"- Frozen gate passed: **{payload['retention_gate']['passed']}**",
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    protocol, a268 = _load_protocol(protocol_path, expected_protocol_sha256)
    evaluation = _evaluate(a268)
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_rank_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["local_mean_log2_rank_bit_gain"]
        > evaluation["raw_A268_bit_gain"]
        and evaluation["positive_prefix_groups"]
        >= gate["minimum_positive_prefix_groups"]
    )
    headline = {
        "raw_bit_gain": evaluation["raw_A268_bit_gain"],
        "local_bit_gain": evaluation["local_mean_log2_rank_bit_gain"],
        "local_minus_raw_bit_gain": evaluation["local_minus_raw_bit_gain"],
        "exact_shared_xor_rank_p": evaluation["exact_shared_xor_rank_p"],
        "exact_shared_xor_pairwise_margin_p": evaluation[
            "exact_shared_xor_pairwise_margin_p"
        ],
        "positive_prefix_groups": evaluation["positive_prefix_groups"],
        "best_shared_xor_rank_offset": evaluation["best_shared_xor_rank_offset"],
        "best_shared_xor_pairwise_margin_offset": evaluation[
            "best_shared_xor_pairwise_margin_offset"
        ],
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_LOCAL_PAIRWISE_INTERVENTION_SIGNAL"
            if retained
            else "FULLROUND_R20_LOCAL_PAIRWISE_INTERVENTION_BOUNDARY"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "operator_source_sha256": protocol["anchors"]["operator_source_sha256"],
        "operator": protocol["operator"],
        "A268_result_sha256": protocol["anchors"]["A268_result_sha256"],
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "headline": headline,
        "retention_gate": {**gate, "passed": retained},
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.analyze_only:
        print(
            json.dumps(
                analyze(args.protocol, args.expected_protocol_sha256),
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                **payload["headline"],
                "result": str(args.output),
                "result_sha256": _file_sha256(args.output),
                "causal": str(args.causal_output),
                "causal_sha256": _file_sha256(args.causal_output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
