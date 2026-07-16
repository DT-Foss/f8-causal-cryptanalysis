#!/usr/bin/env python3
"""A341: freeze a familywise-selected, public-output-conditioned W46 portfolio."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.score_hypercube import local_pairwise_residual  # noqa: E402
from arx_carry_leak.trajectory_contribution import (  # noqa: E402
    familywise_best_gain,
    grouped_scores,
    score_view_statistics,
    standardized_contributions,
)

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_familywise_channel_portfolio_a341_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_familywise_channel_portfolio_a341_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_familywise_channel_portfolio_a341_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_familywise_channel_portfolio_a341.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_familywise_channel_portfolio_a341.sh"

A271_PROTOCOL = CONFIGS / "chacha20_round20_signed_channel_ablation_v1.json"
A271_RESULT = RESULTS / "chacha20_round20_signed_channel_ablation_v1.json"
A271_RUNNER = RESEARCH / "experiments/chacha20_round20_signed_channel_ablation.py"
A272_PROTOCOL = CONFIGS / "chacha20_round20_selected_channel_prospective_validation_v1.json"
A272_RESULT = RESULTS / "chacha20_round20_selected_channel_prospective_validation_v1.json"
A272_RUNNER = RESEARCH / "experiments/chacha20_round20_selected_channel_prospective_validation.py"
A325_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A340_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_target_conditioned_causal_order_a340.py"
A340_RESULT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.json"
A340_MEASUREMENT = (
    RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_measurement_v1.json.zst"
)

ATTEMPT_ID = "A341"
DESIGN_SHA256 = "590a1c65be9796879015fed53aa30c0cb7d5d6c5e9bf89c41bd66d686273b690"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
sys.path.insert(0, str(DOTCAUSAL_SRC))

CELLS = 4096
COARSE_CELLS = 256
SELECTED_GROUP = "learned_literal_count_stage::coefficient_negative"
SELECTED_MODE = "normalized_8cube_graph_laplacian"
SELECTED_VIEW = f"{SELECTED_GROUP}::{SELECTED_MODE}"

RAW = "A325_raw_linf_baseline"
A340_SELECTED = "A340_target_conditioned_selected_channel_fine"
A341_SELECTED = "A341_familywise_selected_literal_local_fine"
FACTOR2 = "raw_A341_min_rank_wavefront_factor2"
FACTOR3 = "raw_A340_A341_min_rank_wavefront_factor3"
BORDA3 = "raw_A340_A341_equal_borda"
HASH_CONTROL = "A325_public_hash_control"
CANDIDATE_NAMES = (
    RAW,
    A340_SELECTED,
    A341_SELECTED,
    FACTOR2,
    FACTOR3,
    BORDA3,
    HASH_CONTROL,
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A341 dependency: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A340 = load_module(A340_RUNNER, "a341_a340")
sha256 = A340.sha256
file_sha256 = A340.file_sha256
canonical_bytes = A340.canonical_bytes
canonical_sha256 = A340.canonical_sha256
atomic_bytes = A340.atomic_bytes
atomic_json = A340.atomic_json
relative = A340.relative
anchor = A340.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A341 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return sha256(b"".join(value.to_bytes(2, "big") for value in exact_order(order, "hash")))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def min_rank_wavefront(source_orders: Sequence[Sequence[int]], label: str) -> list[int]:
    if len(source_orders) < 2:
        raise ValueError("A341 wavefront requires at least two sources")
    ranks = [rank_vector(order) for order in source_orders]
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(row[cell] for row in ranks),
                sum(row[cell] for row in ranks),
                *(row[cell] for row in ranks),
                cell,
            ),
        ),
        label,
    )


def equal_borda(source_orders: Sequence[Sequence[int]]) -> list[int]:
    if len(source_orders) < 2:
        raise ValueError("A341 Borda requires at least two sources")
    ranks = [rank_vector(order) for order in source_orders]
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                sum(row[cell] for row in ranks),
                min(row[cell] for row in ranks),
                max(row[cell] for row in ranks),
                *(row[cell] for row in ranks),
                cell,
            ),
        ),
        "three-way equal Borda",
    )


def wavefront_guarantee(
    wavefront: Sequence[int], source_orders: Sequence[Sequence[int]]
) -> dict[str, Any]:
    wave_ranks = rank_vector(wavefront)
    source_ranks = [rank_vector(order) for order in source_orders]
    best = [min(row[cell] for row in source_ranks) for cell in range(CELLS)]
    factor = len(source_orders)
    violations = [cell for cell in range(CELLS) if wave_ranks[cell] > factor * best[cell]]
    worst = max(range(CELLS), key=lambda cell: wave_ranks[cell] / best[cell])
    return {
        "source_count": factor,
        "statement": f"R_wavefront(cell) <= {factor} * min_i R_i(cell)",
        "violations": len(violations),
        "first_violation_cell": violations[0] if violations else None,
        "maximum_rank_ratio_to_best_source": wave_ranks[worst] / best[worst],
        "maximum_ratio_cell": worst,
        "wavefront_rank_one_based": wave_ranks[worst],
        "best_source_rank_one_based": best[worst],
    }


def spearman_order(left: Sequence[int], right: Sequence[int]) -> float:
    left_ranks = rank_vector(left)
    right_ranks = rank_vector(right)
    squared = sum((a - b) ** 2 for a, b in zip(left_ranks, right_ranks, strict=True))
    return 1.0 - 6.0 * squared / (CELLS * (CELLS * CELLS - 1))


def coarse_spearman(left: Sequence[int], right: Sequence[int]) -> float:
    if len(left) != COARSE_CELLS or len(right) != COARSE_CELLS:
        raise ValueError("A341 coarse order width differs")
    left_ranks = [0] * COARSE_CELLS
    right_ranks = [0] * COARSE_CELLS
    for rank, cell in enumerate(left, 1):
        left_ranks[int(cell)] = rank
    for rank, cell in enumerate(right, 1):
        right_ranks[int(cell)] = rank
    squared = sum((a - b) ** 2 for a, b in zip(left_ranks, right_ranks, strict=True))
    return 1.0 - 6.0 * squared / (COARSE_CELLS * (COARSE_CELLS**2 - 1))


def assert_pre_a325_execution() -> None:
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A341 must materialize before any A325 execution or result")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A341 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    selection = design.get("known_key_selection_contract", {})
    target = design.get("target_application_contract", {})
    portfolio = design.get("portfolio_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-w46-familywise-channel-portfolio-a341-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "known_key_selection_complete_and_frozen_before_any_A325_execution_prefix_or_result"
        or selection.get("selected_group") != SELECTED_GROUP
        or selection.get("selected_mode") != SELECTED_MODE
        or selection.get("selected_view") != SELECTED_VIEW
        or selection.get("view_count") != 64
        or target.get("coarse_candidates") != COARSE_CELLS
        or target.get("fine_candidates") != CELLS
        or target.get("target_labels_used") != 0
        or tuple(portfolio.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or portfolio.get("primary_operator") != A341_SELECTED
        or portfolio.get("protected_operator") != FACTOR3
        or boundary.get("A325_hidden_assignment_available") is not False
        or boundary.get("A325_progress_available") is not False
        or boundary.get("A325_result_available") is not False
        or boundary.get("A325_target_label_used_for_selection_scoring_or_ordering") is not False
        or boundary.get("A325_candidate_execution_by_A341") is not False
        or boundary.get("A325_protocol_or_existing_raw_order_modified") is not False
        or boundary.get("model_refits_or_coefficient_updates") != 0
    ):
        raise RuntimeError("A341 frozen design semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            expected = anchors[key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / value, expected)
    return design


def reconstruct_known_key_selection(
    design: Mapping[str, Any],
) -> tuple[dict[str, Any], Any, Any, dict[str, tuple[int, ...]]]:
    a272 = load_module(A272_RUNNER, "a341_a272")
    protocol, a268, _a251_protocol, a268_preflight, _a242, _indices = a272._load_protocol(  # noqa: SLF001
        A272_PROTOCOL, design["source_anchors"]["A272_protocol_sha256"]
    )
    a268_protocol = json.loads((ROOT / protocol["anchors"]["A268_protocol_path"]).read_bytes())
    model = a268._frozen_model(a268_protocol, a268_preflight)  # noqa: SLF001
    if canonical_sha256(model.as_dict()) != design["source_anchors"]["frozen_model_sha256"]:
        raise RuntimeError("A341 frozen model identity differs")

    a271_protocol = json.loads(A271_PROTOCOL.read_bytes())
    groups = {
        row["name"]: tuple(int(index) for index in row["feature_indices"])
        for row in a271_protocol["frozen_model"]["signed_semantic_groups"]
    }
    group_rows = [
        {"name": name, "feature_indices": list(indices)} for name, indices in groups.items()
    ]
    if canonical_sha256(group_rows) != design["source_anchors"]["A271_group_ledger_sha256"]:
        raise RuntimeError("A341 signed group ledger differs")

    a272_result = json.loads(A272_RESULT.read_bytes())
    if (
        a272_result.get("retention_gate", {}).get("passed") is not True
        or a272_result.get("prospective_corpus", {}).get("complete_candidate_covers") is not True
        or len(a272_result.get("prospective_corpus", {}).get("measurement_ledger", [])) != 20
    ):
        raise RuntimeError("A341 A272 source corpus gate failed")
    stored_ledgers = {
        row["label"]: row for row in a272_result["prospective_corpus"]["measurement_ledger"]
    }
    rows = list(protocol["prospective_design"]["rows"])
    fields = {name: [] for name in groups}
    truths: list[int] = []
    prefix_indices: list[int] = []
    measurement_ledger = []
    for row in rows:
        label = str(row["label"])
        path = a272._measurement_path(label)  # noqa: SLF001
        stored = stored_ledgers[label]
        if file_sha256(path) != stored["compressed_sha256"]:
            raise RuntimeError(f"A341 A272 measurement hash differs: {label}")
        measurement = a272._read_measurement(  # noqa: SLF001
            path, design["source_anchors"]["A272_protocol_sha256"], a268
        )
        table = a268.build_trajectory_shape_table(measurement)
        contributions = standardized_contributions(
            table.matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        for name, scores in grouped_scores(contributions, groups).items():
            fields[name].append(scores)
        truths.append(int(row["prefix8"]))
        prefix_indices.append(int(row["prefix_index"]))
        measurement_ledger.append(
            {"label": label, "path": relative(path), "sha256": file_sha256(path)}
        )

    evaluations: dict[str, dict[str, Any]] = {}
    for group_name in sorted(fields):
        direct = f"{group_name}::direct_additive_contribution"
        local = f"{group_name}::normalized_8cube_graph_laplacian"
        evaluations[direct] = score_view_statistics(
            fields[group_name], true_prefixes=truths, prefix_indices=prefix_indices
        )
        evaluations[local] = score_view_statistics(
            [local_pairwise_residual(field) for field in fields[group_name]],
            true_prefixes=truths,
            prefix_indices=prefix_indices,
        )
    familywise = familywise_best_gain(evaluations)
    selected_name = max(
        evaluations,
        key=lambda name: (evaluations[name]["mean_log2_rank_bit_gain"], name),
    )
    selected = evaluations[selected_name]
    contract = design["known_key_selection_contract"]
    if (
        len(evaluations) != 64
        or selected_name != SELECTED_VIEW
        or familywise["best_observed_view"] != SELECTED_VIEW
        or familywise["exact_familywise_shared_xor_p"]
        != contract["expected_familywise_exact_shared_xor_p"]
        or selected["exact_shared_xor_p"] != contract["expected_selected_exact_shared_xor_p"]
        or abs(
            selected["mean_log2_rank_bit_gain"]
            - contract["expected_selected_mean_log2_rank_bit_gain"]
        )
        > 1e-15
        or selected["positive_prefix_groups"]
        != contract["expected_selected_positive_prefix_groups"]
    ):
        raise RuntimeError("A341 known-key familywise selection differs")
    panel = [
        {
            "view": name,
            "mean_log2_rank": values["mean_log2_rank"],
            "mean_log2_rank_bit_gain": values["mean_log2_rank_bit_gain"],
            "exact_shared_xor_p": values["exact_shared_xor_p"],
            "positive_prefix_groups": values["positive_prefix_groups"],
        }
        for name, values in sorted(
            evaluations.items(),
            key=lambda item: (-item[1]["mean_log2_rank_bit_gain"], item[0]),
        )
    ]
    selection = {
        "known_key_count": len(rows),
        "complete_candidate_covers": len(rows),
        "candidate_measurements": len(rows) * COARSE_CELLS,
        "view_count": len(evaluations),
        "selected_view": SELECTED_VIEW,
        "selected_feature_indices": list(groups[SELECTED_GROUP]),
        "selected_statistics": {
            key: selected[key]
            for key in (
                "ranks",
                "mean_log2_rank",
                "uniform_mean_log2_rank_reference",
                "mean_log2_rank_bit_gain",
                "positive_prefix_groups",
                "prefix_groups",
                "exact_shared_xor_p",
                "best_shared_xor_offset",
            )
        },
        "familywise": {
            "best_observed_view": familywise["best_observed_view"],
            "best_observed_bit_gain": familywise["best_observed_bit_gain"],
            "exact_familywise_shared_xor_p": familywise["exact_familywise_shared_xor_p"],
            "best_null_offset": familywise["best_null_offset"],
            "max_statistic_vector_sha256": canonical_sha256(
                familywise["max_bit_gain_by_shared_xor_offset"]
            ),
        },
        "selection_panel": panel,
        "selection_panel_sha256": canonical_sha256(panel),
        "full_evaluation_sha256": canonical_sha256(
            {"evaluations": evaluations, "familywise": familywise}
        ),
        "measurement_ledger": measurement_ledger,
        "measurement_ledger_sha256": canonical_sha256(measurement_ledger),
        "model_refits": 0,
    }
    return selection, a272, model, groups


def load_a340_measurement(
    design: Mapping[str, Any], a272: Any, model: Any, groups: Mapping[str, Sequence[int]]
) -> tuple[list[int], list[float], dict[str, Any], Any]:
    a340_result = json.loads(A340_RESULT.read_bytes())
    if (
        a340_result.get("attempt_id") != "A340"
        or a340_result.get("measurement_summary", {}).get("model_free_UNKNOWN_stages") != 1024
        or a340_result.get("measurement_summary", {}).get("models_returned") != 0
        or a340_result.get("measurement_summary", {}).get("target_labels_used") != 0
        or a340_result.get("information_boundary", {}).get(
            "A325_hidden_assignment_prefix_or_filter_outcome_used"
        )
        is not False
    ):
        raise RuntimeError("A341 A340 result boundary differs")
    ledger = a340_result["measurement"]
    compressed = A340_MEASUREMENT.read_bytes()
    if sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A341 A340 compressed measurement hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A341 A340 raw measurement hash differs")
    measurement = json.loads(raw)
    if canonical_bytes(measurement) != raw:
        raise RuntimeError("A341 A340 measurement is not canonical")
    a275, target_model, _a291, _indices, _helper = A340.A296._reader_stack()  # noqa: SLF001
    if (
        canonical_sha256(target_model.as_dict()) != canonical_sha256(model.as_dict())
        or canonical_sha256(target_model.as_dict())
        != design["source_anchors"]["frozen_model_sha256"]
    ):
        raise RuntimeError("A341 target and selection model identities differ")
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    group_score = grouped_scores(contributions, groups)[SELECTED_GROUP]
    scores = local_pairwise_residual(group_score)
    coarse = [int(value) for value in a275._candidate_order(scores)]  # noqa: SLF001
    if len(coarse) != COARSE_CELLS or set(coarse) != set(range(COARSE_CELLS)):
        raise RuntimeError("A341 selected coarse order differs")
    return coarse, np.asarray(scores, dtype=np.float64).tolist(), a340_result, a275


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    selected = "A341:familywise_selected_literal_local_reader"
    order = "A341:target_conditioned_complete_W46_order"
    terminal = "A341:protected_three_operator_W46_portfolio"
    writer = CausalWriter(api_id="a341w46")
    writer._rules = []
    writer.add_rule(
        name="familywise_known_key_selection",
        description="All 64 A271 views are evaluated on all twenty disjoint A272 known keys under one exact shared-XOR max statistic.",
        pattern=["A271_sixty_four_frozen_views", "A272_twenty_complete_known_key_covers"],
        conclusion="A341_familywise_selected_literal_local_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_reader_to_public_target_order",
        description="The selected frozen reader consumes A340's complete model-free public-output measurement without refit and emits one exact W46 order.",
        pattern=["A341_familywise_selected_literal_local_reader", "A340_public_output_measurement"],
        conclusion="A341_target_conditioned_complete_W46_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="three_operator_factor_protection",
        description="Raw Linf, A340 selected-channel and A341 familywise-selected orders form a pointwise factor-three min-rank portfolio.",
        pattern=["A341_target_conditioned_complete_W46_order", "A340_and_raw_orders"],
        conclusion="A341_protected_three_operator_W46_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A271:sixty_four_frozen_signed_views",
        mechanism="complete_A272_twenty_key_familywise_XOR_selection",
        outcome=selected,
        confidence=1.0,
        source=payload["selection_analysis_sha256"],
        quantification=json.dumps(payload["known_key_selection"]["familywise"], sort_keys=True),
        evidence="FAMILYWISE_P_3_OVER_256_SELECTED_GAIN_2_125768_BITS_FIVE_OF_FIVE_GROUPS",
        domain="known-key Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="reuse_A340_public_output_model_free_measurement_without_refit",
        outcome=order,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                "coarse_order_sha256": payload["target_application"]["coarse_order_uint8_sha256"],
                "fine_order_sha256": payload["order_uint16be_sha256"][A341_SELECTED],
            },
            sort_keys=True,
        ),
        evidence="ZERO_TARGET_LABELS_ZERO_REFITS_ZERO_NEW_SOLVER_STAGES",
        domain="public-output-conditioned Causal ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=order,
        mechanism="join_raw_A340_A341_by_min_rank_wavefront",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["guarantees"]["factor3"], sort_keys=True),
        evidence="ZERO_POINTWISE_FACTOR_THREE_VIOLATIONS",
        domain="protected diverse-operator search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A271:sixty_four_frozen_signed_views",
        mechanism="materialized_known_key_selection_target_application_and_protection_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A341_familywise_target_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A341 familywise-selected W46 portfolio",
        entities=["A271:sixty_four_frozen_signed_views", selected, order, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="single_independently_confirmed_A325_prefix_ranked_across_all_seven_frozen_A341_orders",
        confidence=1.0,
        suggested_queries=[
            "After A325 confirmation, which frozen public-output-conditioned operator reaches the W46 prefix first and how many search-gain bits does its protected portfolio retain?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a341w46"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A341 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A341 result artifacts already exist")
    assert_pre_a325_execution()
    design = load_design()
    selection, a272, model, groups = reconstruct_known_key_selection(design)
    coarse, target_scores, a340_result, _a275 = load_a340_measurement(design, a272, model, groups)
    selected_fine = exact_order(A340.A296.fine_order(coarse), A341_SELECTED)
    raw = exact_order(a340_result["orders"][A340.RAW], RAW)
    a340_selected = exact_order(a340_result["orders"][A340.TARGET_CAUSAL], A340_SELECTED)
    hash_control = exact_order(a340_result["orders"][A340.HASH_CONTROL], HASH_CONTROL)
    sources2 = [raw, selected_fine]
    sources3 = [raw, a340_selected, selected_fine]
    orders = {
        RAW: raw,
        A340_SELECTED: a340_selected,
        A341_SELECTED: selected_fine,
        FACTOR2: min_rank_wavefront(sources2, FACTOR2),
        FACTOR3: min_rank_wavefront(sources3, FACTOR3),
        BORDA3: equal_borda(sources3),
        HASH_CONTROL: hash_control,
    }
    orders = {name: orders[name] for name in CANDIDATE_NAMES}
    hashes = {name: order_sha256(order) for name, order in orders.items()}
    if len(set(hashes.values())) != len(CANDIDATE_NAMES):
        raise RuntimeError("A341 expected seven distinct orders")
    factor2 = wavefront_guarantee(orders[FACTOR2], sources2)
    factor3 = wavefront_guarantee(orders[FACTOR3], sources3)
    if (
        factor2["violations"] != 0
        or factor2["maximum_rank_ratio_to_best_source"] > 2
        or factor3["violations"] != 0
        or factor3["maximum_rank_ratio_to_best_source"] > 3
    ):
        raise RuntimeError("A341 pointwise portfolio guarantee failed")
    pairwise = {
        left: {right: spearman_order(orders[left], orders[right]) for right in CANDIDATE_NAMES}
        for left in CANDIDATE_NAMES
    }
    target_application = {
        "A340_measurement_reused": True,
        "new_solver_stages": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "coarse_order": coarse,
        "coarse_order_uint8_sha256": sha256(bytes(coarse)),
        "score_field": target_scores,
        "score_field_sha256": canonical_sha256(target_scores),
        "complete_fine_cells": len(selected_fine),
        "old_A340_vs_new_A341_coarse_spearman": coarse_spearman(
            a340_result["coarse_order"], coarse
        ),
    }
    selection_analysis_sha256 = canonical_sha256(selection)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-familywise-channel-portfolio-a341-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A325_EXECUTION_FAMILYWISE_SELECTED_PUBLIC_OUTPUT_CONDITIONED_W46_PORTFOLIO_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "A325_protocol_sha256": design["source_anchors"]["A325_protocol_sha256"],
        "A325_public_challenge_sha256": a340_result["A325_public_challenge_sha256"],
        "known_key_selection": selection,
        "selection_analysis_sha256": selection_analysis_sha256,
        "target_application": target_application,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "primary_operator": A341_SELECTED,
        "protected_operator": FACTOR3,
        "orders": orders,
        "order_uint16be_sha256": hashes,
        "unique_order_count": len(set(hashes.values())),
        "guarantees": {"factor2": factor2, "factor3": factor3},
        "operator_geometry": {
            "pairwise_spearman": pairwise,
            "raw_vs_A341": pairwise[RAW][A341_SELECTED],
            "A340_vs_A341": pairwise[A340_SELECTED][A341_SELECTED],
            "A341_vs_public_hash": pairwise[A341_SELECTED][HASH_CONTROL],
        },
        "information_boundary": {
            **design["information_boundary"],
            "A325_progress_absent_at_materialization": True,
            "A325_result_absent_at_materialization": True,
            "A325_hidden_assignment_prefix_or_filter_outcome_used": False,
            "A325_candidate_executions_performed_by_A341": 0,
        },
        "future_evaluation_contract": {
            "gate": "exact_A325_result_SHA_after_independent_confirmation",
            "operation": "lookup_confirmed_prefix_rank_in_all_seven_frozen_orders_without_refit_or_duplicate_candidate_execution",
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A271_protocol": anchor(
                A271_PROTOCOL, design["source_anchors"]["A271_protocol_sha256"]
            ),
            "A271_result": anchor(A271_RESULT, design["source_anchors"]["A271_result_sha256"]),
            "A271_runner": anchor(A271_RUNNER, design["source_anchors"]["A271_runner_sha256"]),
            "A272_protocol": anchor(
                A272_PROTOCOL, design["source_anchors"]["A272_protocol_sha256"]
            ),
            "A272_result": anchor(A272_RESULT, design["source_anchors"]["A272_result_sha256"]),
            "A272_runner": anchor(A272_RUNNER, design["source_anchors"]["A272_runner_sha256"]),
            "A325_protocol": anchor(
                A325_PROTOCOL, design["source_anchors"]["A325_protocol_sha256"]
            ),
            "A340_result": anchor(A340_RESULT, design["source_anchors"]["A340_result_sha256"]),
            "A340_measurement": anchor(
                A340_MEASUREMENT, design["source_anchors"]["A340_measurement_sha256"]
            ),
            "A340_runner": anchor(A340_RUNNER, design["source_anchors"]["A340_runner_sha256"]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A325_protocol_sha256": payload["A325_protocol_sha256"],
            "A325_public_challenge_sha256": payload["A325_public_challenge_sha256"],
            "selected_view": SELECTED_VIEW,
            "selection_analysis_sha256": selection_analysis_sha256,
            "candidate_sequence": payload["candidate_sequence"],
            "order_uint16be_sha256": hashes,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "target_application": target_application,
            "order_uint16be_sha256": hashes,
            "guarantees": payload["guarantees"],
            "operator_geometry": payload["operator_geometry"],
        }
    )
    assert_pre_a325_execution()
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A341 — familywise-selected public-output W46 portfolio\n\n"
            "- Known-key selection covers: **20 / 20 complete A272 keys**\n"
            "- Frozen signed-channel views: **64 / 64**\n"
            f"- Selected known-key bit gain: **{selection['selected_statistics']['mean_log2_rank_bit_gain']:+.9f} bits**\n"
            f"- Exact familywise XOR p: **{selection['familywise']['exact_familywise_shared_xor_p']:.8f}**\n"
            "- Positive selection prefix groups: **5 / 5**\n"
            "- New A325 solver stages / target labels / refits: **0 / 0 / 0**\n"
            f"- Raw/A341 Spearman: **{pairwise[RAW][A341_SELECTED]:.8f}**\n"
            f"- A340/A341 Spearman: **{pairwise[A340_SELECTED][A341_SELECTED]:.8f}**\n"
            f"- Factor-two / factor-three violations: **{factor2['violations']} / {factor3['violations']}**\n"
            "- Exact distinct frozen orders: **7 / 7**\n"
            "- A325 candidate executions / protocol changes: **zero / zero**\n"
        ).encode(),
    )
    return {
        "attempt_id": ATTEMPT_ID,
        "result": relative(RESULT),
        "result_sha256": file_sha256(RESULT),
        "commitment_sha256": payload["commitment_sha256"],
        "measurement_sha256": payload["measurement_sha256"],
        "Causal_sha256": payload["causal"]["sha256"],
        "selected_view": SELECTED_VIEW,
        "known_key_selection": {
            "bit_gain": selection["selected_statistics"]["mean_log2_rank_bit_gain"],
            "individual_p": selection["selected_statistics"]["exact_shared_xor_p"],
            "familywise_p": selection["familywise"]["exact_familywise_shared_xor_p"],
            "positive_prefix_groups": selection["selected_statistics"]["positive_prefix_groups"],
        },
        "order_uint16be_sha256": hashes,
        "operator_geometry": payload["operator_geometry"],
        "guarantees": payload["guarantees"],
    }


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "commitment_sha256": payload["commitment_sha256"],
                "measurement_sha256": payload["measurement_sha256"],
                "selected_view": payload["known_key_selection"]["selected_view"],
                "known_key_selection": payload["known_key_selection"]["selected_statistics"],
                "order_uint16be_sha256": payload["order_uint16be_sha256"],
                "operator_geometry": payload["operator_geometry"],
                "guarantees": payload["guarantees"],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--run", action="store_true")
    action.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    payload = materialize() if args.run else analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
