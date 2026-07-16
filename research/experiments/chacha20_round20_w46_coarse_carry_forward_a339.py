#!/usr/bin/env python3
"""A339: freeze a W46 coarse carry-forward and protected raw-Linf portfolio."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_coarse_carry_forward_a339_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_coarse_carry_forward_a339_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w46_coarse_carry_forward_a339_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_w46_coarse_carry_forward_a339_order_v1.md"

A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A325_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A338_RESULT = RESULTS / "chacha20_round20_extended_pre_result_rank_panel_a338_v1.json"
A339_TEST = ROOT / "tests/test_chacha20_round20_w46_coarse_carry_forward_a339.py"
A339_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_coarse_carry_forward_a339.sh"

ATTEMPT_ID = "A339"
DESIGN_SHA256 = "47c5e44f6ad19bc78d3242a040e5f37da04a824b06783d99c5b7856e2c7e6f11"
ANCHOR_SHA256 = {
    A318_ORDER: "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0",
    A325_PROTOCOL: "480fe15f22c87df1b9422c1dc8cfcf5a9add147f65b6631d25e94d66b5255a2c",
    A338_RESULT: "361d670f64c909c227ad26f1dfa6d5469ec12cb549f3005c69c87877558dd02e",
}
EXPECTED_ORDER_SHA256 = {
    "A325_raw_linf_baseline": "5d1afc37614fdbe050e9853413a3de7b850b876e9bc5649d3dffcf3e23c9780a",
    "W45_coarse_carry_forward_primary": "79cb4208849e1a7926fded8ed507e3c5c7c7bf7b9724177ffcfe4aa0f837c56a",
    "W45_fine_carry_forward_view_control": "d21b993bdafb78016ae5d801a6c072c1e188c733c3db20e02ef825a5e7e1f555",
}
CELLS = 1 << 12
RAW = "A325_raw_linf_baseline"
COARSE = "W45_coarse_carry_forward_primary"
WAVEFRONT = "raw_coarse_min_rank_wavefront_protected"
BORDA = "raw_coarse_equal_borda"
FINE_CONTROL = "W45_fine_carry_forward_view_control"
CANDIDATE_NAMES = (RAW, COARSE, WAVEFRONT, BORDA, FINE_CONTROL)

DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
sys.path.insert(0, str(DOTCAUSAL_SRC))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def atomic_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    observed = file_sha256(path)
    if expected is not None and observed != expected:
        raise RuntimeError(f"A339 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A339 {label} is not an exact 4,096-cell cover")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(cell.to_bytes(2, "big") for cell in exact_order(order, "hash"))
    ).hexdigest()


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A339 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("order_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-w46-coarse-carry-forward-a339-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_after_A338_before_any_A325_execution_candidate_prefix_or_result"
        or tuple(contract.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or contract.get("primary_operator") != COARSE
        or contract.get("protected_operator") != WAVEFRONT
        or contract.get("established_baseline") != RAW
        or contract.get("matched_view_control") != FINE_CONTROL
        or contract.get("A325_existing_execution_order_rewritten") is not False
        or contract.get("new_candidate_execution") is not False
        or boundary.get("A338_global_winner_was_prospectively_selected_for_A322") is not False
        or boundary.get("A325_public_challenge_feature_used") is not False
        or boundary.get("A325_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("A325_result_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A325") != 0
        or boundary.get("orders_refit_after_A325") is not False
    ):
        raise RuntimeError("A339 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                ROOT / value,
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def min_rank_wavefront(raw: Sequence[int], coarse: Sequence[int]) -> list[int]:
    raw_ranks = rank_vector(raw)
    coarse_ranks = rank_vector(coarse)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(raw_ranks[cell], coarse_ranks[cell]),
                raw_ranks[cell] + coarse_ranks[cell],
                raw_ranks[cell],
                coarse_ranks[cell],
                cell,
            ),
        ),
        "factor-two wavefront",
    )


def equal_borda(raw: Sequence[int], coarse: Sequence[int]) -> list[int]:
    raw_ranks = rank_vector(raw)
    coarse_ranks = rank_vector(coarse)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                raw_ranks[cell] + coarse_ranks[cell],
                min(raw_ranks[cell], coarse_ranks[cell]),
                max(raw_ranks[cell], coarse_ranks[cell]),
                raw_ranks[cell],
                coarse_ranks[cell],
                cell,
            ),
        ),
        "equal Borda",
    )


def wavefront_guarantee(
    wavefront: Sequence[int], raw: Sequence[int], coarse: Sequence[int]
) -> dict[str, Any]:
    wave_ranks = rank_vector(wavefront)
    raw_ranks = rank_vector(raw)
    coarse_ranks = rank_vector(coarse)
    best = [min(raw_ranks[cell], coarse_ranks[cell]) for cell in range(CELLS)]
    violations = [cell for cell in range(CELLS) if wave_ranks[cell] > 2 * best[cell]]
    worst = max(range(CELLS), key=lambda cell: wave_ranks[cell] / best[cell])
    return {
        "statement": "R_wavefront(cell) <= 2 * min(R_raw_linf(cell), R_coarse(cell))",
        "violations": len(violations),
        "first_violation_cell": violations[0] if violations else None,
        "maximum_rank_ratio_to_best_source": wave_ranks[worst] / best[worst],
        "maximum_ratio_cell": worst,
        "wavefront_rank_one_based": wave_ranks[worst],
        "best_source_rank_one_based": best[worst],
    }


def spearman(left: Sequence[int], right: Sequence[int]) -> float:
    left_ranks = rank_vector(left)
    right_ranks = rank_vector(right)
    squared = sum((a - b) ** 2 for a, b in zip(left_ranks, right_ranks, strict=True))
    return 1.0 - 6.0 * squared / (CELLS * (CELLS * CELLS - 1))


def build_family() -> dict[str, Any]:
    design = load_design()
    a318 = json.loads(A318_ORDER.read_bytes())
    a325 = json.loads(A325_PROTOCOL.read_bytes())
    a338 = json.loads(A338_RESULT.read_bytes())
    winner = a338.get("global_descriptive_winner", {})
    if (
        winner.get("alias") != "A335/carry_forward_alpha_0/coarse"
        or winner.get("rank_one_based") != 12
        or winner.get("prospectively_selected_for_A322") is not False
        or winner.get("descriptive_breadcrumb_only") is not True
    ):
        raise RuntimeError("A339 A338 rank-12 breadcrumb differs")
    if (
        a325.get("selected_family") != "raw_multiview"
        or a325.get("selected_operator") != "raw_nearest_prototype_Linf"
        or a325.get("selected_W46_order_uint16be_sha256") != EXPECTED_ORDER_SHA256[RAW]
    ):
        raise RuntimeError("A339 A325 raw-Linf protocol source differs")
    coordinate_orders = a318.get("coordinate_source_orders", {})
    orders = {
        RAW: exact_order(a325["selected_W46_order"], RAW),
        COARSE: exact_order(coordinate_orders["coarse"], COARSE),
        FINE_CONTROL: exact_order(coordinate_orders["fine"], FINE_CONTROL),
    }
    for name, expected in EXPECTED_ORDER_SHA256.items():
        if order_sha256(orders[name]) != expected:
            raise RuntimeError(f"A339 frozen source order differs: {name}")
    orders[WAVEFRONT] = min_rank_wavefront(orders[RAW], orders[COARSE])
    orders[BORDA] = equal_borda(orders[RAW], orders[COARSE])
    orders = {name: orders[name] for name in CANDIDATE_NAMES}
    guarantee = wavefront_guarantee(orders[WAVEFRONT], orders[RAW], orders[COARSE])
    if guarantee["violations"] != 0 or guarantee["maximum_rank_ratio_to_best_source"] > 2:
        raise RuntimeError("A339 factor-two wavefront guarantee failed")
    order_hashes = {name: order_sha256(order) for name, order in orders.items()}
    if len(set(order_hashes.values())) != len(CANDIDATE_NAMES):
        raise RuntimeError("A339 expected five distinct frozen orders")
    return {
        "design": design,
        "orders": orders,
        "order_hashes": order_hashes,
        "wavefront_guarantee": guarantee,
        "operator_geometry": {
            "raw_vs_coarse_spearman": spearman(orders[RAW], orders[COARSE]),
            "raw_vs_fine_control_spearman": spearman(orders[RAW], orders[FINE_CONTROL]),
            "coarse_vs_fine_control_spearman": spearman(orders[COARSE], orders[FINE_CONTROL]),
        },
        "A338_breadcrumb": winner,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A339:frozen_W46_coarse_raw_portfolio"
    writer = CausalWriter(api_id="a339w46")
    writer._rules = []
    writer.add_rule(
        name="rank12_breadcrumb_to_width46_carry_forward",
        description="The exact rank-12 W45 coarse carry-forward breadcrumb transfers its unchanged width-walk rule to the unseen W46 prefix field.",
        pattern=["A338_rank12_coarse_breadcrumb", "A325_not_executed"],
        conclusion="A339_W45_coarse_carry_forward_primary",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="raw_and_coarse_to_protected_wavefront",
        description="Raw Linf and coarse carry-forward ranks form an exact min-rank wavefront with a pointwise factor-two guarantee.",
        pattern=["A325_raw_Linf_order", "A339_coarse_carry_forward_order"],
        conclusion="A339_factor_two_protected_wavefront",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_orders_to_future_single_execution_readout",
        description="All five orders are frozen without a W46 label and will receive one prefix lookup only after independent A325 confirmation.",
        pattern=["A339_five_hash_frozen_orders", "future_A325_dual_confirmation"],
        conclusion="A339_postconfirmation_rank_panel_without_duplicate_execution",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A338:A335_coarse_carry_forward_rank12_on_confirmed_W45",
        mechanism="unchanged_width_walk_transfer_from_exact_W45_coarse_order",
        outcome="A339:prospective_W46_coarse_carry_forward_primary",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["A338_breadcrumb"], sort_keys=True),
        evidence="FROZEN_BEFORE_A325_EXECUTION_OR_PREFIX",
        domain="AI-native width-walk inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A339:raw_Linf_plus_coarse_carry_forward",
        mechanism="exact_min_rank_wavefront_with_pointwise_factor_two_bound",
        outcome="A339:protected_W46_prefix_order",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["wavefront_guarantee"], sort_keys=True),
        evidence="ZERO_GUARANTEE_VIOLATIONS_ACROSS_4096_CELLS",
        domain="rank-portfolio amplification",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A339:five_exact_hash_frozen_W46_orders",
        mechanism="zero_target_label_prospective_commitment",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["order_uint16be_sha256"], sort_keys=True),
        evidence="A325_PROTOCOL_UNCHANGED_ZERO_CANDIDATE_EXECUTIONS",
        domain="prospective Causal commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A338:rank12_breadcrumb_and_A325_raw_Linf_protocol",
        mechanism="materialized_coarse_transfer_and_factor_two_protection_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A339_W46_portfolio_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A339 W46 coarse carry-forward portfolio",
        entities=[
            "A338:A335_coarse_carry_forward_rank12_on_confirmed_W45",
            "A339:prospective_W46_coarse_carry_forward_primary",
            "A339:raw_Linf_plus_coarse_carry_forward",
            "A339:protected_W46_prefix_order",
            "A339:five_exact_hash_frozen_W46_orders",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="single_independently_confirmed_A325_prefix_ranked_in_all_five_frozen_orders",
        confidence=1.0,
        suggested_queries=[
            "After A325 dual confirmation, which frozen A339 order reaches its W46 prefix first without another candidate execution?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a339w46"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A339 authentic Causal reopen gate failed")
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
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A339 artifacts already exist")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A339 must materialize before any A325 execution or result")
    built = build_family()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-coarse-carry-forward-a339-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A325_EXECUTION_W46_COUNTERFACTUAL_ORDER_FAMILY_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "primary_operator": COARSE,
        "protected_operator": WAVEFRONT,
        "established_execution_order": RAW,
        "matched_view_control": FINE_CONTROL,
        "orders": built["orders"],
        "order_uint16be_sha256": built["order_hashes"],
        "unique_order_count": len(set(built["order_hashes"].values())),
        "wavefront_guarantee": built["wavefront_guarantee"],
        "operator_geometry": built["operator_geometry"],
        "A338_breadcrumb": built["A338_breadcrumb"],
        "information_boundary": {
            **built["design"]["information_boundary"],
            "A325_progress_absent_at_materialization": True,
            "A325_result_absent_at_materialization": True,
            "A325_challenge_fields_read_for_order_construction": 0,
            "candidate_executions_performed_by_A339": 0,
            "A325_protocol_modified": False,
        },
        "future_evaluation_contract": built["design"]["future_evaluation_contract"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A318_order": anchor(A318_ORDER, ANCHOR_SHA256[A318_ORDER]),
            "A325_protocol": anchor(A325_PROTOCOL, ANCHOR_SHA256[A325_PROTOCOL]),
            "A338_result": anchor(A338_RESULT, ANCHOR_SHA256[A338_RESULT]),
            "runner": anchor(Path(__file__)),
            "test": anchor(A339_TEST),
            "reproducer": anchor(A339_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "source_anchor_sha256": {
                relative(path): digest for path, digest in ANCHOR_SHA256.items()
            },
            "candidate_sequence": payload["candidate_sequence"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "wavefront_guarantee": payload["wavefront_guarantee"],
            "operator_geometry": payload["operator_geometry"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    guarantee = payload["wavefront_guarantee"]
    atomic_bytes(
        REPORT,
        (
            "# A339 — frozen W46 coarse carry-forward portfolio\n\n"
            "- A338 retained breadcrumb: **coarse carry-forward rank 12 / 4,096 on confirmed W45**\n"
            "- W46 primary: **exact W45 coarse-order carry-forward**\n"
            "- Protected order: **raw Linf + coarse exact min-rank wavefront**\n"
            f"- Factor-two violations over all cells: **{guarantee['violations']}**\n"
            f"- Maximum observed pointwise ratio: **{guarantee['maximum_rank_ratio_to_best_source']:.9f}**\n"
            f"- Exact distinct frozen orders: **{payload['unique_order_count']} / 5**\n"
            "- A325 candidate executions / protocol changes: **zero / zero**\n"
            "- A325 progress and result at freeze: **absent / absent**\n"
            "- Future readout: **one independently confirmed A325 prefix, five exact rank lookups**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


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
                "unique_order_count": payload["unique_order_count"],
                "wavefront_guarantee": payload["wavefront_guarantee"],
                "order_uint16be_sha256": payload["order_uint16be_sha256"],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    args = parser.parse_args()
    payload = analyze() if args.analyze else materialize()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
