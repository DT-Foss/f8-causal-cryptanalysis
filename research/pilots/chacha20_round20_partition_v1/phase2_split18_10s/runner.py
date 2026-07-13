#!/usr/bin/env python3
"""Frozen post-phase-1 split18 cut frontier for the round-20 pilot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


PHASE2_DIR = Path(__file__).resolve().parent
PHASE1_DIR = PHASE2_DIR.parent
PHASE1_RUNNER = PHASE1_DIR / "runner.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round20_partition_phase1_anchor", PHASE1_RUNNER
)
assert SPEC is not None and SPEC.loader is not None
P1 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = P1
SPEC.loader.exec_module(P1)


PHASE_ID = "PILOT_CHACHA20_R20_PARTITION_V1_PHASE2_SPLIT18"
SCHEMA = "chacha20-round20-width20-split18-partition-phase2-v1"
CONFIG_SCHEMA = "chacha20-round20-width20-split18-partition-phase2-protocol-v1"
SPLIT = 18
CONFIG_PATH = PHASE2_DIR / "config.json"
FORMULA_PLAN_PATH = PHASE2_DIR / "formula_plan.json"
LEDGER_PATH = PHASE2_DIR / "hash_ledger.json"
RESULT_PATH = PHASE2_DIR / "result.json"
CAUSAL_PATH = PHASE2_DIR / "result.causal"
README_PATH = PHASE2_DIR / "README.md"
TEST_PATH = PHASE2_DIR / "test_phase2.py"
REPRODUCE_PATH = PHASE2_DIR / "reproduce.sh"


def _execution_plan() -> dict[str, Any]:
    plan = P1._execution_plan()
    plan.update(
        {
            "formula_representation": "portable_SMTLIB2_round20_split18_b1_complete_5bit_prefix_partition",
            "split": SPLIT,
            "phase": "post_phase1_controlled_cut_frontier",
            "single_changed_factor_from_phase1": "split19_to_split18",
        }
    )
    return plan


def _phase1_gates(config: dict[str, Any]) -> dict[str, Any]:
    declared = config["phase1_anchors"]
    observed = {
        "config_sha256": P1._file_sha256(P1.CONFIG_PATH),
        "runner_sha256": P1._file_sha256(P1.Path(P1.__file__).resolve()),
        "formula_plan_file_sha256": P1._file_sha256(P1.FORMULA_PLAN_PATH),
        "hash_ledger_sha256": P1._file_sha256(P1.LEDGER_PATH),
        "result_sha256": P1._file_sha256(P1.RESULT_PATH),
        "causal_sha256": P1._file_sha256(P1.CAUSAL_PATH),
    }
    if observed != declared:
        raise RuntimeError("phase2 phase1 artifact hash gate failed")
    result = json.loads(P1.RESULT_PATH.read_bytes())
    reader = P1.CryptoCausalReader(P1.CAUSAL_PATH)
    if (
        result.get("evidence_stage")
        != "PILOT_ROUND20_WIDTH20_COMPLETE_PARTITION_SOLVER_BOUNDARY"
        or result.get("comparisons", {}).get("status_counts")
        != {
            "sat": 0,
            "unsat": 0,
            "unknown": 32,
            "invalid": 0,
            "external_timeout": 0,
        }
        or result.get("execution", {}).get("complete_variant_plan_executed")
        is not True
        or result.get("execution", {}).get("early_stop_used") is not False
        or result.get("confirmations") != []
        or reader.file_sha256 != declared["causal_sha256"]
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("phase2 retained phase1 all-unknown boundary gate failed")
    return {
        **observed,
        "phase1_status_counts": result["comparisons"]["status_counts"],
        "phase1_total_volatile_seconds": result["execution"]["total_volatile_seconds"],
        "phase1_causal_graph_sha256": reader.graph_sha256,
        "phase1_causal_provenance_verified": True,
    }


def _load_config() -> dict[str, Any]:
    config = json.loads(CONFIG_PATH.read_bytes())
    phase1_config = json.loads(P1.CONFIG_PATH.read_bytes())
    challenge = config.get("public_challenge", {})
    plan = _execution_plan()
    boundary = config.get("information_boundary", {})
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("phase_id") != PHASE_ID
        or config.get("protocol_state")
        != "frozen_after_complete_phase1_and_before_any_phase2_solver_execution"
        or config.get("public_challenge_sha256")
        != P1._canonical_sha256(challenge)
        or challenge != phase1_config["public_challenge"]
        or config.get("public_challenge_sha256")
        != phase1_config["public_challenge_sha256"]
        or config.get("execution_plan") != plan
        or config.get("execution_plan_sha256") != P1._canonical_sha256(plan)
        or boundary.get("phase1_retained_byte_exactly") is not True
        or boundary.get("only_changed_factor_from_phase1") != "split19_to_split18"
        or boundary.get("secret_prefix_used_for_cell_selection") is not False
        or boundary.get("all_thirty_two_cells_required") is not True
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("phase2 frozen config identity gate failed")
    P1._validate_challenge(challenge)
    _phase1_gates(config)
    if P1._solver_identity({"solver_binary": config["solver_binary"]}) != config[
        "solver_binary"
    ]:
        raise RuntimeError("phase2 solver gate failed")
    return config


def _formula_material(config: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    old_split = P1.SPLIT
    try:
        P1.SPLIT = SPLIT
        base = P1._base_formula(config["public_challenge"])
    finally:
        P1.SPLIT = old_split
    formulas = {variant: P1._formula(base, variant) for variant in P1.VARIANTS}
    rows = [
        {
            "bytes": len(formulas[variant].encode()),
            "candidate_count": 1 << P1.FREE_BITS,
            "fixed_key_coordinates": [19, 18, 17, 16, 15],
            "free_bits": P1.FREE_BITS,
            "free_key_coordinates": list(reversed(range(P1.FREE_BITS))),
            "portable_smtlib2": True,
            "prefix": f"{P1._prefix_value(variant):05b}",
            "sha256": P1._sha256(formulas[variant].encode()),
            "solver_time_limit_milliseconds": P1.TIME_LIMIT_MS,
            "split": SPLIT,
            "variant": variant,
        }
        for variant in P1.VARIANTS
    ]
    plan = {
        "schema": "chacha20-round20-width20-split18-formula-plan-v1",
        "phase_id": PHASE_ID,
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in rows),
        "partition_complete_and_disjoint_by_construction": True,
        "rows": rows,
    }
    if (
        plan["complete_domain_candidate_count"] != 1 << P1.UNKNOWN_KEY_BITS
        or [row["prefix"] for row in rows]
        != [f"{value:05b}" for value in range(P1.CELL_COUNT)]
    ):
        raise RuntimeError("phase2 formula plan coverage failed")
    return formulas, plan


def freeze() -> dict[str, Any]:
    if LEDGER_PATH.exists() or RESULT_PATH.exists() or CAUSAL_PATH.exists():
        raise RuntimeError("phase2 freeze is one-shot")
    config = _load_config()
    phase1 = _phase1_gates(config)
    _, formula_plan = _formula_material(config)
    P1._atomic_json(FORMULA_PLAN_PATH, formula_plan)
    source_paths = [
        CONFIG_PATH,
        Path(__file__).resolve(),
        FORMULA_PLAN_PATH,
        README_PATH,
        TEST_PATH,
        REPRODUCE_PATH,
    ]
    artifacts = {
        str(path.relative_to(P1.ROOT)): P1._file_sha256(path) for path in source_paths
    }
    ledger = {
        "schema": "chacha20-round20-width20-split18-phase2-freeze-ledger-v1",
        "phase_id": PHASE_ID,
        "protocol_state": "frozen_after_complete_phase1_and_before_any_phase2_solver_execution",
        "phase2_solver_execution_started": False,
        "artifacts": artifacts,
        "phase1_gates": phase1,
        "solver_identity": config["solver_binary"],
        "public_challenge_sha256": config["public_challenge_sha256"],
        "execution_plan_sha256": config["execution_plan_sha256"],
        "formula_plan_sha256": P1._canonical_sha256(formula_plan),
        "formula_plan_file_sha256": P1._file_sha256(FORMULA_PLAN_PATH),
    }
    P1._atomic_json(LEDGER_PATH, ledger)
    return {
        "config_sha256": P1._file_sha256(CONFIG_PATH),
        "runner_sha256": P1._file_sha256(Path(__file__).resolve()),
        "public_challenge_sha256": config["public_challenge_sha256"],
        "execution_plan_sha256": config["execution_plan_sha256"],
        "formula_plan_sha256": ledger["formula_plan_sha256"],
        "formula_plan_file_sha256": ledger["formula_plan_file_sha256"],
        "hash_ledger_sha256": P1._file_sha256(LEDGER_PATH),
        "phase2_solver_execution_started": False,
    }


def analyze() -> dict[str, Any]:
    config = _load_config()
    ledger = json.loads(LEDGER_PATH.read_bytes())
    if (
        ledger.get("schema")
        != "chacha20-round20-width20-split18-phase2-freeze-ledger-v1"
        or ledger.get("phase_id") != PHASE_ID
        or ledger.get("protocol_state")
        != "frozen_after_complete_phase1_and_before_any_phase2_solver_execution"
        or ledger.get("phase2_solver_execution_started") is not False
        or ledger.get("public_challenge_sha256")
        != config["public_challenge_sha256"]
        or ledger.get("execution_plan_sha256") != config["execution_plan_sha256"]
    ):
        raise RuntimeError("phase2 ledger identity gate failed")
    for relative, expected in ledger["artifacts"].items():
        if P1._file_sha256(P1.ROOT / relative) != expected:
            raise RuntimeError(f"phase2 frozen artifact differs: {relative}")
    phase1 = _phase1_gates(config)
    if phase1 != ledger["phase1_gates"]:
        raise RuntimeError("phase2 phase1 ledger gate differs")
    solver = P1._solver_identity({"solver_binary": config["solver_binary"]})
    if solver != ledger["solver_identity"]:
        raise RuntimeError("phase2 solver ledger differs")
    formulas, expected_plan = _formula_material(config)
    observed_plan = json.loads(FORMULA_PLAN_PATH.read_bytes())
    if (
        observed_plan != expected_plan
        or P1._canonical_sha256(observed_plan) != ledger["formula_plan_sha256"]
        or P1._file_sha256(FORMULA_PLAN_PATH) != ledger["formula_plan_file_sha256"]
    ):
        raise RuntimeError("phase2 formula plan differs from freeze")
    return {
        "config": config,
        "ledger": ledger,
        "phase1": phase1,
        "solver": solver,
        "formulas": formulas,
        "formula_plan": observed_plan,
        "solver_execution_started": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = P1.CryptoCausalBuilder(
        experiment="chacha20_round20_width20_split18_phase2_cut_frontier",
        parameters={
            "phase_id": PHASE_ID,
            "rounds": P1.ROUNDS,
            "split": SPLIT,
            "unknown_key_bits": P1.UNKNOWN_KEY_BITS,
            "partition_cells": P1.CELL_COUNT,
        },
    )
    ids = [
        "phase2-r20-complete-split19-boundary-anchor",
        "phase2-r20-frozen-split18-complete-cover",
        "phase2-r20-complete-numeric-cell-execution",
        "phase2-r20-independent-confirmation",
        "phase2-r20-controlled-cut-comparison",
    ]
    rows = [
        (
            "phase1:round20_split19_complete_all_unknown_boundary",
            "retain_phase1_byte_exactly_and_change_only_the_midstate_cut",
            "phase2:controlled_split18_question",
            "retained_complete_phase1_boundary",
            payload["phase1_gates"]["result_sha256"],
            {"phase1_gates": payload["phase1_gates"]},
        ),
        (
            "phase2:controlled_split18_question",
            "freeze_all_thirty_two_split18_prefix_cells_at_the_same_10s_budget",
            "phase2:complete_structural_split18_cover",
            "post_phase1_pre_solver_cut_freeze",
            payload["formula_plan_sha256"],
            {"formula_plan": payload["formula_plan"]},
        ),
        (
            "phase2:complete_structural_split18_cover",
            "execute_every_cell_in_numeric_order_without_secret_selection_or_early_stop",
            "phase2:complete_split18_execution",
            "complete_predeclared_cell_execution",
            payload["execution_sha256"],
            {"execution": payload["execution"]},
        ),
        (
            "phase2:complete_split18_execution",
            "recompute_every_SAT_model_over_eight_full_ChaCha20_blocks_and_control",
            "phase2:independently_confirmed_models",
            "independent_full_block_confirmation",
            payload["confirmation_sha256"],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "phase2:independently_confirmed_models",
            "compare_split18_against_byte_exact_split19_under_the_same_budget",
            "phase2:round20_cut_frontier_result",
            "controlled_cut_frontier",
            payload["comparison_sha256"],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(rows):
        trigger, mechanism, outcome, kind, source, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=[] if index == 0 else [ids[index - 1]],
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = P1.CryptoCausalReader(path)
    triplets = reader.triplets(include_inferred=False)
    if len(triplets) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("phase2 Causal provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(triplets),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze()
    observations = [
        P1._run_cell(
            variant=variant,
            formula=analysis["formulas"][variant],
            solver=analysis["solver"],
        )
        for variant in P1.VARIANTS
    ]
    if [row["variant"] for row in observations] != list(P1.VARIANTS):
        raise RuntimeError("phase2 did not execute every cell in numeric order")
    confirmations = [
        P1._confirm_model(
            analysis["config"]["public_challenge"],
            row["variant"],
            row["model"],
        )
        for row in observations
        if row["model"] is not None
    ]
    invalid = [
        row
        for row in confirmations
        if (
            not row["known_key_constraints_match"]
            or not row["all_blocks_match"]
            or row["control_first_block_match"]
            or row["output_bits_checked"] < 512
        )
    ]
    confirmed = [row for row in confirmations if row not in invalid]
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmed})
    statuses = {row["variant"]: row["status"] for row in observations}
    status_counts = {
        status: sum(value == status for value in statuses.values())
        for status in ("sat", "unsat", "unknown", "invalid", "external_timeout")
    }
    execution = {
        "variant_order": list(P1.VARIANTS),
        "complete_variant_plan_executed": len(observations) == P1.CELL_COUNT,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "independently_confirmed_model_count": len(confirmed),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
        "total_volatile_seconds": sum(row["volatile_seconds"] for row in observations),
    }
    prediction_retained = bool(recovered)
    comparisons = {
        "phase1_split": 19,
        "phase2_split": SPLIT,
        "same_public_challenge": True,
        "same_solver_budget_milliseconds_per_cell": P1.TIME_LIMIT_MS,
        "same_numeric_complete_partition": True,
        "only_changed_factor": "split19_to_split18",
        "phase1_status_counts": analysis["phase1"]["phase1_status_counts"],
        "phase2_status_counts": status_counts,
        "phase2_statuses": statuses,
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in observations),
        "partition_complete_and_disjoint_by_construction": True,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "phase2_prediction_retained": prediction_retained,
        "uniqueness_established": False,
        "uniqueness_boundary": (
            "Unknown cells are not UNSAT proofs, and one SAT response does not "
            "exclude further models in its cell."
        ),
        "prior_stronger_fullround_width_bits": 40,
        "phase2_unknown_width_bits": 20,
    }
    evidence_stage = (
        "PILOT_ROUND20_WIDTH20_SPLIT18_CUT_TRANSFER_MODEL_RECOVERY"
        if prediction_retained
        else "PILOT_ROUND20_WIDTH20_SPLIT18_CUT_FRONTIER_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "phase_id": PHASE_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Changing only the round20 midstate cut from split19 to split18 returned "
            "an independently confirmed model under the same complete partition and budget."
            if prediction_retained
            else "Changing only the round20 midstate cut from split19 to split18 left "
            "all thirty-two cells at the bounded solver frontier."
        ),
        "scope": (
            "Controlled post-phase1 cut frontier on the same fresh width20 standard "
            "ChaCha20 challenge; not a wider result than retained A184 width40 recovery."
        ),
        "parameters": {
            "rounds": P1.ROUNDS,
            "split": SPLIT,
            "unknown_key_bits": P1.UNKNOWN_KEY_BITS,
            "known_key_bits": P1.KNOWN_KEY_BITS,
            "partition_cells": P1.CELL_COUNT,
            "free_bits_per_cell": P1.FREE_BITS,
        },
        "phase1_gates": analysis["phase1"],
        "freeze": {
            "config_sha256": P1._file_sha256(CONFIG_PATH),
            "runner_sha256": P1._file_sha256(Path(__file__).resolve()),
            "formula_plan_file_sha256": P1._file_sha256(FORMULA_PLAN_PATH),
            "hash_ledger_sha256": P1._file_sha256(LEDGER_PATH),
        },
        "public_challenge": analysis["config"]["public_challenge"],
        "public_challenge_sha256": analysis["config"]["public_challenge_sha256"],
        "execution_plan": analysis["config"]["execution_plan"],
        "execution_plan_sha256": analysis["config"]["execution_plan_sha256"],
        "solver_identity": analysis["solver"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": P1._canonical_sha256(analysis["formula_plan"]),
        "execution": execution,
        "execution_sha256": P1._canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": P1._canonical_sha256(confirmations),
        "comparisons": comparisons,
        "comparison_sha256": P1._canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    P1._atomic_json(output, payload)
    reader = P1.CryptoCausalReader(causal_output)
    if reader.file_sha256 != causal["file_sha256"] or not reader.verify_provenance():
        raise RuntimeError("phase2 final Causal reopen gate failed")
    return {
        "json_sha256": P1._file_sha256(output),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": status_counts,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "total_volatile_seconds": execution["total_volatile_seconds"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=RESULT_PATH)
    parser.add_argument("--causal-output", type=Path, default=CAUSAL_PATH)
    args = parser.parse_args(argv)
    if args.freeze and args.analyze_only:
        raise ValueError("--freeze and --analyze-only are mutually exclusive")
    if args.freeze:
        print(json.dumps(freeze(), sort_keys=True))
        return
    if args.analyze_only:
        analysis = analyze()
        print(
            json.dumps(
                {
                    "config_sha256": P1._file_sha256(CONFIG_PATH),
                    "runner_sha256": P1._file_sha256(Path(__file__).resolve()),
                    "public_challenge_sha256": analysis["config"]["public_challenge_sha256"],
                    "execution_plan_sha256": analysis["config"]["execution_plan_sha256"],
                    "formula_plan_sha256": P1._canonical_sha256(analysis["formula_plan"]),
                    "formula_plan_file_sha256": P1._file_sha256(FORMULA_PLAN_PATH),
                    "hash_ledger_sha256": P1._file_sha256(LEDGER_PATH),
                    "formula_count": len(analysis["formulas"]),
                    "complete_domain_candidate_count": analysis["formula_plan"]["complete_domain_candidate_count"],
                    "solver_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal outputs must differ")
    print(
        json.dumps(
            run(output=args.output.resolve(), causal_output=args.causal_output.resolve()),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
