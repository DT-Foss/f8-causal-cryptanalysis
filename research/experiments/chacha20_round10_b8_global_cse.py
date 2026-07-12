#!/usr/bin/env python3
"""Global expression hash-consing across eight shared-key ChaCha10 SMT blocks."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A198 = _import_sibling(
    "chacha20_bitwuzla_round10_b8_partition_transfer.py",
    "chacha20_round10_cse_a198_anchor",
)
_A200 = _import_sibling(
    "chacha20_round10_public_geometry_partition.py",
    "chacha20_round10_cse_a200_anchor",
)
_A201 = _import_sibling(
    "chacha20_phase_conjugacy_holdout.py",
    "chacha20_round10_cse_a201_anchor",
)

ATTEMPT_ID = "A202"
SCHEMA = "chacha20-round10-b8-global-cse-v1"
PROTOCOL_SCHEMA = "chacha20-round10-b8-global-cse-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_b8_global_cse_v1.json"
PROTOCOL_SHA256 = "e6a26b56c855fa3931897e350f6b905f2f933cb3fbf88e2ca1cc72b7b45eef00"
A198_FILENAME = _A198.RESULT_FILENAME
A198_SHA256 = "693367464ab488c49d386c1d011e8c45e7fb094cceeb37352934dde121773373"
A198_CAUSAL_FILENAME = _A198.CAUSAL_FILENAME
A198_CAUSAL_SHA256 = "b7c4e1302594e266c7958057221fb4101fb5ef5ee284792d6ca93e43386dd514"
A200_FILENAME = _A200.RESULT_FILENAME
A200_SHA256 = "a945e95c63499d84cf0c41932dbe056b1eb39adbaf6d7a2096887e1b108d99ad"
A200_CAUSAL_FILENAME = _A200.CAUSAL_FILENAME
A200_CAUSAL_SHA256 = "1d1680e04a829139f74fae832a6498164b994c35e636458b2262f66f973f2c93"
A201_FILENAME = _A201.RESULT_FILENAME
A201_SHA256 = "c186da54770b520153f94b0b9f72e809d6b78d950a52bee39d74ea9c15194767"
A201_CAUSAL_FILENAME = _A201.CAUSAL_FILENAME
A201_CAUSAL_SHA256 = "adfb1e7e3390b67725587373dac8423b20a4873bd46a278bdd4d97ac672816d8"
PUBLIC_CHALLENGE_SHA256 = _A198.PUBLIC_CHALLENGE_SHA256
ORIGINAL_BASE_SHA256 = "9f315292550a671352c8b745d72e0a0be05da00ff7f9bed074bccc895e4255d8"
CSE_BASE_SHA256 = "c4cdc311248f25fe4dd41c687d46b38ea3ad1af1cd847b94d31418e1339a1035"
CSE_STATS_SHA256 = "e61b4b6b87ed141f420d3c78225b21feac46eefe4f8bc3738c054e9a55a0e162"
FORMULA_PLAN_SHA256 = "81d2468b21fa1296ce046303cc325fc7ef1e2cd4e4062a3ca7ec1d68b0275427"
FORMULA_HASH_LIST_SHA256 = "d998de7e253c174b3b80a0725e1a0b305664b9d2c1a4171779ce575ec7e3ef98"
EXECUTION_PLAN_SHA256 = "6dcba196f1bd064b52e5dcdb149d424ef13dcc4f3d5b9f33a9eb864a3762de06"
VARIANT_ORDER_SHA256 = "8e8e72eaffece56a66c150d0c96910d80f30c1435e92ddf65e39ac3072b1f1c3"
ROUNDS = 10
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
BLOCK_COUNT = 8
PREFIXES = tuple(f"{value:05b}" for value in range(32))
VARIANTS = tuple(f"cse_prefix_{prefix}" for prefix in PREFIXES)
FREE_BITS = 15
TIME_LIMIT_MS = 10_000
EXTERNAL_TIMEOUT_SLACK_SECONDS = 5
MAX_PARALLEL_WORKERS = 4
RESULT_FILENAME = "chacha20_round10_b8_global_cse_v1.json"
CAUSAL_FILENAME = "chacha20_round10_b8_global_cse_v1.causal"
DEFINITION_PATTERN = re.compile(r"^\(define-fun (v\d+) \(\) \(_ BitVec 32\) (.*)\)$")
LOCAL_TOKEN_PATTERN = re.compile(r"\bv\d+\b")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A198._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A198._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A202 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    compiler = protocol.get("compiler_plan", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A200_A201_and_global_CSE_derivation_before_any_A202_solver_execution"
        or protocol.get("execution_plan_sha256") != EXECUTION_PLAN_SHA256
        or protocol.get("variant_order_sha256") != VARIANT_ORDER_SHA256
        or compiler.get("original_base_sha256") != ORIGINAL_BASE_SHA256
        or compiler.get("cse_base_sha256") != CSE_BASE_SHA256
        or compiler.get("formula_plan_sha256") != FORMULA_PLAN_SHA256
        or compiler.get("reused_definition_occurrences") != 196
        or boundary.get("A202_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("cell_order_budget_or_CSE_rule_changed_after_any_A202_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
        or boundary.get("original_A198_cells_reexecuted") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
    ):
        raise RuntimeError("A202 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    specs = (
        (
            "A198",
            A198_FILENAME,
            A198_CAUSAL_FILENAME,
            A198_SHA256,
            A198_CAUSAL_SHA256,
            "ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_RETAINED",
        ),
        (
            "A200",
            A200_FILENAME,
            A200_CAUSAL_FILENAME,
            A200_SHA256,
            A200_CAUSAL_SHA256,
            "ROUND10_PUBLIC_GEOMETRY_COMPLETE_PARTITION_BOUNDARY_RETAINED",
        ),
        (
            "A201",
            A201_FILENAME,
            A201_CAUSAL_FILENAME,
            A201_SHA256,
            A201_CAUSAL_SHA256,
            "PUBLIC_CHACHA_PHASE_CONJUGACY_HOLDOUT_RETAINED",
        ),
    )
    retained = {}
    gates: dict[str, Any] = {}
    for label, result_name, causal_name, result_sha, causal_sha, stage in specs:
        result_path = results_dir / result_name
        causal_path = results_dir / causal_name
        if _file_sha256(result_path) != result_sha or _file_sha256(causal_path) != causal_sha:
            raise RuntimeError(f"A202 {label} anchor hash gate failed")
        result = json.loads(result_path.read_bytes())
        reader = CryptoCausalReader(causal_path)
        if (
            result.get("evidence_stage") != stage
            or reader.file_sha256 != causal_sha
            or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
            or not reader.verify_provenance()
        ):
            raise RuntimeError(f"A202 {label} anchor content gate failed")
        retained[label] = result
        gates.update(
            {
                f"{label}_result_sha256": result_sha,
                f"{label}_causal_sha256": causal_sha,
                f"{label}_causal_graph_sha256": reader.graph_sha256,
                f"{label}_causal_provenance_verified": True,
            }
        )
    if (
        retained["A198"].get("execution", {}).get("returned_model_count") != 0
        or retained["A200"].get("execution", {}).get("returned_model_count") != 0
        or retained["A201"].get("all_predictions_retained_in_every_batch") is not True
    ):
        raise RuntimeError("A202 retained representation-boundary gate failed")
    gates["A198_A200_complete_partition_boundaries_zero_models"] = True
    gates["A201_shared_public_operator_structure_retained"] = True
    return gates


def _block_formulas(challenge: dict[str, Any]) -> list[tuple[list[str], list[str], list[str]]]:
    old_rounds = _A198._A185.ROUNDS
    old_variants = _A198._A185.VARIANTS
    try:
        _A198._A185.ROUNDS = ROUNDS
        _A198._A185.VARIANTS = tuple(
            ["forward", "inverse", *[f"split{index}" for index in range(1, 10)]]
        )
        blocks = [
            _A198._A187._split_formula(_A198._A185._formula("split8", block, TIME_LIMIT_MS))
            for block in _A198._block_challenges(challenge)
        ]
    finally:
        _A198._A185.ROUNDS = old_rounds
        _A198._A185.VARIANTS = old_variants
    return blocks


def _global_cse_base(challenge: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    blocks = _block_formulas(challenge)
    header = [line for line in blocks[0][0] if not line.startswith("(set-option :timeout ")]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    header.extend(
        [
            f"(assert (= lo8 #x{challenge['known_key_word1'] & 0xFF:02x}))",
            (
                "(assert (= ((_ extract 31 20) k0) "
                f"#x{challenge['known_key_word0_upper12'] >> 20:03x}))"
            ),
        ]
    )

    expression_to_global: dict[str, str] = {}
    definitions = []
    assertions = []
    per_block = []
    for block_index in reversed(range(BLOCK_COUNT)):
        _, local_definitions, local_assertions = blocks[block_index]
        mapping: dict[str, str] = {}
        new_count = 0
        reused_count = 0
        for line in local_definitions:
            match = DEFINITION_PATTERN.fullmatch(line)
            if match is None:
                raise RuntimeError("A202 could not parse a local SMT definition")
            local_name, expression = match.groups()
            expression = LOCAL_TOKEN_PATTERN.sub(
                lambda token, mapping=mapping: mapping[token.group()], expression
            )
            if expression in expression_to_global:
                global_name = expression_to_global[expression]
                reused_count += 1
            else:
                global_name = f"g{len(definitions)}"
                expression_to_global[expression] = global_name
                definitions.append(f"(define-fun {global_name} () (_ BitVec 32) {expression})")
                new_count += 1
            mapping[local_name] = global_name
        assertions.extend(
            LOCAL_TOKEN_PATTERN.sub(lambda token, mapping=mapping: mapping[token.group()], line)
            for line in local_assertions
        )
        per_block.append(
            {
                "block_index": block_index,
                "new_definitions": new_count,
                "reused_definitions": reused_count,
            }
        )
    base = (
        "\n".join([*header, *definitions, *assertions, "(check-sat)", "(get-value (k0 lo8))"])
        + "\n"
    )
    original = _A198._base_formula(challenge)
    stats = {
        "original_base_bytes": len(original.encode()),
        "original_base_sha256": _sha256(original.encode()),
        "original_definition_count": 2560,
        "cse_base_bytes": len(base.encode()),
        "cse_base_sha256": _sha256(base.encode()),
        "cse_definition_count": len(definitions),
        "reused_definition_occurrences": 2560 - len(definitions),
        "byte_reduction": len(original.encode()) - len(base.encode()),
        "byte_reduction_fraction": round(1.0 - len(base.encode()) / len(original.encode()), 12),
        "per_block": per_block,
        "semantic_rule": (
            "reuse_only_byte_identical_expressions_after_exact_local_to_global_DAG_name_substitution"
        ),
    }
    if (
        stats["original_base_sha256"] != ORIGINAL_BASE_SHA256
        or stats["cse_base_sha256"] != CSE_BASE_SHA256
        or stats["original_base_bytes"] != 177158
        or stats["cse_base_bytes"] != 148714
        or stats["cse_definition_count"] != 2364
        or stats["reused_definition_occurrences"] != 196
        or _canonical_sha256(per_block) != CSE_STATS_SHA256
        or len(assertions) != 128
    ):
        raise RuntimeError("A202 global CSE compiler gate failed")
    return base, stats


def _formula(base: str, variant: str) -> str:
    match = re.fullmatch(r"cse_prefix_([01]{5})", variant)
    if match is None:
        raise ValueError(f"unknown A202 variant {variant}")
    prefix = match.group(1)
    assertion = f"(assert (= ((_ extract 19 15) k0) #b{prefix}))"
    return base.replace("(check-sat)", assertion + "\n(check-sat)")


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "deterministic_numeric_prefix_waves_external_solver",
        "external_timeout_slack_seconds_per_cell": EXTERNAL_TIMEOUT_SLACK_SECONDS,
        "formula_representation": (
            "portable_SMTLIB2_round10_split8_b8_global_hash_cons_shared_key_DAG"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "max_parallel_workers": MAX_PARALLEL_WORKERS,
        "partition_cell_count": 32,
        "partition_cell_free_bits": FREE_BITS,
        "partition_fixed_bits": 5,
        "partition_prefix_order": list(PREFIXES),
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "shared_key_block_count": BLOCK_COUNT,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        "target_output_bits_per_cell": BLOCK_COUNT * 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
        "wave_count": len(VARIANTS) // MAX_PARALLEL_WORKERS,
        "wave_size": MAX_PARALLEL_WORKERS,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = _A198._load_public_challenge()
    base, cse_stats = _global_cse_base(challenge)
    plan = _execution_plan()
    if _canonical_sha256(plan) != EXECUTION_PLAN_SHA256:
        raise RuntimeError("A202 execution plan hash differs from freeze")
    if _canonical_sha256(list(VARIANTS)) != VARIANT_ORDER_SHA256:
        raise RuntimeError("A202 variant order hash differs from freeze")
    formulas = {variant: _formula(base, variant) for variant in VARIANTS}
    formula_plan = [
        {
            "variant": variant,
            "prefix": variant[-5:],
            "fixed_key_coordinates": [19, 18, 17, 16, 15],
            "free_key_coordinates": list(reversed(range(15))),
            "candidate_count": 1 << FREE_BITS,
            "shared_key_block_count": BLOCK_COUNT,
            "target_output_bits": BLOCK_COUNT * 512,
            "block_definition_order": list(reversed(range(BLOCK_COUNT))),
            "original_definition_count": 2560,
            "cse_definition_count": 2364,
            "reused_definition_occurrences": 196,
            "bytes": len(formulas[variant].encode()),
            "sha256": _sha256(formulas[variant].encode()),
            "portable_smtlib2": True,
        }
        for variant in VARIANTS
    ]
    if (
        _canonical_sha256(formula_plan) != FORMULA_PLAN_SHA256
        or _canonical_sha256([row["sha256"] for row in formula_plan]) != FORMULA_HASH_LIST_SHA256
        or sum(row["candidate_count"] for row in formula_plan) != 1 << UNKNOWN_KEY_BITS
        or [row["prefix"] for row in formula_plan] != list(PREFIXES)
    ):
        raise RuntimeError("A202 formula plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "cse_stats": cse_stats,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _run_cell(variant: str, formula: str, identity: dict[str, Any]) -> dict[str, Any]:
    prefix = variant[-5:]
    prefix_value = int(prefix, 2)
    command = [
        identity["path"],
        "--lang",
        "smt2",
        "--time-limit",
        str(TIME_LIMIT_MS),
        "--produce-models",
        "--bv-output-format",
        "16",
        "--bv-solver",
        "bitblast",
        "--sat-solver",
        "cadical",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=TIME_LIMIT_MS / 1000 + EXTERNAL_TIMEOUT_SLACK_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = error.stdout or "", error.stderr or "", None
    status = next(
        (line for line in stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
        "invalid",
    )
    values = {
        name: int(raw, 16) for name, raw in re.findall(r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout)
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"A202 {variant} SAT model parse failed")
        if (values["k0"] >> FREE_BITS) & 0x1F != prefix_value:
            raise RuntimeError(f"A202 {variant} model violates its prefix cell")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low20": values["k0"] & LOW_MASK,
        }
    return {
        "variant": variant,
        "prefix": prefix,
        "candidate_count": 1 << FREE_BITS,
        "free_bits": FREE_BITS,
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "command": command,
        "status": status,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "model": model,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_b8_global_cse",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "cells": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a202-a198-a200-boundary",
        "chacha20-a202-a201-shared-operator-structure",
        "chacha20-a202-global-expression-hash-cons",
        "chacha20-a202-complete-cse-prefix-cover",
        "chacha20-a202-independent-model-confirmation",
        "chacha20-a202-prospective-cse-result",
    ]
    rows = [
        (
            "A198_A200:complete_round10_partition_covers_zero_models",
            "retain_partition_boundaries_without_reexecuting_original_formulas",
            "A202:compiler_representation_change_required",
            "retained_partition_representation_boundary",
            A200_CAUSAL_SHA256,
            [],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A202:compiler_representation_change_required",
            "use_A201_shared_column_diagonal_operator_structure_as_compiler_motivation",
            "A202:shared_multiblock_DAG_question",
            "public_operator_to_compiler_transfer",
            A201_CAUSAL_SHA256,
            [ids[0]],
            {"A201_causal_sha256": A201_CAUSAL_SHA256},
        ),
        (
            "A202:shared_multiblock_DAG_question",
            "reuse_only_exactly_identical_globalized_expressions_across_eight_blocks",
            "A202:2364_node_global_CSE_formula",
            "semantics_preserving_global_hash_cons",
            payload["cse_stats_sha256"],
            [ids[1]],
            {"cse_stats": payload["cse_stats"]},
        ),
        (
            "A202:2364_node_global_CSE_formula",
            "execute_all_32_numeric_prefix_cells_at_the_frozen_10s_budget",
            "A202:complete_global_CSE_execution",
            "complete_predeclared_CSE_cover",
            payload["execution_sha256"],
            [ids[2]],
            {"execution": payload["execution"]},
        ),
        (
            "A202:complete_global_CSE_execution",
            "recompute_every_model_over_all_4096_target_bits_and_control",
            "A202:independently_confirmed_CSE_models",
            "independent_eight_block_confirmation",
            payload["confirmation_sha256"],
            [ids[3]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A202:independently_confirmed_CSE_models",
            "apply_the_frozen_primary_and_secondary_CSE_rules",
            "A202:prospective_global_CSE_result",
            "prospective_global_CSE_transfer",
            payload["comparison_sha256"],
            [ids[4]],
            {"comparisons": payload["comparisons"]},
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
        raise RuntimeError("A202 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _A198._A197._A191._solver_gate(analysis["protocol"])
    observations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> dict[str, Any]:
            return _run_cell(variant, analysis["formulas"][variant], identity)

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        observations.extend(rows)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": list(wave),
                "statuses": [row["status"] for row in rows],
                "maximum_volatile_seconds": max(row["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A202 did not execute the complete variant plan")
    confirmations = [
        {
            "variant": row["variant"],
            "prefix": row["prefix"],
            **_A198._confirm_model(analysis["public_challenge"], row["model"]),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"]
        or not row["all_blocks_match"]
        or row["control_first_block_match"]
        or row["output_bits_checked"] != 4096
        for row in confirmations
    ):
        raise RuntimeError("A202 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    resolved = status_counts["sat"] + status_counts["unsat"]
    comparisons = {
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in observations),
        "partition_complete_and_disjoint_by_construction": True,
        "original_A198_prefix_cover_reexecuted": False,
        "original_A198_10s_prefix_status": "all_unknown",
        "original_definition_count": 2560,
        "cse_definition_count": 2364,
        "reused_definition_occurrences": 196,
        "status_counts": status_counts,
        "resolved_sat_plus_unsat_cell_count": resolved,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_prediction_retained": len(confirmations) >= 1,
        "secondary_prediction_retained": resolved >= 1,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "PROSPECTIVE_ROUND10_GLOBAL_CSE_RECOVERY_RETAINED"
        if comparisons["primary_prediction_retained"]
        else "ROUND10_GLOBAL_CSE_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A complete numeric-prefix cover tests exact global expression hash-consing "
            "across the eight shared-key reduced ChaCha10 blocks."
        ),
        "scope": (
            "Prospective reduced ChaCha10 width-20 partial-key compiler transfer over the "
            "unchanged A198 challenge and split8 semantics."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "prospective_predictions": analysis["protocol"]["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "cse_stats": analysis["cse_stats"],
        "cse_stats_sha256": _canonical_sha256(analysis["cse_stats"]),
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": EXECUTION_PLAN_SHA256,
        "solver_identity": identity,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": FORMULA_PLAN_SHA256,
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
    _A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A202 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": status_counts,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_prediction_retained": comparisons["primary_prediction_retained"],
        "secondary_prediction_retained": comparisons["secondary_prediction_retained"],
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
            "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
            "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
            "cse_stats": analysis["cse_stats"],
            "variants": len(analysis["formula_plan"]),
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
