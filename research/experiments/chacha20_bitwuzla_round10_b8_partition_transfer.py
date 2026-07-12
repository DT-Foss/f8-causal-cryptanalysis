#!/usr/bin/env python3
"""Prospective eight-block shared-key transfer at the ChaCha10 partition boundary."""

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


_A197 = _import_sibling(
    "chacha20_bitwuzla_round10_width12_refinement.py",
    "chacha20_round10_b8_a197_anchor",
)
_A188 = _import_sibling(
    "chacha20_bitwuzla_round5_transfer.py",
    "chacha20_round10_b8_a188_anchor",
)
_A187 = _A188._A187
_A185 = _A197._A185
_A119 = _A197._A119

ATTEMPT_ID = "A198"
SCHEMA = "chacha20-bitwuzla-round10-b8-partition-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round10-b8-partition-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.json"
PROTOCOL_SHA256 = "ea1e395dc3de59a59e203f47f668312b4ffc024da7044e3521ca010a2e95fa28"
A187_FILENAME = _A187.RESULT_FILENAME
A187_SHA256 = "ec00786b9e778b3914cc2594919da11b763cfffa72f71fa110c2c90dc8e9e3e3"
A187_CAUSAL_FILENAME = _A187.CAUSAL_FILENAME
A187_CAUSAL_SHA256 = "6c3eda1c3f84cac90bf04e63267728cd88581f73f85fe18e971e72caa67fd68d"
A188_FILENAME = _A188.RESULT_FILENAME
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A188_CAUSAL_FILENAME = _A188.CAUSAL_FILENAME
A188_CAUSAL_SHA256 = "a717e615cfc005fe985a24059f7e6bedcd8008c460b274bb313f6ddfc53e7c78"
A197_FILENAME = _A197.RESULT_FILENAME
A197_SHA256 = "177a76c130d3705e8e3ebcd35f517486b204c6f7d501adaae1cdba8dca90060c"
A197_CAUSAL_FILENAME = _A197.CAUSAL_FILENAME
A197_CAUSAL_SHA256 = "f180d14b244a91d5dcbe22acd4972590d9facfb8099ee8846fb3d0d5cae92561"
ATLAS_AUDIT_FILENAME = "formula_atlas_transfer_coverage_v1.json"
ATLAS_AUDIT_SHA256 = "feadca39a2cdb0caf38018e9d28ed6aecd56384f5771d7a6e6ab261f87ee1cc2"
A197_PROTOCOL_FILENAME = _A197.PROTOCOL_FILENAME
A197_PROTOCOL_SHA256 = _A197.PROTOCOL_SHA256
PUBLIC_CHALLENGE_SHA256 = _A197.PUBLIC_CHALLENGE_SHA256
EXECUTION_PLAN_SHA256 = "6965f67a341a3e234b51c3ddc8e0e375d12803d8f603feac80dd5bae980c78c3"
VARIANT_ORDER_SHA256 = "804a858c7605347f4d64bf81f62f7e77d956af16f6ce48dc46ba594e6c1103a7"
ROUNDS = 10
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
PARTITION_FIXED_BITS = 5
PARTITION_FREE_BITS = 15
BLOCK_COUNT = 8
BUDGETS_MS = (10_000, 30_000)
EXTERNAL_TIMEOUT_SLACK_SECONDS = 5
MAX_PARALLEL_WORKERS = 4
PREFIXES = tuple(f"{value:05b}" for value in range(32))
VARIANTS = tuple(f"b8_t{budget}_prefix_{prefix}" for budget in BUDGETS_MS for prefix in PREFIXES)
RESULT_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A197._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A197._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A198 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A197_boundary_and_formula_reaudit_before_any_A198_solver_execution"
        or protocol.get("anchors", {}).get("A187", {}).get("sha256") != A187_SHA256
        or protocol.get("anchors", {}).get("A188", {}).get("sha256") != A188_SHA256
        or protocol.get("anchors", {}).get("A197", {}).get("sha256") != A197_SHA256
        or protocol.get("anchors", {}).get("formula_atlas_reaudit", {}).get("sha256")
        != ATLAS_AUDIT_SHA256
        or protocol.get("execution_plan_sha256") != EXECUTION_PLAN_SHA256
        or protocol.get("variant_plan", {}).get("variant_order_sha256") != VARIANT_ORDER_SHA256
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A198_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("cell_budget_wave_or_formula_changed_after_any_A198_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A198 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    specs = (
        (
            "A187",
            A187_FILENAME,
            A187_CAUSAL_FILENAME,
            A187_SHA256,
            A187_CAUSAL_SHA256,
            _A187.SCHEMA,
            "PROSPECTIVE_SHARED_KEY_CAUSAL_STACKING_TRANSFER_RETAINED",
        ),
        (
            "A188",
            A188_FILENAME,
            A188_CAUSAL_FILENAME,
            A188_SHA256,
            A188_CAUSAL_SHA256,
            _A188.SCHEMA,
            "CROSS_ENGINE_ROUND5_RECOVERY_BOUNDARY_RETAINED",
        ),
        (
            "A197",
            A197_FILENAME,
            A197_CAUSAL_FILENAME,
            A197_SHA256,
            A197_CAUSAL_SHA256,
            _A197.SCHEMA,
            "ROUND10_WIDTH12_REFINEMENT_BOUNDARY_RETAINED",
        ),
    )
    gates: dict[str, Any] = {}
    retained: dict[str, dict[str, Any]] = {}
    for label, result_name, causal_name, result_sha, causal_sha, schema, stage in specs:
        result_path = results_dir / result_name
        causal_path = results_dir / causal_name
        if _file_sha256(result_path) != result_sha or _file_sha256(causal_path) != causal_sha:
            raise RuntimeError(f"A198 {label} anchor hash gate failed")
        result = json.loads(result_path.read_bytes())
        if result.get("schema") != schema or result.get("evidence_stage") != stage:
            raise RuntimeError(f"A198 {label} retained stage gate failed")
        reader = CryptoCausalReader(causal_path)
        if (
            reader.file_sha256 != causal_sha
            or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
            or not reader.verify_provenance()
        ):
            raise RuntimeError(f"A198 {label} Causal gate failed")
        retained[label] = result
        gates.update(
            {
                f"{label}_result_sha256": result_sha,
                f"{label}_causal_sha256": causal_sha,
                f"{label}_causal_graph_sha256": reader.graph_sha256,
                f"{label}_causal_provenance_verified": True,
            }
        )

    a187 = retained["A187"]
    a188 = retained["A188"]
    a197 = retained["A197"]
    a188_confirmations = a188.get("confirmations", [])
    if (
        a187.get("comparisons", {}).get("primary_prediction_retained") is not True
        or a187.get("comparisons", {}).get("full_b8") != {"conflicts": 389, "decisions": 1686}
        or len(a188_confirmations) != 1
        or a188_confirmations[0].get("variant") != "bitwuzla_bitblast_b8"
        or a188_confirmations[0].get("all_blocks_match") is not True
        or a188_confirmations[0].get("output_bits_checked") != 4096
        or a188_confirmations[0].get("control_first_block_match") is not False
        or a197.get("execution", {}).get("complete_variant_plan_executed") is not True
        or a197.get("execution", {}).get("returned_model_count") != 0
        or a197.get("comparisons", {}).get("complete_domain_candidate_count") != 1 << 20
        or set(a197.get("comparisons", {}).get("statuses", {}).values()) != {"unknown"}
    ):
        raise RuntimeError("A198 retained mechanism/boundary gate failed")

    atlas_path = results_dir / ATLAS_AUDIT_FILENAME
    if _file_sha256(atlas_path) != ATLAS_AUDIT_SHA256:
        raise RuntimeError("A198 formula-atlas audit hash gate failed")
    atlas = json.loads(atlas_path.read_bytes())
    if (
        atlas.get("schema") != "formula-atlas-transfer-coverage-v1"
        or atlas.get("summary", {}).get("entries") != 2411
        or atlas.get("summary", {}).get("pages") != 113
        or atlas.get("method", {}).get("formula_entries_dropped") != 0
    ):
        raise RuntimeError("A198 formula-atlas audit coverage gate failed")
    gates["formula_atlas_reaudit_sha256"] = ATLAS_AUDIT_SHA256
    gates["mechanism_and_boundary_anchors_retained"] = True
    return gates


def _load_public_challenge() -> dict[str, Any]:
    config_path = Path(__file__).parents[1] / "configs" / A197_PROTOCOL_FILENAME
    if _file_sha256(config_path) != A197_PROTOCOL_SHA256:
        raise RuntimeError("A198 A197 challenge protocol hash gate failed")
    challenge = json.loads(config_path.read_bytes())["public_challenge"]
    _A197._validate_public_challenge(challenge)
    return challenge


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": (
            "deterministic_budget_major_numeric_waves_external_solver_two_complete_prefix_covers"
        ),
        "external_timeout_slack_seconds_per_cell": EXTERNAL_TIMEOUT_SLACK_SECONDS,
        "formula_representation": (
            "portable_SMTLIB2_round10_split8_b8_shared_key_complete_5bit_prefix_partition"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "max_parallel_workers": MAX_PARALLEL_WORKERS,
        "partition_cell_count_per_budget": 32,
        "partition_cell_free_bits": PARTITION_FREE_BITS,
        "partition_fixed_bits": PARTITION_FIXED_BITS,
        "partition_prefix_order": list(PREFIXES),
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "shared_key_block_count": BLOCK_COUNT,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limits_milliseconds": list(BUDGETS_MS),
        "target_output_bits_per_cell": BLOCK_COUNT * 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
        "wave_count": len(VARIANTS) // MAX_PARALLEL_WORKERS,
        "wave_size": MAX_PARALLEL_WORKERS,
    }


def _variant_spec(variant: str) -> tuple[int, str, int]:
    match = re.fullmatch(r"b8_t(10000|30000)_prefix_([01]{5})", variant)
    if match is None:
        raise ValueError(f"unknown A198 variant {variant}")
    raw_budget, prefix = match.groups()
    return int(raw_budget), prefix, int(prefix, 2)


def _block_challenges(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "rounds": ROUNDS,
            "known_key_word1_upper24": challenge["known_key_word1"] & 0xFFFFFF00,
            "known_key_words_2_through_7": challenge["known_key_words_2_through_7"],
            "counter": (challenge["counter_start"] + index) & 0xFFFFFFFF,
            "nonce_words": challenge["nonce_words"],
            "target_words": target,
        }
        for index, target in enumerate(challenge["target_words"])
    ]


def _base_formula(challenge: dict[str, Any]) -> str:
    old_rounds = _A185.ROUNDS
    old_variants = _A185.VARIANTS
    try:
        _A185.ROUNDS = ROUNDS
        _A185.VARIANTS = tuple(["forward", "inverse", *[f"split{i}" for i in range(1, 10)]])
        parsed = [
            _A187._split_formula(_A185._formula("split8", block, BUDGETS_MS[0]))
            for block in _block_challenges(challenge)
        ]
    finally:
        _A185.ROUNDS = old_rounds
        _A185.VARIANTS = old_variants

    header = [line for line in parsed[0][0] if not line.startswith("(set-option :timeout ")]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    lines = header
    lines.append(f"(assert (= lo8 #x{challenge['known_key_word1'] & 0xFF:02x}))")
    lines.append(
        f"(assert (= ((_ extract 31 20) k0) #x{challenge['known_key_word0_upper12'] >> 20:03x}))"
    )
    for block_index in reversed(range(BLOCK_COUNT)):
        _, definitions, assertions = parsed[block_index]
        if len(assertions) != 16:
            raise RuntimeError("A198 block formula does not expose 16 output assertions")
        lines.extend(_A187._rename_block([*definitions, *assertions], block_index))
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def _formula(base: str, variant: str) -> str:
    _, prefix, _ = _variant_spec(variant)
    assertion = f"(assert (= ((_ extract 19 15) k0) #b{prefix}))"
    return base.replace("(check-sat)", assertion + "\n(check-sat)")


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = _load_public_challenge()
    plan = _execution_plan()
    if _canonical_sha256(plan) != EXECUTION_PLAN_SHA256:
        raise RuntimeError("A198 execution plan hash differs from freeze")
    if _canonical_sha256(list(VARIANTS)) != VARIANT_ORDER_SHA256:
        raise RuntimeError("A198 variant order hash differs from freeze")
    base = _base_formula(challenge)
    formulas = {variant: _formula(base, variant) for variant in VARIANTS}
    formula_plan = []
    for variant in VARIANTS:
        budget, prefix, _ = _variant_spec(variant)
        formula = formulas[variant]
        formula_plan.append(
            {
                "variant": variant,
                "budget_milliseconds": budget,
                "prefix": prefix,
                "fixed_key_coordinates": [19, 18, 17, 16, 15],
                "free_key_coordinates": list(reversed(range(15))),
                "candidate_count": 1 << PARTITION_FREE_BITS,
                "shared_key_block_count": BLOCK_COUNT,
                "target_output_bits": BLOCK_COUNT * 512,
                "block_definition_order": list(reversed(range(BLOCK_COUNT))),
                "bytes": len(formula.encode()),
                "sha256": _sha256(formula.encode()),
                "portable_smtlib2": True,
            }
        )
    for budget in BUDGETS_MS:
        rows = [row for row in formula_plan if row["budget_milliseconds"] == budget]
        if sum(row["candidate_count"] for row in rows) != 1 << UNKNOWN_KEY_BITS or [
            row["prefix"] for row in rows
        ] != list(PREFIXES):
            raise RuntimeError(f"A198 {budget}ms complete partition coverage gate failed")
    first = formula_plan[:32]
    second = formula_plan[32:]
    if [row["sha256"] for row in first] != [row["sha256"] for row in second]:
        raise RuntimeError("A198 formulas differ across solver budgets")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _run_cell(variant: str, formula: str, identity: dict[str, Any]) -> dict[str, Any]:
    budget, prefix, prefix_value = _variant_spec(variant)
    command = [
        identity["path"],
        "--lang",
        "smt2",
        "--time-limit",
        str(budget),
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
            timeout=budget / 1000 + EXTERNAL_TIMEOUT_SLACK_SECONDS,
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
            raise RuntimeError(f"A198 {variant} SAT model parse failed")
        if values["k0"] >> PARTITION_FREE_BITS & 0x1F != prefix_value:
            raise RuntimeError(f"A198 {variant} model violates its partition cell")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low20": values["k0"] & LOW_MASK,
        }
    return {
        "variant": variant,
        "budget_milliseconds": budget,
        "prefix": prefix,
        "free_bits": PARTITION_FREE_BITS,
        "candidate_count": 1 << PARTITION_FREE_BITS,
        "shared_key_block_count": BLOCK_COUNT,
        "target_output_bits": BLOCK_COUNT * 512,
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


def _confirm_model(challenge: dict[str, Any], model: dict[str, int]) -> dict[str, Any]:
    initial = np.zeros((1, 16), dtype=np.uint32)
    initial[0, :4] = _A119.CONSTANTS
    initial[0, 4] = np.uint32(model["key_word0"])
    initial[0, 5] = np.uint32(challenge["known_key_word1"])
    initial[0, 6:12] = np.array(challenge["known_key_words_2_through_7"], dtype=np.uint32)
    initial[0, 13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    matches = []
    hashes = []
    for block_index, target_words in enumerate(challenge["target_words"]):
        initial[0, 12] = np.uint32((challenge["counter_start"] + block_index) & 0xFFFFFFFF)
        output = (_A119._core(initial.copy(), ROUNDS) + initial).astype(np.uint32)
        target = np.array(target_words, dtype=np.uint32).reshape(1, 16)
        matches.append(bool(np.array_equal(output, target)))
        hashes.append(_sha256(output.astype("<u4").tobytes()))
    return {
        **model,
        "known_key_constraints_match": (
            model["key_word0"] & ~LOW_MASK == challenge["known_key_word0_upper12"]
            and model["key_word1_low_value"] == challenge["known_key_word1"] & 0xFF
        ),
        "block_count_checked": BLOCK_COUNT,
        "block_matches": matches,
        "all_blocks_match": all(matches),
        "candidate_block_sha256": hashes,
        "control_first_block_match": hashes[0] == challenge["control_target_block_sha256"],
        "output_bits_checked": BLOCK_COUNT * 512,
        "implementation": "independent_NumPy_ChaCha10_eight_blocks",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round10_b8_partition_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "variants": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a198-a187-a188-stacking-mechanism",
        "chacha20-a198-a197-round10-refinement-boundary",
        "chacha20-a198-still-secret-round10-challenge",
        "chacha20-a198-b8-two-budget-complete-partitions",
        "chacha20-a198-complete-wave-execution",
        "chacha20-a198-independent-eight-block-confirmation",
        "chacha20-a198-prospective-depth-transfer",
    ]
    evidence = [
        (
            "A187_A188:shared_key_b8_search_shape_and_recovery",
            "anchor_the_confirmed_eight_block_mechanism",
            "A198:round10_b8_depth_transfer_question",
            "retained_shared_key_stacking_mechanism",
            A188_CAUSAL_SHA256,
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A198:round10_b8_depth_transfer_question",
            "anchor_the_complete_A197_width12_zero_model_boundary",
            "A198:representation_change_requirement",
            "retained_round10_refinement_boundary",
            A197_CAUSAL_SHA256,
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A198:representation_change_requirement",
            "reuse_the_byte_identical_still_secret_round10_challenge",
            "A198:still_secret_round10_width20_challenge",
            "same_challenge_zero_model_boundary",
            PUBLIC_CHALLENGE_SHA256,
            {"public_challenge": payload["public_challenge"]},
        ),
        (
            "A198:still_secret_round10_width20_challenge",
            "compile_all_eight_targets_into_each_of_two_complete_prefix_covers",
            "A198:b8_two_budget_complete_formula_plan",
            "shared_key_stacked_complete_partitions",
            payload["formula_plan_sha256"],
            {"formula_plan": payload["formula_plan"]},
        ),
        (
            "A198:b8_two_budget_complete_formula_plan",
            "execute_all_sixteen_waves_without_early_stop",
            "A198:complete_two_budget_execution",
            "complete_predeclared_wave_execution",
            payload["execution_sha256"],
            {"execution": payload["execution"]},
        ),
        (
            "A198:complete_two_budget_execution",
            "recompute_each_model_over_all_4096_target_bits_and_control",
            "A198:independently_confirmed_b8_models",
            "independent_eight_block_confirmation",
            payload["confirmation_sha256"],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A198:independently_confirmed_b8_models",
            "apply_the_predeclared_10s_and_30s_success_rules",
            "A198:prospective_shared_key_depth_result",
            "prospective_shared_key_stacking_depth_transfer",
            payload["comparison_sha256"],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(evidence):
        trigger, mechanism, outcome, kind, source, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=[] if index < 2 else [ids[index - 1]],
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected = [[], [], *[[ids[index - 1]] for index in range(2, len(ids))]]
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or [by_id[edge_id]["provenance"] for edge_id in ids] != expected
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A198 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _A197._A191._solver_gate(analysis["protocol"])
    observations = []
    wave_observations = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> dict[str, Any]:
            return _run_cell(variant, analysis["formulas"][variant], identity)

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        observations.extend(rows)
        wave_observations.append(
            {
                "wave_index": wave_index,
                "variants": list(wave),
                "statuses": [row["status"] for row in rows],
                "maximum_volatile_seconds": max(row["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A198 did not execute the complete variant plan")
    confirmations = [
        {
            "variant": row["variant"],
            "budget_milliseconds": row["budget_milliseconds"],
            "prefix": row["prefix"],
            **_confirm_model(analysis["public_challenge"], row["model"]),
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
        raise RuntimeError("A198 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    budget_results: dict[str, Any] = {}
    for budget in BUDGETS_MS:
        rows = [row for row in observations if row["budget_milliseconds"] == budget]
        confirmed = [row for row in confirmations if row["budget_milliseconds"] == budget]
        budget_results[str(budget)] = {
            "complete_domain_candidate_count": sum(row["candidate_count"] for row in rows),
            "complete_partition_executed": len(rows) == 32,
            "confirmed_variants": [row["variant"] for row in confirmed],
            "fully_confirmed_unknown_low20_assignments": sorted(
                {row["recovered_unknown_low20"] for row in confirmed}
            ),
            "prediction_retained": len(confirmed) >= 1,
            "statuses": {row["variant"]: row["status"] for row in rows},
        }
    comparisons = {
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "complete_domain_covered_once_per_budget": True,
        "partition_complete_and_disjoint_by_construction": True,
        "shared_key_block_count": BLOCK_COUNT,
        "target_output_bits_per_cell": BLOCK_COUNT * 512,
        "same_formula_bytes_across_budgets": (
            [row["formula_sha256"] for row in observations[:32]]
            == [row["formula_sha256"] for row in observations[32:]]
        ),
        "budget_results": budget_results,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_30000ms_prediction_retained": budget_results["30000"]["prediction_retained"],
        "secondary_10000ms_prediction_retained": budget_results["10000"]["prediction_retained"],
    }
    prediction_retained = comparisons["primary_30000ms_prediction_retained"]
    evidence_stage = (
        "PROSPECTIVE_ROUND10_B8_COMPLETE_PARTITION_RECOVERY_RETAINED"
        if prediction_retained
        else "ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": wave_observations,
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
            "Two complete shared-key eight-block partition covers test the retained "
            "stacking mechanism at the still-secret reduced ChaCha10 width-20 boundary."
        ),
        "scope": (
            "Prospective reduced ChaCha10 partial-key depth transfer over the unchanged "
            "2^20 domain, represented as 32 disjoint width-15 cells at each of two budgets."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "target_output_bits_per_cell": BLOCK_COUNT * 512,
            "partition_cells_per_budget": 32,
            "free_bits_per_cell": PARTITION_FREE_BITS,
            "budgets_milliseconds": list(BUDGETS_MS),
            "variants": list(VARIANTS),
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "mechanism_basis": analysis["protocol"]["mechanism_basis"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "challenge_reuse_boundary": analysis["protocol"]["challenge_reuse_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": EXECUTION_PLAN_SHA256,
        "solver_identity": identity,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
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
    _A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A198 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "comparisons": comparisons,
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
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
                    "execution_plan_sha256": EXECUTION_PLAN_SHA256,
                    "formula_plan": analysis["formula_plan"],
                    "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
                    "solver_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal outputs must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
