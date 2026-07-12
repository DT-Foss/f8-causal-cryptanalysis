#!/usr/bin/env python3
"""Prospective complete-domain SHAKE256 full-round reconstruction at width 32."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
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


_A176 = _import_sibling(
    "shake_symbolic_r2_input_declaration_swap_boundary.py",
    "shake256_width32_a176_anchor",
)
_A165 = _import_sibling(
    "shake_a152_native_fullround_reader_transfer.py",
    "shake256_width32_a165_native_base",
)
_NATIVE = _A165._NATIVE
_BASE = _A165._BASE
_WINDOW = _A165._WINDOW
_BITSLICED = _A165._BITSLICED

ATTEMPT_ID = "A177"
SCHEMA = "shake256-native-fullround-width32-prospective-v1"
PROTOCOL_SCHEMA = "shake256-native-fullround-width32-prospective-protocol-v1"
PROTOCOL_FILENAME = "shake256_native_fullround_width32_prospective_v1.json"
PROTOCOL_SHA256 = "f4e3ee4b43a536d7ccf51964de768953019ecf96819f661a50edaa549d6db068"
A176_FILENAME = _A176.RESULT_FILENAME
A176_SHA256 = "4b609a6f4388c9a759625169aebe94309b808608e061b4f033c66a22cc992a60"
A176_RESULT_SHA256 = "69055a782b8db1102d136004a7719a05fbd5c10fd918c2b8ff7a8f90321b727a"
NATIVE_FILENAME = _A165.NATIVE_FILENAME
NATIVE_SHA256 = _A165.NATIVE_SHA256
NATIVE_CAUSAL_FILENAME = _A165.NATIVE_CAUSAL_FILENAME
NATIVE_CAUSAL_SHA256 = _A165.NATIVE_CAUSAL_SHA256
NATIVE_SOURCE_SHA256 = _A165.NATIVE_SOURCE_SHA256
DERIVATION_LABEL = f"f8-causal:A177:shake256:32:{A176_SHA256}"
DERIVATION_SHA256 = "287f1840310ee763cceb6275e07ccf081c01681ce034493db880036d3894fbcc"
SEED = 679_417_920
VARIANT_KEY = "shake256"
WINDOW_BITS = 32
THREADS = 10
STREAM_PACKS = 1 << 20
FILTER_LANES = 2
RESULT_FILENAME = "shake256_native_fullround_width32_prospective_v1.json"
CAUSAL_FILENAME = "shake256_native_fullround_width32_prospective_v1.causal"
CHECKPOINT_FILENAME = "shake256_native_fullround_width32_prospective_v1.checkpoint.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A165._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A165._file_sha256(path)


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    a176_path = results_dir / A176_FILENAME
    native_path = results_dir / NATIVE_FILENAME
    native_causal_path = results_dir / NATIVE_CAUSAL_FILENAME
    source_path = Path(__file__).with_name("shake_bitsliced_native.c")
    observed = {
        "A176_result_sha256": _file_sha256(a176_path),
        "native_result_sha256": _file_sha256(native_path),
        "native_causal_sha256": _file_sha256(native_causal_path),
        "native_source_sha256": _file_sha256(source_path),
    }
    expected = {
        "A176_result_sha256": A176_SHA256,
        "native_result_sha256": NATIVE_SHA256,
        "native_causal_sha256": NATIVE_CAUSAL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A177 A176/native anchor hash gate failed")

    a176 = json.loads(a176_path.read_bytes())
    native = json.loads(native_path.read_bytes())
    if (
        a176.get("schema") != _A176.SCHEMA
        or a176.get("declaration_boundary_result_sha256") != A176_RESULT_SHA256
        or a176.get("declaration_boundary_result", {}).get("classification")
        != "exact_input_declaration_order_invariance"
        or a176.get("declaration_boundary_result", {}).get(
            "all_four_canonical_observations_exactly_equal"
        )
        is not True
        or native.get("schema") != "shake-native-window-solver-v1"
        or native.get("retained") is not True
        or native.get("native_build", {}).get("source_sha256") != NATIVE_SOURCE_SHA256
        or native.get("parameters", {}).get("permutation_rounds") != 24
        or 28 not in native.get("parameters", {}).get("window_bits", [])
    ):
        raise RuntimeError("A177 retained A176/native mechanism gate failed")

    shake256_rows = native.get("confirmation", {}).get("shake256", [])
    width28 = [row for row in shake256_rows if row.get("window_bits") == 28]
    if (
        len(width28) != 1
        or width28[0].get("unique_exact_consistency") is not True
        or width28[0].get("wrong_target_rejected") is not True
    ):
        raise RuntimeError("A177 retained SHAKE256 width-28 frontier gate failed")

    reader = CryptoCausalReader(native_causal_path)
    rows = reader.triplets(include_inferred=False)
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_executable_native_fullround_consistency"
        and row["trigger"].startswith("shake256:")
    ]
    if (
        reader.file_sha256 != NATIVE_CAUSAL_SHA256
        or not reader.verify_provenance()
        or len(recipes) != 1
    ):
        raise RuntimeError("A177 native Causal Reader gate failed")
    recipe = recipes[0]
    if (
        recipe.get("variant") != "SHAKE256"
        or recipe.get("native_source_sha256") != NATIVE_SOURCE_SHA256
        or recipe.get("permutation_rounds") != 24
        or recipe.get("candidates_per_machine_word") != 64
        or recipe.get("filter_lanes") != FILTER_LANES
        or recipe.get("full_confirmation") != "independent_scalar_complete_rate_equality"
    ):
        raise RuntimeError("A177 SHAKE256 native recipe differs")
    return {
        **observed,
        "A176_result_sha256": A176_SHA256,
        "A176_mechanism_sha256": A176_RESULT_SHA256,
        "native_causal_graph_sha256": reader.graph_sha256,
        "native_causal_provenance_verified": True,
        "retained_SHAKE256_width28_assignment": width28[0]["factual_full_matches"],
        "native_reader_recipe": recipe,
    }


def _public_relation_summary(
    template: np.ndarray,
    target: np.ndarray,
    positions: np.ndarray,
    message: np.ndarray,
    variant: Any,
) -> dict[str, Any]:
    control = target.copy()
    control[0, 0] ^= np.uint64(1)
    return {
        "variant": variant.name,
        "seed": SEED,
        "seed_derivation_label": DERIVATION_LABEL,
        "seed_derivation_sha256": DERIVATION_SHA256,
        "window_bits": WINDOW_BITS,
        "capacity_window_positions": [int(value) for value in positions],
        "capacity_window_positions_sha256": _sha256(positions.astype("<u2", copy=False).tobytes()),
        "capacity_window_start_bit": int(positions[0]),
        "capacity_window_stop_bit_exclusive": int(positions[-1]) + 1,
        "cleared_template_sha256": _sha256(template.astype("<u8", copy=False).tobytes()),
        "message_sha256": _sha256(message.tobytes()),
        "target_rate_lanes": variant.rate_lanes,
        "target_rate_bits": variant.rate_bits,
        "target_rate_sha256": _sha256(
            target[:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
        ),
        "control_target_rule": "flip_bit_0_of_first_public_target_rate_lane",
        "control_target_rate_sha256": _sha256(
            control[:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
        ),
        "instrumented_assignment_included": False,
    }


def _execution_plan() -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    pack_count = candidate_count // 64
    return {
        "variant": "SHAKE256",
        "permutation_rounds": 24,
        "window_bits": WINDOW_BITS,
        "logical_candidate_count": candidate_count,
        "candidates_per_machine_word": 64,
        "packed_state_count": pack_count,
        "native_threads": THREADS,
        "stream_pack_count": STREAM_PACKS,
        "stream_batch_count": pack_count // STREAM_PACKS,
        "maximum_mask_memory_bytes": STREAM_PACKS * 16,
        "filter_rate_lanes": FILTER_LANES,
        "filter_rate_bits": FILTER_LANES * 64,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "full_confirmation": "independent_NumPy_lane_core_all_1088_rate_bits",
        "control_target_required": True,
        "wallclock_excluded_from_canonical_result": True,
    }


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A177 frozen protocol hash differs")
    protocol = json.loads(raw)
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A177_candidate_execution"
        or protocol.get("anchors", {}).get("A176", {}).get("sha256") != A176_SHA256
        or protocol.get("anchors", {}).get("native_reader", {}).get("sha256") != NATIVE_SHA256
        or protocol.get("public_relation", {}).get("variant") != "SHAKE256"
        or protocol.get("public_relation", {}).get("window_bits") != WINDOW_BITS
        or protocol.get("execution_plan", {}).get("complete_domain_required") is not True
        or protocol.get("information_boundary", {}).get(
            "A177_candidate_outcomes_used_before_protocol_freeze"
        )
        is not False
    ):
        raise RuntimeError("A177 frozen protocol identity gate failed")
    return protocol


def _prepare_public_relation(
    protocol: dict[str, Any],
) -> tuple[dict[str, np.ndarray], dict[str, Any], dict[str, Any]]:
    variant = _BASE.VARIANTS[VARIANT_KEY]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    public = {
        "template": problem["template"].copy(),
        "target": problem["target"].copy(),
        "positions": problem["positions"].copy(),
    }
    summary = _public_relation_summary(
        public["template"],
        public["target"],
        public["positions"],
        problem["message"],
        variant,
    )
    frozen = protocol["public_relation"]
    if summary != frozen:
        raise RuntimeError("A177 regenerated public relation differs from freeze")
    plan = _execution_plan()
    if protocol["execution_plan"] != plan or protocol["execution_plan_sha256"] != _canonical_sha256(
        plan
    ):
        raise RuntimeError("A177 regenerated execution plan differs from freeze")
    return public, summary, problem


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    public, summary, problem = _prepare_public_relation(protocol)
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public": public,
        "public_relation": summary,
        "problem": problem,
        "execution_plan": _execution_plan(),
        "candidate_execution_started": False,
    }


def _draft_analysis(results_dir: Path) -> dict[str, Any]:
    anchors = _load_anchor_gates(results_dir)
    variant = _BASE.VARIANTS[VARIANT_KEY]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    public = {
        "template": problem["template"].copy(),
        "target": problem["target"].copy(),
        "positions": problem["positions"].copy(),
    }
    return {
        "anchor_gates": anchors,
        "public_relation": _public_relation_summary(
            public["template"],
            public["target"],
            public["positions"],
            problem["message"],
            variant,
        ),
        "execution_plan": _execution_plan(),
        "execution_plan_sha256": _canonical_sha256(_execution_plan()),
        "candidate_execution_started": False,
    }


def _checkpoint_fingerprint(
    public_relation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "shake256-native-width32-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "seed": SEED,
        "window_bits": WINDOW_BITS,
        "positions_sha256": public_relation["capacity_window_positions_sha256"],
        "cleared_template_sha256": public_relation["cleared_template_sha256"],
        "target_rate_sha256": public_relation["target_rate_sha256"],
        "control_target_rate_sha256": public_relation["control_target_rate_sha256"],
        "threads": THREADS,
        "stream_packs": STREAM_PACKS,
    }


def _enumerate_public_relation(
    *,
    kernel: Any,
    public: dict[str, np.ndarray],
    public_relation: dict[str, Any],
    variant: Any,
    recipe: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    positions = public["positions"]
    template = public["template"]
    target = public["target"]
    candidate_count = 1 << WINDOW_BITS
    pack_count = candidate_count // 64
    if (
        recipe["variant"] != "SHAKE256"
        or recipe["permutation_rounds"] != 24
        or recipe["candidates_per_machine_word"] != 64
        or recipe["filter_lanes"] != FILTER_LANES
        or len(positions) != WINDOW_BITS
    ):
        raise RuntimeError("A177 executable Reader plan differs")

    next_pack = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = _checkpoint_fingerprint(public_relation)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A177 checkpoint fingerprint differs")
        next_pack = int(checkpoint["next_pack"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        if (
            next_pack < 0
            or next_pack > pack_count
            or next_pack % STREAM_PACKS != 0
            or any(value < 0 or value >= next_pack * 64 for value in factual_filtered)
            or any(value < 0 or value >= next_pack * 64 for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A177 checkpoint progress is invalid")

    control_target = _A165._control_target(target)
    resumed_pack_count = next_pack
    while next_pack < pack_count:
        batch_count = min(STREAM_PACKS, pack_count - next_pack)
        factual_masks, control_masks = kernel.filter_masks(
            template,
            variant.rate_lanes,
            positions,
            WINDOW_BITS,
            next_pack,
            batch_count,
            target,
            control_target,
            FILTER_LANES,
            THREADS,
        )
        factual_filtered.extend(
            _BITSLICED._indices_from_masks(
                factual_masks,
                next_pack,
                candidate_count,
            )
        )
        control_filtered.extend(
            _BITSLICED._indices_from_masks(
                control_masks,
                next_pack,
                candidate_count,
            )
        )
        next_pack += batch_count
        _NATIVE._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_pack": next_pack,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
            },
        )
        print(f"A177 native packs={next_pack}/{pack_count}", flush=True)

    factual_confirmations = [
        _A165._independent_confirm(
            template,
            target,
            positions,
            variant,
            candidate,
        )
        for candidate in factual_filtered
    ]
    control_confirmations = [
        _A165._independent_confirm(
            template,
            control_target,
            positions,
            variant,
            candidate,
        )
        for candidate in control_filtered
    ]
    factual_full = [
        row["assignment"] for row in factual_confirmations if row["complete_rate_match"]
    ]
    control_full = [
        row["assignment"] for row in control_confirmations if row["complete_rate_match"]
    ]
    if not factual_full:
        raise RuntimeError("A177 complete-domain Reader returned no exact public model")
    return {
        "window_bits": WINDOW_BITS,
        "logical_candidate_count": candidate_count,
        "candidate_pack_width": 64,
        "packed_state_count": pack_count,
        "native_threads": THREADS,
        "stream_pack_count": STREAM_PACKS,
        "stream_batch_count": pack_count // STREAM_PACKS,
        "resumed_pack_count": resumed_pack_count,
        "newly_executed_pack_count": pack_count - resumed_pack_count,
        "complete_domain_executed": next_pack == pack_count,
        "early_stop_used": False,
        "filter_rate_lanes": FILTER_LANES,
        "filter_rate_bits": FILTER_LANES * 64,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_target_rule": "flip_bit_0_of_first_public_target_rate_lane",
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_public_model": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "packed_evaluation_reduction_factor": candidate_count / pack_count,
        "instrumented_assignment_input_used": False,
        "posthoc_assignment_read_before_candidate_execution": False,
    }


def _posthoc_after_execution(
    problem: dict[str, Any],
    recovered: list[int],
) -> dict[str, Any]:
    variant = _BASE.VARIANTS[VARIANT_KEY]
    actual = _WINDOW._extract_window(
        problem["base_state"],
        variant,
        problem["positions"],
    )
    independent = _A165._independent_confirm(
        problem["template"],
        problem["target"],
        problem["positions"],
        variant,
        actual,
    )
    return {
        "instrumented_assignment": actual,
        "read_only_after_complete_domain_execution": True,
        "used_for_candidate_generation_filtering_or_confirmation": False,
        "recovered_assignments": recovered,
        "unique_reconstruction_matches_instrumented_assignment": recovered == [actual],
        "instrumented_assignment_independent_check": independent,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake256_native_fullround_width32_prospective",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake256",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "logical_candidates": 1 << WINDOW_BITS,
            "native_threads": THREADS,
        },
    )
    ids = [
        "shake256-a176-derived-width32-public-freeze",
        "shake256-retained-native-fullround-reader-recipe",
        "shake256-a177-complete-packed-domain-execution",
        "shake256-a177-independent-complete-rate-confirmation",
        "shake256-a177-posthoc-prospective-comparison",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A176:exact_input_declaration_order_invariance",
        mechanism="derive_and_hash_freeze_a_new_SHAKE256_32_bit_capacity_window_relation",
        outcome="A177:prospectively_frozen_SHAKE256_width32_relation",
        confidence=1.0,
        evidence_kind="pre_execution_public_relation_freeze",
        source=PROTOCOL_SHA256,
        attrs={"public_relation": payload["public_relation"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A177:prospectively_frozen_SHAKE256_width32_relation",
        mechanism="reopen_hash_pinned_native_Causal_artifact_and_extract_SHAKE256_recipe",
        outcome="A177:verified_SHAKE256_native_fullround_recipe",
        confidence=1.0,
        evidence_kind="retained_Causal_Reader_recipe",
        source=NATIVE_CAUSAL_SHA256,
        provenance=[ids[0]],
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A177:verified_SHAKE256_native_fullround_recipe",
        mechanism="enumerate_all_2^32_assignments_in_64_candidate_native_packs_without_early_stop",
        outcome="A177:complete_67108864_pack_filter_result",
        confidence=1.0,
        evidence_kind="complete_native_candidate_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[1]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A177:complete_67108864_pack_filter_result",
        mechanism="confirm_every_128_bit_filter_candidate_with_independent_24_round_NumPy_core_over_all_1088_rate_bits",
        outcome="A177:independently_confirmed_SHAKE256_width32_model_set",
        confidence=1.0,
        evidence_kind="independent_complete_rate_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[2]],
        attrs={
            "factual_confirmations": payload["execution"]["factual_confirmations"],
            "control_confirmations": payload["execution"]["control_confirmations"],
        },
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A177:independently_confirmed_SHAKE256_width32_model_set",
        mechanism="only_after_complete_execution_extract_and_compare_the_instrumented_assignment",
        outcome="A177:prospective_SHAKE256_width32_reconstruction_result",
        confidence=1.0,
        evidence_kind="post_execution_prospective_comparison",
        source=A176_SHA256,
        provenance=[ids[3]],
        attrs={"posthoc_comparison": payload["posthoc_comparison"]},
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A177 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    build_dir: Path,
    checkpoint_path: Path,
    cc: str,
    resume: bool,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    variant = _BASE.VARIANTS[VARIANT_KEY]
    library_path, native_build = _NATIVE._compile_native(build_dir, cc)
    if native_build["source_sha256"] != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A177 compiled native source differs")
    kernel = _NATIVE.NativeBitSliceKernel(library_path)
    current_build_gate = _NATIVE._cross_implementation_gate(kernel, SEED ^ 0xA177)
    execution = _enumerate_public_relation(
        kernel=kernel,
        public=analysis["public"],
        public_relation=analysis["public_relation"],
        variant=variant,
        recipe=analysis["anchor_gates"]["native_reader_recipe"],
        checkpoint_path=checkpoint_path,
        resume=resume,
    )
    if not execution["complete_domain_executed"]:
        raise RuntimeError("A177 did not execute the complete candidate domain")
    posthoc = _posthoc_after_execution(
        analysis["problem"],
        execution["factual_full_matches"],
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "SHAKE256_NATIVE_FULLROUND_WIDTH32_RECONSTRUCTION_RETAINED"
            if execution["unique_exact_public_model"]
            and posthoc["unique_reconstruction_matches_instrumented_assignment"]
            and execution["control_target_rejected"]
            else "SHAKE256_NATIVE_FULLROUND_WIDTH32_MODEL_SET_RETAINED"
        ),
        "result": (
            "The retained native Causal Reader executes the complete prospective "
            "SHAKE256 32-bit public relation and independently confirms every exact "
            "full-round model."
        ),
        "scope": (
            "Known-complement SHAKE256 state-window reconstruction over the complete "
            "2^32 declared capacity-window domain and all 1,088 next-rate bits."
        ),
        "parameters": {
            "variant": "SHAKE256",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "logical_candidate_count": 1 << WINDOW_BITS,
            "native_threads": THREADS,
            "stream_pack_count": STREAM_PACKS,
            "volatile_wallclock_excluded_from_canonical_result": True,
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_relation": analysis["public_relation"],
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "native_build": native_build,
        "current_build_cross_implementation_gate": current_build_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key not in {"factual_confirmations", "control_confirmations"}
            }
        ),
        "confirmation_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "posthoc_comparison": posthoc,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    if checkpoint_path.exists():
        checkpoint_path.unlink()
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A177 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "logical_candidate_count": execution["logical_candidate_count"],
        "packed_state_count": execution["packed_state_count"],
        "factual_filter_matches": execution["factual_filter_matches"],
        "factual_full_matches": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "unique_reconstruction_matches_instrumented": posthoc[
            "unique_reconstruction_matches_instrumented_assignment"
        ],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=research_root / "results" / "v1" / CHECKPOINT_FILENAME,
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "native",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
    else:
        analysis = None
    if analysis is not None:
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "anchor_gates": analysis["anchor_gates"],
                    "public_relation": analysis["public_relation"],
                    "execution_plan": analysis["execution_plan"],
                    "execution_plan_sha256": (
                        analysis.get("execution_plan_sha256")
                        or _canonical_sha256(analysis["execution_plan"])
                    ),
                    "candidate_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                build_dir=args.build_dir.resolve(),
                checkpoint_path=args.checkpoint.resolve(),
                cc=args.cc,
                resume=args.resume,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
