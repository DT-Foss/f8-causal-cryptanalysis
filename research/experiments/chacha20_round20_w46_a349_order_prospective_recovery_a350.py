#!/usr/bin/env python3
"""A350: execute A349's pre-result target-conditioned order on A345's fresh W46 challenge."""

from __future__ import annotations

import argparse
import importlib.util
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
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_a349_order_prospective_recovery_a350.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a349_order_prospective_recovery_a350.sh"

A345_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w46_factor2_replication_a345.py"
A345_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A345_PROGRESS = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_progress_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A349_ORDER = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
A324_QUALIFICATION = RESULTS / "chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"

ATTEMPT_ID = "A350"
DESIGN_SHA256 = "55e08eeea9648a685b9b68950b958744018095e62beeedb291f2433f12d7f63d"
A345_PROTOCOL_SHA256 = "8e4280d6603f1eacac0345df634113ed1b550f5d5292c2bed75cc31b19a07f95"
A345_PUBLIC_CHALLENGE_SHA256 = "622f7b7218d022167e50efef459983e54207165078c49f0bb253c70545e3231f"
A349_ORDER_SHA256 = "d2cbc5cbfe4765d7fd3681f92c4881a962d6b856d86a88bf9c9af716867dc96e"
A349_ORDER_COMMITMENT_SHA256 = "9b11478cd8ac38459ad2f8e1692fecdc5d2f31849408aaeaf42ebc80aa1d57af"
A349_SELECTED_ORDER_SHA256 = "441c6af3d9a2a32e1a61f0d50804a1ecbf2363517a7b570c408a09a15fd1bbaa"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
SELECTED_OPERATOR = "A342_selected_pair_slice_z_on_complete_A345_direct12_grid"

WIDTH = 46
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A350 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A345 = load_module(A345_RUNNER, "a350_a345_common")
A325 = A345.A325
A324 = A345.A324
file_sha256 = A345.file_sha256
canonical_sha256 = A345.canonical_sha256
sha256 = A345.sha256
atomic_json = A345.atomic_json
atomic_bytes = A345.atomic_bytes
path_from_ref = A345.path_from_ref
DOTCAUSAL_SRC = A345.DOTCAUSAL_SRC


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A350 anchor hash differs: {path}")
    return {"path": relative(path), "sha256": digest}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A350 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    return sha256(b"".join(value.to_bytes(2, "big") for value in exact_order(values, "hash")))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A350 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    reader = value.get("reader_contract", {})
    execution = value.get("execution_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-a349-order-prospective-recovery-a350-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or boundary.get("A345_result_available_at_design_freeze") is not False
        or boundary.get("A345_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("A350_executes_the_A349_order_from_rank_one_without_postfreeze_reordering")
        is not True
        or reader.get("target_labels_used_before_order_freeze") != 0
        or reader.get("reader_refits") != 0
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("prefix_groups") != CELLS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
    ):
        raise RuntimeError("A350 frozen design semantics differ")
    sources = value["source_anchors"]
    expected = {
        "A345_protocol": A345_PROTOCOL,
        "A349_order": A349_ORDER,
        "A324_qualification": A324_QUALIFICATION,
    }
    for name, path in expected.items():
        if sources[f"{name}_path"] != relative(path):
            raise RuntimeError(f"A350 design source path differs: {name}")
        anchor(path, sources[f"{name}_sha256"])
    return value


def source_boundary_snapshot() -> dict[str, Any]:
    if A345_RESULT.exists():
        raise RuntimeError("A350 prospective freeze requires A345 result absence")
    snapshot: dict[str, Any] = {
        "A345_result_available": False,
        "A345_candidate_or_prefix_available": False,
    }
    if not A345_PROGRESS.exists():
        snapshot["A345_progress_available"] = False
        return snapshot
    raw = A345_PROGRESS.read_bytes()
    value = json.loads(raw)
    if (
        value.get("status") == "candidate_found"
        or value.get("factual_filter_candidates") != 0
        or value.get("matched_control_candidates") != 0
        or "candidate" in value
        or "prefix12" in value
    ):
        raise RuntimeError("A350 prospective freeze requires candidate-free A345 progress")
    snapshot.update(
        {
            "A345_progress_available": True,
            "A345_progress_sha256": sha256(raw),
            "A345_progress_status": value.get("status"),
            "A345_executed_prefix_groups_at_snapshot": int(
                value.get("executed_prefix_groups", 0)
            ),
            "A345_progress_mtime_ns": A345_PROGRESS.stat().st_mtime_ns,
        }
    )
    return snapshot


def load_source_order_and_challenge() -> tuple[dict[str, Any], dict[str, Any], list[int]]:
    load_design()
    if file_sha256(A349_ORDER) != A349_ORDER_SHA256:
        raise RuntimeError("A350 A349 order artifact hash differs")
    order_value = json.loads(A349_ORDER.read_bytes())
    selected = exact_order(order_value.get("selected_order", []), "A349 selected")
    if (
        order_value.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-order-v1"
        or order_value.get("order_commitment_sha256") != A349_ORDER_COMMITMENT_SHA256
        or order_value.get("selected_order_uint16be_sha256") != A349_SELECTED_ORDER_SHA256
        or order_sha256(selected) != A349_SELECTED_ORDER_SHA256
        or order_value.get("target_labels_used") != 0
        or order_value.get("reader_refits") != 0
        or order_value.get("A345_result_available_at_order_freeze") is not False
        or order_value.get("A345_candidate_or_prefix_read_before_order_freeze") is not False
    ):
        raise RuntimeError("A350 A349 prospective order semantics differ")
    protocol = A345.load_protocol(A345_PROTOCOL_SHA256)
    challenge = protocol.get("public_challenge", {})
    if (
        protocol.get("public_challenge_sha256") != A345_PUBLIC_CHALLENGE_SHA256
        or canonical_sha256(challenge) != A345_PUBLIC_CHALLENGE_SHA256
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or "assignment" in challenge
        or "candidate" in challenge
        or "prefix12" in challenge
    ):
        raise RuntimeError("A350 A345 public challenge boundary differs")
    return order_value, protocol, selected


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A350 implementation or execution artifacts already exist")
    before = source_boundary_snapshot()
    order_value, _source_protocol, selected = load_source_order_and_challenge()
    A325.load_a324_qualification(A324_QUALIFICATION_SHA256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A350 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a349-order-prospective-recovery-a350-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A345_or_A350_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(selected),
        "A349_order_commitment_sha256": order_value["order_commitment_sha256"],
        "source_boundary_snapshot": before,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A349_order": anchor(A349_ORDER, A349_ORDER_SHA256),
            "A324_qualification": anchor(A324_QUALIFICATION, A324_QUALIFICATION_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    try:
        source_boundary_snapshot()
    except Exception:
        IMPLEMENTATION.unlink(missing_ok=True)
        raise
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A350 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a349-order-prospective-recovery-a350-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != A349_SELECTED_ORDER_SHA256
        or value.get("source_boundary_snapshot", {}).get("A345_candidate_or_prefix_available")
        is not False
    ):
        raise RuntimeError("A350 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A345_protocol": A345_PROTOCOL,
        "A349_order": A349_ORDER,
        "A324_qualification": A324_QUALIFICATION,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A350 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A350 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A350 protocol or execution artifacts already exist")
    before = source_boundary_snapshot()
    implementation = load_implementation(expected_implementation_sha256)
    order_value, source_protocol, selected = load_source_order_and_challenge()
    qualification = A325.load_a324_qualification(A324_QUALIFICATION_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a349-order-prospective-recovery-a350-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A349_public_output_conditioned_order_frozen_before_A345_or_A350_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A324_qualification_sha256": A324_QUALIFICATION_SHA256,
        "A324_semantic_qualification_sha256": qualification[
            "qualification_sha256"
        ],
        "A345_protocol_sha256": A345_PROTOCOL_SHA256,
        "public_challenge_sha256": A345_PUBLIC_CHALLENGE_SHA256,
        "public_challenge": source_protocol["public_challenge"],
        "A349_order_sha256": A349_ORDER_SHA256,
        "A349_order_commitment_sha256": order_value["order_commitment_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(selected),
        "selected_order": selected,
        "measurement_sha256": order_value["measurement_sha256"],
        "score_field_sha256": order_value["score_field_sha256"],
        "source_boundary_snapshot": before,
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A345_result_available_at_protocol_freeze": False,
            "A345_candidate_or_prefix_available_at_protocol_freeze": False,
            "A350_candidate_or_prefix_available_at_protocol_freeze": False,
            "A349_order_frozen_before_protocol": True,
            "A349_target_labels_used_for_order_construction": 0,
            "A349_reader_refits": 0,
            "A350_order_starts_at_frozen_rank_one": True,
            "A345_running_order_modified": False,
        },
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A349_order": anchor(A349_ORDER, A349_ORDER_SHA256),
            "A324_qualification": anchor(A324_QUALIFICATION, A324_QUALIFICATION_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    try:
        source_boundary_snapshot()
    except Exception:
        PROTOCOL.unlink(missing_ok=True)
        raise
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A350 protocol artifact hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "protocol selected")
    if (
        value.get("schema")
        != "chacha20-round20-w46-a349-order-prospective-recovery-a350-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A345_protocol_sha256") != A345_PROTOCOL_SHA256
        or value.get("A349_order_sha256") != A349_ORDER_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != A349_SELECTED_ORDER_SHA256
        or order_sha256(selected) != A349_SELECTED_ORDER_SHA256
        or value.get("information_boundary", {}).get(
            "A345_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A350_order_starts_at_frozen_rank_one"
        )
        is not True
        or canonical_sha256(value.get("public_challenge", {}))
        != A345_PUBLIC_CHALLENGE_SHA256
    ):
        raise RuntimeError("A350 frozen protocol semantics differ")
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A350 protocol commitment differs")
    for name, path in {
        "implementation": IMPLEMENTATION,
        "A345_protocol": A345_PROTOCOL,
        "A349_order": A349_ORDER,
        "A324_qualification": A324_QUALIFICATION,
        "runner": Path(__file__),
    }.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A350 protocol anchor differs: {name}")
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a349-order-prospective-recovery-a350-progress-v1"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A350 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A324_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A350 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A350:confirmed_public_output_conditioned_fullround_W46_recovery"
    writer = CausalWriter(api_id="a350w46")
    writer._rules = []
    writer.add_rule(
        name="public_output_reader_to_pre_result_order",
        description="The frozen A348 reader maps the complete unlabeled A345 public-output direct12 grid to the immutable A349 order.",
        pattern=["A348_frozen_pair_reader", "A345_public_output_direct12_grid"],
        conclusion="A349_pre_result_A345_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="pre_result_order_to_sole_fullround_model",
        description="A350 executes every complete 2^34 assignment group in the immutable A349 order until the sole factual filter model appears.",
        pattern=["A349_pre_result_A345_order", "A324_exact_W46_group_engine"],
        conclusion="A350_sole_factual_W46_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_dual_confirmation",
        description="Independent byte and word implementations confirm every bit of all eight full-round output blocks.",
        pattern=["A350_sole_factual_W46_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A348:frozen_selected_pair_reader",
        mechanism="zero_refit_complete_A345_public_output_direct12_measurement",
        outcome="A349:pre_result_A345_order",
        confidence=1.0,
        source=payload["A349_order_commitment_sha256"],
        quantification=json.dumps(payload["reader_gate"], sort_keys=True),
        evidence="target-label-free exact 4096-cell order",
        domain="prospective public-output-conditioned W46 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A349:pre_result_A345_order",
        mechanism="ordered_complete_eight_slab_fullround_search",
        outcome="A350:sole_factual_W46_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="full-round ChaCha20 W46 model recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A350:sole_factual_W46_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W46 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A348:frozen_selected_pair_reader",
        mechanism="materialized_reader_order_recovery_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A350_reader_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A350 prospective public-output-conditioned W46 recovery",
        entities=[
            "A348:frozen_selected_pair_reader",
            "A349:pre_result_A345_order",
            "A350:sole_factual_W46_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_independent_target_conditioned_recovery_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "Repeat the frozen reader-to-recovery chain on a new W46 target or transfer it to the qualified W47 engine."
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
        reader.api_id != "a350w46"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A350 authentic Causal reopen gate failed")
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


def recover(
    *, expected_protocol_sha256: str, expected_a324_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A350 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if protocol["A324_qualification_sha256"] != expected_a324_qualification_sha256:
        raise RuntimeError("A350 protocol qualification anchor differs")
    challenge = protocol["public_challenge"]
    a324_protocol = A324.load_protocol(A325.A324_PROTOCOL_SHA256)
    executable_row = a324_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A324.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w46-a349-order-prospective-recovery-a350-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": protocol["selected_operator"],
                "selected_order_uint16be_sha256": protocol[
                    "selected_order_uint16be_sha256"
                ],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=expected_a324_qualification_sha256,
    )
    discovery = completed_discovery or A325.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A350 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A325.confirm(challenge, candidate)
    if (
        confirmation.get("all_blocks_match") is not True
        or confirmation.get("total_cross_implementation_output_bits_checked") != 8192
    ):
        raise RuntimeError("A350 dual independent confirmation failed")
    prefix = (candidate & MASK32) >> WORD0_SUFFIX_BITS
    if prefix != int(discovery["prefix12"]):
        raise RuntimeError("A350 recovered prefix codec differs")
    selected = exact_order(protocol["selected_order"], "recovery selected")
    rank = selected.index(prefix) + 1
    if rank != int(discovery["executed_prefix_groups"]):
        raise RuntimeError("A350 discovery rank differs from frozen order")
    strict_subset = rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_PUBLIC_OUTPUT_CONDITIONED_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_PUBLIC_OUTPUT_CONDITIONED_W46_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    rank_analysis = {
        "confirmed_prefix12": prefix,
        "confirmed_prefix12_hex": f"{prefix:03x}",
        "selected_rank_one_based": rank,
        "gain_bits_vs_complete_4096_group_cover": math.log2(CELLS / rank),
        "domain_reduction_factor_at_rank": CELLS / rank,
        "complete_group_assignment_bound": rank * GROUP_SIZE,
        "complete_W46_domain_assignments": DOMAIN_SIZE,
        "rank_computed_after_dual_confirmation": True,
    }
    reader_gate = {
        "complete_direct12_cells": 4096,
        "solver_stages": 16384,
        "target_labels_used": 0,
        "reader_refits": 0,
        "A345_result_available_at_order_freeze": False,
        "A345_candidate_or_prefix_read_before_order_freeze": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a349-order-prospective-recovery-a350-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "A345_protocol_sha256": A345_PROTOCOL_SHA256,
        "public_challenge_sha256": A345_PUBLIC_CHALLENGE_SHA256,
        "A349_order_sha256": A349_ORDER_SHA256,
        "A349_order_commitment_sha256": A349_ORDER_COMMITMENT_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": A349_SELECTED_ORDER_SHA256,
        "reader_gate": reader_gate,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W46_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": rank_analysis,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": SELECTED_OPERATOR,
            "selected_order_uint16be_sha256": A349_SELECTED_ORDER_SHA256,
            "discovery": stable_discovery,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "reader_gate": reader_gate,
            "discovery": stable_discovery,
            "rank_analysis": rank_analysis,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A350 — prospective public-output-conditioned full-round ChaCha20 W46 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen Reader: **{SELECTED_OPERATOR}**\n"
            f"- W46 execution rank: **{rank} / 4,096**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W46 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **eight complete 2^31 slabs before outcome evaluation**\n"
            "- Target labels / Reader refits before order freeze: **0 / 0**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        response["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        response["protocol_sha256"] = file_sha256(PROTOCOL)
        response["selected_order_uint16be_sha256"] = A349_SELECTED_ORDER_SHA256
    if PROGRESS.exists():
        progress = json.loads(PROGRESS.read_bytes())
        response["progress"] = {
            key: progress.get(key)
            for key in (
                "status",
                "executed_prefix_groups",
                "executed_assignments",
                "factual_filter_candidates",
                "matched_control_candidates",
                "last_completed_prefix12",
            )
        }
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a324-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-protocol requires --expected-implementation-sha256")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.recover:
        if not args.expected_protocol_sha256 or not args.expected_a324_qualification_sha256:
            parser.error("--recover requires protocol and A324 qualification hashes")
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
