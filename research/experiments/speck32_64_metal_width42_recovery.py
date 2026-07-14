#!/usr/bin/env python3
"""A237: fresh complete-domain full-round Speck32/64 W42 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_encrypt_block,
    speck_round_keys,
)


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUAL = _import_sibling(
    "speck32_64_metal_qualification.py", "speck32_64_a237_qualification"
)

ATTEMPT_ID = "A237"
SCHEMA = "speck32-64-metal-width42-recovery-v1"
PROTOCOL_SCHEMA = "speck32-64-metal-width42-recovery-protocol-v1"
PROTOCOL_FILENAME = "speck32_64_metal_width42_recovery_v1.json"
PROTOCOL_SHA256 = "d8a657c4f46f0fc913b012331ad58791d577bc10a94f1f9146d01df00e1e93ca"
PUBLIC_CHALLENGE_SHA256 = "fc7035aa844c1669f79f263b5e1e081e4002121c465d3b55eade3a078a9bb201"
QUALIFICATION_FILENAME = "speck32_64_metal_qualification_v1.json"
QUALIFICATION_SHA256 = "e3a6c816adc246b1e6c264183557430e45c94e418179699bee9531125ffe5f44"
NATIVE_SOURCE_FILENAME = "speck32_64_metal_native.swift"
NATIVE_SOURCE_SHA256 = "219d40e02c434219e2e387516d18f4d82736816206d729961a64aea5a6cd9d9c"
UNKNOWN_BITS = 42
OUTER_BITS = 10
KNOWN_KEY_BITS = 22
OUTER_SLICES = 1 << OUTER_BITS
INNER_CANDIDATES = 1 << 32
LOGICAL_CANDIDATES = 1 << UNKNOWN_BITS
STREAM_CANDIDATES = 1 << 30
RESULT_CAPACITY = 64
PLAINTEXT_BLOCKS = 3
FILTER_WORDS = PLAINTEXT_BLOCKS * 2
FILTER_BITS = FILTER_WORDS * 16
RESULT_FILENAME = "speck32_64_metal_width42_recovery_v1.json"
CAUSAL_FILENAME = "speck32_64_metal_width42_recovery_v1.causal"
CHECKPOINT_FILENAME = "speck32_64_metal_width42_recovery_v1.checkpoint.json"
REPORT_FILENAME = "FULLROUND_SPECK32_64_METAL_WIDTH42_RECOVERY_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
VARIANT = SPECK_VARIANTS["speck32_64"]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return _sha256(raw)


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_text(path: Path, text: str) -> None:
    raw = text.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "Speck32/64_block_cipher",
        "rounds": 22,
        "unknown_key_bits": UNKNOWN_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_key2_low10_slice_count": OUTER_SLICES,
        "inner_key0_key1_candidate_count_per_slice": INNER_CANDIDATES,
        "combined_assignment_encoding": (
            "key2_low10_times_2^32_plus_key1_times_2^16_plus_key0"
        ),
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": LOGICAL_CANDIDATES,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batches_per_slice": INNER_CANDIDATES // STREAM_CANDIDATES,
        "stream_batch_count": LOGICAL_CANDIDATES // STREAM_CANDIDATES,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "full_confirmation": (
            "independent_Python_Speck32/64_all_three_96_output_bits"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }


def _known_material(label: str) -> tuple[int, int, list[int], str]:
    raw = hashlib.shake_256(label.encode()).digest(16)
    key2_known_upper6 = int.from_bytes(raw[:2], "big") & 0xFC00
    key3 = int.from_bytes(raw[2:4], "big")
    plaintext = [
        int.from_bytes(raw[offset : offset + 2], "big")
        for offset in range(4, 16, 2)
    ]
    return key2_known_upper6, key3, plaintext, _sha256(raw)


def _validate_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
        or challenge.get("cipher") != "Speck32/64"
        or challenge.get("rounds") != 22
        or challenge.get("plaintext_blocks") != PLAINTEXT_BLOCKS
        or len(challenge.get("plaintext_words_xy_order", [])) != FILTER_WORDS
        or len(challenge.get("target_ciphertext_words_xy_order", []))
        != FILTER_WORDS
        or len(challenge.get("control_ciphertext_words_xy_order", []))
        != FILTER_WORDS
        or challenge.get("unknown_assignment_bits") != UNKNOWN_BITS
        or challenge.get("known_master_key_bits") != KNOWN_KEY_BITS
        or challenge.get("known_key2_upper6", 1) & 0x03FF
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key0_included") is not False
        or challenge.get("unknown_key1_included") is not False
        or challenge.get("unknown_key2_low10_included") is not False
    ):
        raise RuntimeError("A237 public challenge identity gate failed")
    key2, key3, plaintext, derived_sha = _known_material(
        challenge["known_material_derivation_label"]
    )
    if (
        key2 != challenge["known_key2_upper6"]
        or key3 != challenge["known_key3"]
        or plaintext != challenge["plaintext_words_xy_order"]
        or derived_sha != challenge["known_material_derivation_sha256"]
        or len({tuple(plaintext[i : i + 2]) for i in range(0, 6, 2)})
        != PLAINTEXT_BLOCKS
    ):
        raise RuntimeError("A237 public known-material derivation gate failed")
    target = np.array(challenge["target_ciphertext_words_xy_order"], dtype="<u2")
    control = np.array(challenge["control_ciphertext_words_xy_order"], dtype="<u2")
    expected_control = target.copy()
    expected_control[-1] ^= np.uint16(1)
    if (
        _sha256(target.tobytes())
        != challenge["target_ciphertext_little_u16_sha256"]
        or _sha256(control.tobytes())
        != challenge["control_ciphertext_little_u16_sha256"]
        or not np.array_equal(control, expected_control)
    ):
        raise RuntimeError("A237 target/control byte gate failed")


def analyze(
    *, results_dir: Path, protocol_path: Path | None = None
) -> dict[str, Any]:
    research_root = Path(__file__).parents[1]
    path = protocol_path or research_root / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A237 frozen protocol hash differs")
    protocol = json.loads(path.read_text())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A237_candidate_execution"
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("anchors", {}).get("qualification", {}).get("sha256")
        != QUALIFICATION_SHA256
        or protocol.get("anchors", {}).get("native_host", {}).get("sha256")
        != NATIVE_SOURCE_SHA256
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A237_candidate_outcomes_used_before_protocol_freeze")
        is not False
    ):
        raise RuntimeError("A237 frozen protocol identity gate failed")
    qualification = results_dir / QUALIFICATION_FILENAME
    native_source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    if (
        _file_sha256(qualification) != QUALIFICATION_SHA256
        or _file_sha256(native_source) != NATIVE_SOURCE_SHA256
    ):
        raise RuntimeError("A237 implementation anchor hash differs")
    qualification_payload = json.loads(qualification.read_text())
    if (
        qualification_payload.get("evidence_stage")
        != "SPECK32_64_METAL_PRE_TARGET_QUALIFICATION"
        or qualification_payload.get("official_kat_gate", {}).get(
            "three_block_scalar_identity"
        )
        is not True
        or qualification_payload.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or qualification_payload.get("boundary_filter_gate", {}).get(
            "exact_boundary_identity"
        )
        is not True
    ):
        raise RuntimeError("A237 retained qualification gate failed")
    challenge = protocol["public_challenge"]
    _validate_challenge(challenge)
    plan = _execution_plan()
    if (
        protocol.get("execution_plan") != plan
        or protocol.get("execution_plan_sha256") != _canonical_sha256(plan)
    ):
        raise RuntimeError("A237 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "public_challenge": challenge,
        "execution_plan": plan,
        "qualification": qualification_payload,
        "anchor_gates": {
            "protocol_sha256": PROTOCOL_SHA256,
            "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
            "qualification_sha256": QUALIFICATION_SHA256,
            "native_source_sha256": NATIVE_SOURCE_SHA256,
        },
        "candidate_execution_started": False,
    }


def _arrays(challenge: dict[str, Any]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    return (
        np.array(challenge["plaintext_words_xy_order"], dtype=np.uint32),
        np.array(challenge["target_ciphertext_words_xy_order"], dtype=np.uint32),
        np.array(challenge["control_ciphertext_words_xy_order"], dtype=np.uint32),
    )


def _configure_outer(
    host: _QUAL.MetalSpeck3264Host,
    challenge: dict[str, Any],
    outer: int,
    plaintext: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
) -> None:
    if outer < 0 or outer >= OUTER_SLICES:
        raise ValueError("A237 outer assignment is outside the ten-bit domain")
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key2=int(challenge["known_key2_upper6"]) | outer,
        key3=int(challenge["known_key3"]),
    )


def _scalar_outputs(
    challenge: dict[str, Any], combined_assignment: int
) -> np.ndarray:
    if combined_assignment < 0 or combined_assignment >= LOGICAL_CANDIDATES:
        raise ValueError("A237 combined assignment is outside the W42 domain")
    inner = combined_assignment & 0xFFFFFFFF
    outer = combined_assignment >> 32
    master_key = [
        inner & 0xFFFF,
        (inner >> 16) & 0xFFFF,
        int(challenge["known_key2_upper6"]) | outer,
        int(challenge["known_key3"]),
    ]
    round_keys = speck_round_keys(VARIANT, master_key, VARIANT.full_rounds)
    plaintext = challenge["plaintext_words_xy_order"]
    output = []
    for offset in range(0, FILTER_WORDS, 2):
        output.extend(
            speck_encrypt_block(
                int(plaintext[offset]),
                int(plaintext[offset + 1]),
                round_keys,
                VARIANT,
            )
        )
    return np.array(output, dtype=np.uint32)


def _mapping_gate(
    host: _QUAL.MetalSpeck3264Host,
    challenge: dict[str, Any],
) -> dict[str, Any]:
    plaintext, _target, _control = _arrays(challenge)
    first = 184_032
    count = 256
    offset = 73
    rows = []
    for outer in (0, OUTER_SLICES // 2, OUTER_SLICES - 1):
        expected = np.stack(
            [
                _scalar_outputs(challenge, (outer << 32) | inner)
                for inner in range(first, first + count)
            ]
        )
        target = expected[offset].copy()
        control = target.copy()
        control[-1] ^= np.uint32(1)
        _configure_outer(
            host, challenge, outer, plaintext, target, control
        )
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        if (
            not np.array_equal(observed, expected)
            or filtered["factual"] != [first + offset]
            or filtered["control"] != []
        ):
            raise RuntimeError("A237 synthetic outer-slice mapping gate failed")
        rows.append(
            {
                "outer_key2_low10": outer,
                "first_inner_candidate": first,
                "candidate_count": count,
                "complete_output_bits_checked": int(observed.size * 16),
                "factual_inner_candidate": first + offset,
                "factual_combined_assignment": (outer << 32) | (first + offset),
                "control_matches": [],
                "output_sha256": _sha256(
                    observed.astype("<u4", copy=False).tobytes()
                ),
            }
        )
    return {
        "outer_values_checked": [row["outer_key2_low10"] for row in rows],
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": sum(
            row["complete_output_bits_checked"] for row in rows
        ),
        "rows": rows,
        "exact_scalar_filter_and_mapping_identity": True,
    }


def _confirm(
    challenge: dict[str, Any], target: np.ndarray, combined_assignment: int
) -> dict[str, Any]:
    output = _scalar_outputs(challenge, combined_assignment)
    inner = combined_assignment & 0xFFFFFFFF
    outer = combined_assignment >> 32
    return {
        "combined_assignment": combined_assignment,
        "key0": inner & 0xFFFF,
        "key1": (inner >> 16) & 0xFFFF,
        "key2_low10": outer,
        "complete_three_block_match": bool(np.array_equal(output, target)),
        "output_words_checked": FILTER_WORDS,
        "output_bits_checked": FILTER_BITS,
        "candidate_output_little_u16_sha256": _sha256(
            output.astype("<u2").tobytes()
        ),
        "target_output_little_u16_sha256": _sha256(
            target.astype("<u2").tobytes()
        ),
        "implementation": "independent_Python_canonical_Speck32/64",
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "speck32-64-metal-width42-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "target_ciphertext_sha256": challenge[
            "target_ciphertext_little_u16_sha256"
        ],
        "control_ciphertext_sha256": challenge[
            "control_ciphertext_little_u16_sha256"
        ],
        "unknown_key_bits": UNKNOWN_BITS,
        "stream_candidates": STREAM_CANDIDATES,
        "result_capacity": RESULT_CAPACITY,
    }


def _enumerate_domain(
    *,
    host: _QUAL.MetalSpeck3264Host,
    challenge: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    plaintext, target, control = _arrays(challenge)
    next_assignment = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    gpu_seconds = 0.0
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A237 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint.get("gpu_seconds", 0.0))
        if (
            next_assignment < 0
            or next_assignment > LOGICAL_CANDIDATES
            or next_assignment % STREAM_CANDIDATES != 0
            or any(value < 0 or value >= next_assignment for value in factual_filtered)
            or any(value < 0 or value >= next_assignment for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
            or factual_filtered
            or control_filtered
            or gpu_seconds < 0.0
        ):
            raise RuntimeError("A237 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    durable_next_assignment = next_assignment
    durable_gpu_seconds = gpu_seconds
    configured_outer: int | None = None
    wall_start = time.perf_counter()
    while next_assignment < LOGICAL_CANDIDATES:
        outer = next_assignment >> 32
        first_inner = next_assignment & 0xFFFFFFFF
        batch_count = min(
            STREAM_CANDIDATES,
            INNER_CANDIDATES - first_inner,
            LOGICAL_CANDIDATES - next_assignment,
        )
        if configured_outer != outer:
            _configure_outer(
                host, challenge, outer, plaintext, target, control
            )
            configured_outer = outer
        response = host.filter(first_inner, batch_count)
        gpu_seconds += float(response["gpu_seconds"])
        factual_filtered.extend(
            (outer << 32) | int(candidate) for candidate in response["factual"]
        )
        control_filtered.extend(
            (outer << 32) | int(candidate) for candidate in response["control"]
        )
        next_assignment += batch_count
        # Candidate identities are deliberately not persisted before the full
        # domain completes.  Once a match appears, the durable checkpoint stays
        # immediately before its batch; a crash therefore replays and
        # rediscovers it instead of leaking it through checkpoint state.
        if not factual_filtered and not control_filtered:
            durable_next_assignment = next_assignment
            durable_gpu_seconds = gpu_seconds
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": durable_next_assignment,
                "factual_filtered": [],
                "control_filtered": [],
                "gpu_seconds": durable_gpu_seconds,
                "candidate_matches_persisted": False,
            },
        )
        if (
            next_assignment % (16 * INNER_CANDIDATES) == 0
            or next_assignment == LOGICAL_CANDIDATES
        ):
            print(
                f"A237 Metal slices={next_assignment // INNER_CANDIDATES}/{OUTER_SLICES} "
                f"assignments={next_assignment}/{LOGICAL_CANDIDATES}",
                flush=True,
            )
    wall_seconds = time.perf_counter() - wall_start
    factual_confirmations = [
        _confirm(challenge, target, assignment) for assignment in factual_filtered
    ]
    control_confirmations = [
        _confirm(challenge, control, assignment) for assignment in control_filtered
    ]
    factual_full = [
        row["combined_assignment"]
        for row in factual_confirmations
        if row["complete_three_block_match"]
    ]
    control_full = [
        row["combined_assignment"]
        for row in control_confirmations
        if row["complete_three_block_match"]
    ]
    if not factual_full:
        raise RuntimeError("A237 complete-domain Reader returned no exact assignment")
    return {
        "unknown_key_bits": UNKNOWN_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_slice_count": OUTER_SLICES,
        "inner_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": LOGICAL_CANDIDATES // STREAM_CANDIDATES,
        "resumed_assignment_count": resumed_assignment_count,
        "newly_executed_assignment_count": LOGICAL_CANDIDATES
        - resumed_assignment_count,
        "complete_domain_executed": next_assignment == LOGICAL_CANDIDATES,
        "early_stop_used": False,
        "filter_output_bits": FILTER_BITS,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_assignment": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": wall_seconds,
        "volatile_candidates_per_gpu_second": LOGICAL_CANDIDATES
        / max(gpu_seconds, 1e-12),
        "unknown_assignment_available_to_runner_before_execution": False,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError(
                "dotcausal 0.3.1 is required; install requirements.txt or pass "
                "--dotcausal-src"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A237 authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_authentic_causal(
    *,
    path: Path,
    payload: dict[str, Any],
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    writer = CausalWriter(api_id="a237")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description=(
            "A complete residual-key enumeration followed by independent exact "
            "multi-block confirmation establishes residual-key recovery."
        ),
        pattern=["complete_domain_enumeration", "independent_exact_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="control_separates_target_specific_recovery",
        description=(
            "The same complete search returning no exact model for a one-bit "
            "control separates the factual public relation from pipeline artifacts."
        ),
        pattern=["same_complete_search", "zero_exact_control_models"],
        conclusion="target_specific_recovery_evidence",
        confidence_modifier=1.0,
    )
    execution = payload["execution"]
    writer.add_triplet(
        trigger="A236:pre_target_Metal_qualification",
        mechanism="official_KAT_plus_scalar_cross_gate_plus_uint32_boundary_gate",
        outcome="A237:qualified_fullround_Speck32_64_enumerator",
        confidence=1.0,
        source=QUALIFICATION_SHA256,
        quantification="22 rounds; 3 plaintext blocks; exact numeric word identity",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="Speck32/64 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A237:frozen_public_W42_relation",
        mechanism="complete_domain_enumeration",
        outcome="A237:factual_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{LOGICAL_CANDIDATES} assignments; no early stop",
        evidence=json.dumps(
            {
                "complete": execution["complete_domain_executed"],
                "filter_matches": execution["factual_filter_matches"],
            },
            sort_keys=True,
        ),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A237:factual_filter_candidate_set",
        mechanism="independent_exact_confirmation",
        outcome="A237:unique_verified_42_bit_residual_key",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="3 blocks; 96 output bits; canonical Python implementation",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A237:one_bit_flipped_control_relation",
        mechanism="same_complete_search",
        outcome="A237:control_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{LOGICAL_CANDIDATES} assignments; identical execution plan",
        evidence=json.dumps(
            {"control_filter_matches": execution["control_filter_matches"]},
            sort_keys=True,
        ),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A237:control_filter_candidate_set",
        mechanism="zero_exact_control_models",
        outcome="A237:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero independently confirmed assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    # Materialize the useful closure so the AI-native file remains in its
    # amplified state and does not recompute generic inference at every open.
    writer.add_triplet(
        trigger="A237:frozen_public_W42_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome="A237:unique_verified_42_bit_residual_key",
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and independent confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A237:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="A237:control_relation_rejected",
        confidence=1.0,
        source="materialized:control_separates_target_specific_recovery",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A237 verified recovery chain",
        entities=[
            "A237:frozen_public_W42_relation",
            "complete_domain_enumeration",
            "A237:factual_filter_candidate_set",
            "independent_exact_confirmation",
            "A237:unique_verified_42_bit_residual_key",
        ],
    )
    writer.add_cluster(
        name="A237 matched control chain",
        entities=[
            "A237:one_bit_flipped_control_relation",
            "same_complete_search",
            "A237:control_filter_candidate_set",
            "zero_exact_control_models",
            "A237:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject="A237:unique_verified_42_bit_residual_key",
        predicate="next_required_gain",
        expected_object_type="prospectively_selected_strict_subset_of_W42_domain",
        confidence=1.0,
        suggested_queries=[
            "Which known-key operator ranks the held-out W42 outer slice early?",
            "Does a frozen typed propagation graph reduce executed W42 candidates?",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    materialized = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a237"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
        or all_rows[-2]["outcome"] != "A237:unique_verified_42_bit_residual_key"
        or all_rows[-1]["outcome"] != "A237:control_relation_rejected"
    ):
        raise RuntimeError("A237 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "magic": path.read_bytes()[:8].decode("ascii", errors="replace"),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(materialized),
        "total_triplets": len(all_rows),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "inference_recomputed_on_reader_open": False,
        "amplified_state_materialized_in_file": True,
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": reader_source,
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "recovery_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A237:unique_verified_42_bit_residual_key"
            ],
            "control_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A237:control_relation_rejected"
            ],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: dict[str, Any]) -> str:
    execution = payload["execution"]
    recovery = payload["recovery"]
    causal = payload["causal"]
    return "\n".join(
        [
            "# A237 — Full-round Speck32/64 W42 residual-key recovery",
            "",
            "A fresh public relation was frozen before candidate execution. The native Apple Metal runner then executed every one of the `2^42` residual-key assignments for the standard 22-round Speck32/64 cipher, without early stopping.",
            "",
            "## Result",
            "",
            f"- Complete domain: **{execution['logical_candidate_count']:,} / {execution['logical_candidate_count']:,}**",
            f"- Recovered assignment: **`{recovery['recovered_combined_assignments'][0]}`**",
            f"- Unknown / known master-key bits: **{UNKNOWN_BITS} / {KNOWN_KEY_BITS}**",
            f"- Independent confirmation: **{FILTER_BITS} output bits across {PLAINTEXT_BLOCKS} blocks**",
            f"- Exact factual models: **{len(execution['factual_full_matches'])}**",
            f"- Exact one-bit-control models: **{len(execution['control_full_matches'])}**",
            f"- GPU time: **{execution['gpu_seconds']:.3f} s**",
            f"- Volatile wall time: **{execution['volatile_wall_seconds']:.3f} s**",
            "",
            "## Exact scope",
            "",
            "This is executed full-round partial-key recovery in a 42-bit residual domain: `K0`, `K1`, and the low ten bits of `K2` are unknown; the upper six bits of `K2` and all of `K3` are known. It establishes a commodity-hardware full-round recovery point. The complete residual domain was enumerated, so this result alone does not claim an asymptotic advantage over generic search.",
            "",
            "## AI-native Causal artifact",
            "",
            f"- Authentic Reader integrity gate: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized inferred edges: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Embedded rules / clusters / gaps: **{causal['embedded_rules']} / {causal['clusters']} / {causal['gaps']}**",
            "- Inference is materialized in-file; reopening does not rerun generic amplification.",
            "- The retained next gap is a prospectively frozen strict-subset reader for W42.",
            "",
            "## Primary algorithm source",
            "",
            "- Beaulieu et al., *The SIMON and SPECK Families of Lightweight Block Ciphers*, IACR ePrint 2013/404.",
            "",
        ]
    )


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
    checkpoint_path: Path,
    build_dir: Path,
    swiftc: str,
    dotcausal_src: Path,
    resume: bool,
) -> dict[str, Any]:
    analysis = analyze(results_dir=results_dir)
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalSpeck3264Host(executable)
    try:
        mapping_gate = _mapping_gate(host, analysis["public_challenge"])
        execution = _enumerate_domain(
            host=host,
            challenge=analysis["public_challenge"],
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        host_identity = host.identity
    finally:
        host.close()
    if (
        execution["complete_domain_executed"] is not True
        or execution["unique_exact_assignment"] is not True
        or execution["control_target_rejected"] is not True
        or execution["early_stop_used"] is not False
    ):
        raise RuntimeError("A237 complete-domain recovery gate failed")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SPECK32_64_FULLROUND_42BIT_RESIDUAL_KEY_RECOVERY_RETAINED",
        "result": (
            "The native Metal runner executed the complete fresh 42-bit residual "
            "key domain for standard 22-round Speck32/64 and independently "
            "confirmed the unique assignment across three public blocks."
        ),
        "scope": (
            "Full-round Speck32/64 partial-key recovery with K0, K1, and the low "
            "ten bits of K2 unknown; 22 key bits known; complete 2^42 enumeration."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate": mapping_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key not in {
                    "factual_confirmations",
                    "control_confirmations",
                    "volatile_wall_seconds",
                    "gpu_seconds",
                    "volatile_candidates_per_gpu_second",
                }
            }
        ),
        "confirmation_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "recovery": {
            "recovered_combined_assignments": execution["factual_full_matches"],
            "recovered_key0": [
                value & 0xFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key1": [
                (value >> 16) & 0xFFFF
                for value in execution["factual_full_matches"]
            ],
            "recovered_key2_low10": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "recovery_accepted_only_after_complete_domain_execution": True,
            "candidate_identities_persisted_in_checkpoint": False,
            "unknown_assignment_source_was_discarded_before_runner_construction": True,
        },
    }
    payload["causal"] = _build_authentic_causal(
        path=causal_output, payload=payload, dotcausal_src=dotcausal_src
    )
    _atomic_json(output, payload)
    _atomic_text(report_output, _report(payload))
    checkpoint_path.unlink(missing_ok=True)
    CausalWriter, CausalReader, _source = _load_dotcausal(dotcausal_src)
    del CausalWriter
    reader = CausalReader(str(causal_output), verify_integrity=True)
    reopened = json.loads(output.read_text())
    if (
        reopened != payload
        or _file_sha256(causal_output) != payload["causal"]["file_sha256"]
        or len(reader.get_all_triplets(include_inferred=True)) != 7
        or not report_output.is_file()
    ):
        raise RuntimeError("A237 final artifact reopen gate failed")
    return {
        "output": str(output),
        "json_sha256": _file_sha256(output),
        "causal_output": str(causal_output),
        "causal_sha256": _file_sha256(causal_output),
        "report_output": str(report_output),
        "report_sha256": _file_sha256(report_output),
        "complete_domain_executed": True,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "recovered_combined_assignments": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "gpu_seconds": execution["gpu_seconds"],
        "volatile_wall_seconds": execution["volatile_wall_seconds"],
        "authentic_causal_reader_verified": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    results_dir = research_root / "results" / "v1"
    parser.add_argument("--results-dir", type=Path, default=results_dir)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=results_dir / RESULT_FILENAME)
    parser.add_argument(
        "--causal-output", type=Path, default=results_dir / CAUSAL_FILENAME
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=research_root / "reports" / REPORT_FILENAME,
    )
    parser.add_argument(
        "--checkpoint", type=Path, default=results_dir / CHECKPOINT_FILENAME
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=research_root / "build" / "speck32_64_metal_width42",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.analyze_only:
        print(
            json.dumps(
                analyze(results_dir=args.results_dir), indent=2, sort_keys=True
            )
        )
        return
    print(
        json.dumps(
            run(
                results_dir=args.results_dir,
                output=args.output,
                causal_output=args.causal_output,
                report_output=args.report_output,
                checkpoint_path=args.checkpoint,
                build_dir=args.build_dir,
                swiftc=args.swiftc,
                dotcausal_src=args.dotcausal_src,
                resume=args.resume,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
