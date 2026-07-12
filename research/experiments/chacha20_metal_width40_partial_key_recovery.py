#!/usr/bin/env python3
"""Fresh complete-domain 40-bit ChaCha20 partial-key recovery on Metal."""

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


_A183 = _import_sibling(
    "chacha20_metal_width38_partial_key_recovery.py",
    "chacha20_width40_a183_anchor",
)
_A182 = _A183._A182
_A181 = _A182._A181
_A179 = _A181._A179
_A178 = _A181._A178
_A119 = _A181._A119

ATTEMPT_ID = "A184"
SCHEMA = "chacha20-metal-width40-partial-key-recovery-v1"
PROTOCOL_SCHEMA = "chacha20-metal-width40-partial-key-recovery-protocol-v1"
PROTOCOL_FILENAME = "chacha20_metal_width40_partial_key_recovery_v1.json"
PROTOCOL_SHA256 = "a6c904e07bc56b08994a9cf4c36c86cd43b468f6c23f9e0d81f3cd52317c6ecf"
A183_FILENAME = _A183.RESULT_FILENAME
A183_SHA256 = "68d4396e8c064baa2385467cfd5dd7d9aee06014d40f87ee6dfdb8c3d253be7d"
A183_CAUSAL_FILENAME = _A183.CAUSAL_FILENAME
A183_CAUSAL_SHA256 = "2f82b26e85595f50895f159db95562fa872d373b10e5f303f73ca2947ba51688"
NATIVE_SOURCE_FILENAME = _A181.NATIVE_SOURCE_FILENAME
NATIVE_SOURCE_SHA256 = _A181.NATIVE_SOURCE_SHA256
PUBLIC_RELATION_SHA256 = "682462f9c90202dcaa6c9987b40b200b76ca8d7c16253533c98b8981f4241078"
UNKNOWN_KEY_BITS = 40
UNKNOWN_WORD0_BITS = 32
UNKNOWN_WORD1_LOW_BITS = 8
KNOWN_KEY_BITS = 216
OUTER_SLICES = 1 << UNKNOWN_WORD1_LOW_BITS
INNER_CANDIDATES = 1 << UNKNOWN_WORD0_BITS
LOGICAL_CANDIDATES = 1 << UNKNOWN_KEY_BITS
STREAM_CANDIDATES = _A181.STREAM_CANDIDATES
RESULT_CAPACITY = _A181.RESULT_CAPACITY
FILTER_WORDS = 2
RESULT_FILENAME = "chacha20_metal_width40_partial_key_recovery_v1.json"
CAUSAL_FILENAME = "chacha20_metal_width40_partial_key_recovery_v1.causal"
CHECKPOINT_FILENAME = "chacha20_metal_width40_partial_key_recovery_v1.checkpoint.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A181._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A181._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A184 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A184_candidate_execution"
        or protocol.get("anchors", {}).get("A183", {}).get("sha256") != A183_SHA256
        or protocol.get("anchors", {}).get("A183", {}).get("causal_sha256") != A183_CAUSAL_SHA256
        or protocol.get("native_host", {}).get("source_sha256") != NATIVE_SOURCE_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_RELATION_SHA256
        or protocol.get("execution_plan", {}).get("complete_domain_required") is not True
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A184_candidate_outcomes_used_before_protocol_freeze") is not False
    ):
        raise RuntimeError("A184 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    result_path = results_dir / A183_FILENAME
    causal_path = results_dir / A183_CAUSAL_FILENAME
    native_path = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    observed = {
        "A183_result_sha256": _file_sha256(result_path),
        "A183_causal_sha256": _file_sha256(causal_path),
        "Metal_native_source_sha256": _file_sha256(native_path),
    }
    expected = {
        "A183_result_sha256": A183_SHA256,
        "A183_causal_sha256": A183_CAUSAL_SHA256,
        "Metal_native_source_sha256": NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A184 A183/Metal-source anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    if (
        result.get("schema") != _A183.SCHEMA
        or result.get("evidence_stage") != "CHACHA20_FULLROUND_38BIT_PARTIAL_KEY_RECOVERY_RETAINED"
        or result.get("execution", {}).get("complete_domain_executed") is not True
        or result.get("execution", {}).get("logical_candidate_count") != 1 << 38
        or result.get("execution", {}).get("control_full_matches") != []
    ):
        raise RuntimeError("A184 retained A183 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A183_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
        or len(reader.triplets(include_inferred=False)) != 5
    ):
        raise RuntimeError("A184 retained A183 Causal gate failed")
    return result, {
        **observed,
        "A183_causal_graph_sha256": reader.graph_sha256,
        "A183_causal_provenance_verified": True,
        "A183_complete_domain_executed": True,
        "A183_logical_candidate_count": 1 << 38,
    }


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_RELATION_SHA256
        or challenge.get("unknown_assignment_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_key_word0_bits") != UNKNOWN_WORD0_BITS
        or challenge.get("unknown_key_word1_low_bits") != UNKNOWN_WORD1_LOW_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_included") is not False
        or challenge.get("unknown_key_word1_low_value_included") is not False
        or challenge.get("known_key_word1_upper24", 1) & 0xFF
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != 16
        or len(challenge.get("control_target_words", [])) != 16
        or challenge.get("filter_words") != FILTER_WORDS
        or challenge.get("filter_bits") != FILTER_WORDS * 32
        or challenge["control_target_words"][0] != (challenge["target_words"][0] ^ 1)
        or challenge["control_target_words"][1:] != challenge["target_words"][1:]
    ):
        raise RuntimeError("A184 public challenge identity gate failed")
    label = challenge["known_material_derivation_label"]
    derived = hashlib.shake_256(label.encode()).digest(44)
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & 0xFFFFFF00 != challenge["known_key_word1_upper24"]
        or [int(value) for value in words[1:7]] != challenge["known_key_words_2_through_7"]
        or int(words[7]) != challenge["counter"]
        or [int(value) for value in words[8:11]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A184 known-material derivation gate failed")
    target = np.array(challenge["target_words"], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(target.astype("<u4", copy=False).tobytes()) != challenge["target_block_sha256"]
        or _sha256(control.astype("<u4", copy=False).tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A184 public target byte fingerprint differs")


def _initial_for_low_value(challenge: dict[str, Any], low_value: int) -> np.ndarray:
    if low_value < 0 or low_value >= OUTER_SLICES:
        raise ValueError("A184 low value is outside the eight-bit domain")
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = _A119.CONSTANTS
    initial[4] = np.uint32(0)
    initial[5] = np.uint32(challenge["known_key_word1_upper24"] | low_value)
    initial[6:12] = np.array(challenge["known_key_words_2_through_7"], dtype=np.uint32)
    initial[12] = np.uint32(challenge["counter"])
    initial[13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    return initial


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": 20,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "unknown_key_word0_bits": UNKNOWN_WORD0_BITS,
        "unknown_key_word1_low_bits": UNKNOWN_WORD1_LOW_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "counter_bits_known": 32,
        "nonce_bits_known": 96,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_low_bit_slice_count": OUTER_SLICES,
        "inner_word_candidate_count_per_slice": INNER_CANDIDATES,
        "combined_assignment_encoding": ("key_word1_low_value_times_2^32_plus_key_word0"),
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": LOGICAL_CANDIDATES,
        "metal_thread_execution_width": 32,
        "threads_per_threadgroup": 256,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batches_per_slice": INNER_CANDIDATES // STREAM_CANDIDATES,
        "stream_batch_count": LOGICAL_CANDIDATES // STREAM_CANDIDATES,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "maximum_result_memory_bytes": 520,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "full_confirmation": "independent_NumPy_ChaCha20_all_512_output_bits",
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "wallclock_excluded_from_canonical_result": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    _, anchors = _load_anchor_gates(results_dir)
    challenge = protocol["public_challenge"]
    _validate_public_challenge(challenge)
    plan = _execution_plan()
    if protocol["execution_plan"] != plan or protocol["execution_plan_sha256"] != _canonical_sha256(
        plan
    ):
        raise RuntimeError("A184 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "target": np.array(challenge["target_words"], dtype=np.uint32),
        "control_target": np.array(challenge["control_target_words"], dtype=np.uint32),
        "execution_plan": plan,
        "candidate_execution_started": False,
    }


class SliceMetalHost(_A181.MetalChaCha20Host):
    def configure(
        self,
        initial: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
    ) -> None:
        response = self._request(
            {
                "op": "configure",
                "initial": [int(value) for value in initial],
                "target": [int(value) for value in target[:FILTER_WORDS]],
                "control": [int(value) for value in control[:FILTER_WORDS]],
            }
        )
        if response.get("op") != "configured":
            raise RuntimeError("A184 Metal slice reconfiguration failed")


def _synthetic_slice_mapping_gate(
    host: SliceMetalHost,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
) -> dict[str, Any]:
    gate = protocol["required_validation_gates"]["synthetic_slice_mapping_gate"]
    low_values = [int(value) for value in gate["low_values"]]
    first = int(gate["first_key_word0"])
    count = int(gate["candidate_count_per_slice"])
    offset = 73
    rows = []
    for low_value in low_values:
        initial = _initial_for_low_value(challenge, low_value)
        scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
        scalar[:, 4] = np.arange(first, first + count, dtype=np.uint32)
        expected = (_A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
        target = expected[offset].copy()
        control = target.copy()
        control[0] ^= np.uint32(1)
        host.configure(initial, target, control)
        observed = host.blocks(first, count)
        response = host.filter(first, count)
        if (
            not np.array_equal(observed, expected)
            or response["factual"] != [first + offset]
            or response["control"] != []
            or observed.size * 32 != gate["complete_output_bits_per_slice"]
        ):
            raise RuntimeError("A184 synthetic slice-mapping gate failed")
        rows.append(
            {
                "key_word1_low_value": low_value,
                "first_key_word0": first,
                "candidate_count": count,
                "complete_output_bits_checked": int(observed.size * 32),
                "output_sha256": _sha256(observed.astype("<u4").tobytes()),
                "factual_key_word0": first + offset,
                "factual_combined_assignment": (low_value << 32) | (first + offset),
                "control_matches": [],
                "exact_scalar_identity": True,
            }
        )
    return {
        "low_values_checked": low_values,
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": sum(row["complete_output_bits_checked"] for row in rows),
        "rows": rows,
        "exact_scalar_and_mapping_identity": True,
    }


def _independent_confirm(
    challenge: dict[str, Any],
    target: np.ndarray,
    combined_assignment: int,
) -> dict[str, Any]:
    low_value = combined_assignment >> UNKNOWN_WORD0_BITS
    word0 = combined_assignment & 0xFFFFFFFF
    initial = _initial_for_low_value(challenge, low_value).reshape(1, 16)
    initial[0, 4] = np.uint32(word0)
    output = (_A119._core(initial.copy(), 20) + initial).astype(np.uint32)
    expected = target.reshape(1, 16)
    return {
        "combined_assignment": combined_assignment,
        "key_word0": word0,
        "key_word1_low_value": low_value,
        "complete_block_match": bool(np.array_equal(output, expected)),
        "output_words_checked": 16,
        "output_bits_checked": 512,
        "candidate_block_sha256": _sha256(output.astype("<u4").tobytes()),
        "target_block_sha256": _sha256(expected.astype("<u4").tobytes()),
        "implementation": "independent_NumPy_RFC8439_ChaCha20_core",
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "chacha20-metal-width40-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "target_block_sha256": challenge["target_block_sha256"],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "stream_candidates": STREAM_CANDIDATES,
        "result_capacity": RESULT_CAPACITY,
    }


def _enumerate_partial_key(
    *,
    host: SliceMetalHost,
    challenge: dict[str, Any],
    target: np.ndarray,
    control: np.ndarray,
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    next_assignment = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A184 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        if (
            next_assignment < 0
            or next_assignment > LOGICAL_CANDIDATES
            or next_assignment % STREAM_CANDIDATES != 0
            or any(value < 0 or value >= next_assignment for value in factual_filtered)
            or any(value < 0 or value >= next_assignment for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A184 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    configured_low_value: int | None = None
    while next_assignment < LOGICAL_CANDIDATES:
        low_value = next_assignment >> UNKNOWN_WORD0_BITS
        first_word0 = next_assignment & 0xFFFFFFFF
        batch_count = min(
            STREAM_CANDIDATES,
            INNER_CANDIDATES - first_word0,
            LOGICAL_CANDIDATES - next_assignment,
        )
        if configured_low_value != low_value:
            host.configure(
                _initial_for_low_value(challenge, low_value),
                target,
                control,
            )
            configured_low_value = low_value
        response = host.filter(first_word0, batch_count)
        factual_filtered.extend(
            (low_value << UNKNOWN_WORD0_BITS) | int(value) for value in response["factual"]
        )
        control_filtered.extend(
            (low_value << UNKNOWN_WORD0_BITS) | int(value) for value in response["control"]
        )
        next_assignment += batch_count
        _A178._A177._NATIVE._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
            },
        )
        if next_assignment % INNER_CANDIDATES == 0:
            print(
                f"A184 Metal slices={next_assignment // INNER_CANDIDATES}/{OUTER_SLICES} "
                f"assignments={next_assignment}/{LOGICAL_CANDIDATES}",
                flush=True,
            )
    factual_confirmations = [
        _independent_confirm(challenge, target, assignment) for assignment in factual_filtered
    ]
    control_confirmations = [
        _independent_confirm(challenge, control, assignment) for assignment in control_filtered
    ]
    factual_full = [
        row["combined_assignment"] for row in factual_confirmations if row["complete_block_match"]
    ]
    control_full = [
        row["combined_assignment"] for row in control_confirmations if row["complete_block_match"]
    ]
    if not factual_full:
        raise RuntimeError("A184 complete-domain Reader returned no exact assignment")
    return {
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_low_bit_slice_count": OUTER_SLICES,
        "inner_word_candidate_count_per_slice": INNER_CANDIDATES,
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": LOGICAL_CANDIDATES,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": LOGICAL_CANDIDATES // STREAM_CANDIDATES,
        "resumed_assignment_count": resumed_assignment_count,
        "newly_executed_assignment_count": LOGICAL_CANDIDATES - resumed_assignment_count,
        "complete_domain_executed": next_assignment == LOGICAL_CANDIDATES,
        "early_stop_used": False,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_assignment": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "unknown_assignment_available_to_runner_before_execution": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_metal_width40_partial_key_recovery",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 20,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "logical_candidates": LOGICAL_CANDIDATES,
            "execution_backend": "Apple_M4_Metal_GPU",
        },
    )
    ids = [
        "chacha20-a183-width38-recovery-anchor",
        "chacha20-a184-fresh-width40-challenge-freeze",
        "chacha20-a184-two-word-slice-mapping-gate",
        "chacha20-a184-complete-width40-domain-execution",
        "chacha20-a184-independent-width40-recovery",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A183:retained_fresh_fullround_38_bit_partial_key_recovery",
        mechanism="anchor_the_verified_38_bit_Metal_recovery_and_ChaCha20_reader",
        outcome="A184:fresh_40_bit_partial_key_question",
        confidence=1.0,
        evidence_kind="retained_A183_width38_recovery_anchor",
        source=A183_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A184:fresh_40_bit_partial_key_question",
        mechanism="freeze_a_public_target_with_one_full_word_and_eight_adjacent_key_bits_omitted",
        outcome="A184:prospectively_frozen_fresh_width40_challenge",
        confidence=1.0,
        evidence_kind="pre_execution_public_challenge_freeze",
        source=PUBLIC_RELATION_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A184:prospectively_frozen_fresh_width40_challenge",
        mechanism="cross_validate_three_outer_slices_over_complete_512_bit_outputs",
        outcome="A184:verified_two_word_Metal_assignment_mapping",
        confidence=1.0,
        evidence_kind="synthetic_two_word_slice_mapping_gate",
        source=NATIVE_SOURCE_SHA256,
        provenance=[ids[1]],
        attrs={"mapping_gate": payload["synthetic_slice_mapping_gate"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A184:verified_two_word_Metal_assignment_mapping",
        mechanism="enumerate_all_2^40_assignments_across_256_complete_word_domains_without_early_stop",
        outcome="A184:complete_fresh_width40_filter_result",
        confidence=1.0,
        evidence_kind="complete_Metal_width40_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A184:complete_fresh_width40_filter_result",
        mechanism="confirm_every_filter_assignment_with_independent_RFC8439_NumPy_over_all_512_bits",
        outcome="A184:fresh_fullround_40_bit_partial_key_recovery",
        confidence=1.0,
        evidence_kind="independent_complete_block_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[3]],
        attrs={
            "factual_confirmations": payload["execution"]["factual_confirmations"],
            "control_confirmations": payload["execution"]["control_confirmations"],
        },
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
        raise RuntimeError("A184 Causal provenance chain failed validation")
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
    swiftc: str,
    resume: bool,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    executable, native_build = _A181._compile_native(build_dir, swiftc)
    initial = _initial_for_low_value(analysis["public_challenge"], 0)
    host = SliceMetalHost(
        executable,
        initial,
        analysis["target"],
        analysis["control_target"],
    )
    try:
        mapping_gate = _synthetic_slice_mapping_gate(
            host,
            analysis["protocol"],
            analysis["public_challenge"],
        )
        execution = _enumerate_partial_key(
            host=host,
            challenge=analysis["public_challenge"],
            target=analysis["target"],
            control=analysis["control_target"],
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
        raise RuntimeError("A184 complete-domain recovery gate failed")
    recovered = execution["factual_full_matches"]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CHACHA20_FULLROUND_40BIT_PARTIAL_KEY_RECOVERY_RETAINED",
        "result": (
            "The native Metal Causal Reader executes the complete fresh 40-bit "
            "ChaCha20 partial-key domain and independently confirms the unique "
            "assignment matching the standard 20-round block output."
        ),
        "scope": (
            "Standard ChaCha20 block-function partial-key recovery with key word 0 "
            "and the low eight bits of key word 1 unknown, the other 216 key bits "
            "plus counter and nonce known, and complete 2^40 enumeration."
        ),
        "parameters": {
            "rounds": 20,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "logical_candidate_count": LOGICAL_CANDIDATES,
            "execution_backend": "Apple_M4_Metal_GPU",
            "stream_candidate_count": STREAM_CANDIDATES,
            "volatile_wallclock_excluded_from_canonical_result": True,
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "kat": _A119._kat(),
        "native_build": native_build,
        "host_identity": host_identity,
        "synthetic_slice_mapping_gate": mapping_gate,
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
        "recovery": {
            "recovered_combined_assignments": recovered,
            "recovered_key_word0": [value & 0xFFFFFFFF for value in recovered],
            "recovered_key_word1_low_value": [value >> UNKNOWN_WORD0_BITS for value in recovered],
            "first_reveal_occurs_after_complete_domain_execution": True,
            "unknown_assignment_source_was_discarded_before_runner_construction": True,
        },
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    checkpoint_path.unlink(missing_ok=True)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A184 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_combined_assignments": recovered,
        "recovered_key_word0": [value & 0xFFFFFFFF for value in recovered],
        "recovered_key_word1_low_value": [value >> UNKNOWN_WORD0_BITS for value in recovered],
        "control_full_matches": execution["control_full_matches"],
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
        default=Path(__file__).parents[2] / "build" / "chacha-metal-width40",
    )
    parser.add_argument("--swiftc", default=os.environ.get("SWIFTC", "swiftc"))
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "anchor_gates": analysis["anchor_gates"],
                    "public_challenge": analysis["public_challenge"],
                    "public_challenge_sha256": PUBLIC_RELATION_SHA256,
                    "execution_plan": analysis["execution_plan"],
                    "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
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
                swiftc=args.swiftc,
                resume=args.resume,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
