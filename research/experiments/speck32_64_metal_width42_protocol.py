#!/usr/bin/env python3
"""Create the one-shot pre-execution protocol for A237 Speck32/64 W42."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_encrypt_block,
    speck_round_keys,
)

ATTEMPT_ID = "A237"
SCHEMA = "speck32-64-metal-width42-recovery-protocol-v1"
UNKNOWN_BITS = 42
OUTER_BITS = 10
KNOWN_KEY_BITS = 64 - UNKNOWN_BITS
INNER_CANDIDATES = 1 << 32
OUTER_SLICES = 1 << OUTER_BITS
LOGICAL_CANDIDATES = 1 << UNKNOWN_BITS
STREAM_CANDIDATES = 1 << 30
PLAINTEXT_BLOCKS = 3
FILTER_BITS = PLAINTEXT_BLOCKS * 32
KNOWN_MATERIAL_LABEL = "speck32-64/a237/fullround/w42/known-material/v1"
QUALIFICATION_FILENAME = "speck32_64_metal_qualification_v1.json"
QUALIFICATION_SHA256 = "e3a6c816adc246b1e6c264183557430e45c94e418179699bee9531125ffe5f44"
NATIVE_SOURCE_FILENAME = "speck32_64_metal_native.swift"
NATIVE_SOURCE_SHA256 = "219d40e02c434219e2e387516d18f4d82736816206d729961a64aea5a6cd9d9c"
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


def _known_material() -> tuple[int, int, list[int], str]:
    raw = hashlib.shake_256(KNOWN_MATERIAL_LABEL.encode()).digest(16)
    key2_source = int.from_bytes(raw[:2], "big")
    key2_known_upper6 = key2_source & 0xFC00
    key3 = int.from_bytes(raw[2:4], "big")
    plaintext_words = [
        int.from_bytes(raw[offset : offset + 2], "big")
        for offset in range(4, 16, 2)
    ]
    blocks = {
        tuple(plaintext_words[offset : offset + 2])
        for offset in range(0, len(plaintext_words), 2)
    }
    if len(blocks) != PLAINTEXT_BLOCKS:
        raise RuntimeError("A237 deterministic plaintext blocks are not distinct")
    return key2_known_upper6, key3, plaintext_words, _sha256(raw)


def _target_words(
    assignment: int,
    key2_known_upper6: int,
    key3: int,
    plaintext_words: list[int],
) -> list[int]:
    inner = assignment & 0xFFFFFFFF
    outer = assignment >> 32
    master_key = [
        inner & 0xFFFF,
        (inner >> 16) & 0xFFFF,
        key2_known_upper6 | outer,
        key3,
    ]
    round_keys = speck_round_keys(VARIANT, master_key, VARIANT.full_rounds)
    output = []
    for offset in range(0, len(plaintext_words), 2):
        output.extend(
            speck_encrypt_block(
                plaintext_words[offset],
                plaintext_words[offset + 1],
                round_keys,
                VARIANT,
            )
        )
    return output


def build_protocol(*, qualification: Path, native_source: Path) -> dict[str, Any]:
    if _file_sha256(qualification) != QUALIFICATION_SHA256:
        raise RuntimeError("A237 qualification anchor hash differs")
    qualification_payload = json.loads(qualification.read_text())
    if (
        qualification_payload.get("schema") != "speck32-64-metal-qualification-v1"
        or qualification_payload.get("evidence_stage")
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
        or qualification_payload.get("information_boundary", {}).get(
            "production_target_selected"
        )
        is not False
    ):
        raise RuntimeError("A237 qualification semantic gate differs")
    if _file_sha256(native_source) != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A237 native source anchor hash differs")

    key2_known_upper6, key3, plaintext_words, known_material_sha256 = (
        _known_material()
    )
    unknown_assignment = secrets.randbits(UNKNOWN_BITS)
    target_words = _target_words(
        unknown_assignment, key2_known_upper6, key3, plaintext_words
    )
    control_words = list(target_words)
    control_words[-1] ^= 1
    target_raw = np.array(target_words, dtype="<u2").tobytes()
    control_raw = np.array(control_words, dtype="<u2").tobytes()
    public_challenge = {
        "cipher": "Speck32/64",
        "rounds": VARIANT.full_rounds,
        "plaintext_blocks": PLAINTEXT_BLOCKS,
        "plaintext_words_xy_order": plaintext_words,
        "target_ciphertext_words_xy_order": target_words,
        "control_ciphertext_words_xy_order": control_words,
        "target_ciphertext_little_u16_sha256": _sha256(target_raw),
        "control_ciphertext_little_u16_sha256": _sha256(control_raw),
        "known_material_derivation_label": KNOWN_MATERIAL_LABEL,
        "known_material_derivation_sha256": known_material_sha256,
        "known_key2_upper6": key2_known_upper6,
        "known_key3": key3,
        "unknown_key0_bits": 16,
        "unknown_key1_bits": 16,
        "unknown_key2_low_bits": OUTER_BITS,
        "unknown_assignment_bits": UNKNOWN_BITS,
        "known_master_key_bits": KNOWN_KEY_BITS,
        "candidate_encoding": (
            "assignment=(key2_low10<<32)|(key1<<16)|key0"
        ),
        "unknown_assignment_included": False,
        "unknown_key0_included": False,
        "unknown_key1_included": False,
        "unknown_key2_low10_included": False,
        "control_relation": "target_ciphertext_final_word_xor_0x0001",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "Speck32/64_block_cipher",
        "rounds": VARIANT.full_rounds,
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
        "result_capacity_per_batch": 64,
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
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A237_candidate_execution",
        "primary_sources": {
            "algorithm_and_Speck32_64_test_vector": (
                "https://eprint.iacr.org/2013/404.pdf"
            ),
            "official_NSA_publications_index": (
                "https://nsacyber.github.io/simon-speck/publications/"
            ),
        },
        "anchors": {
            "qualification": {
                "filename": QUALIFICATION_FILENAME,
                "sha256": QUALIFICATION_SHA256,
            },
            "native_host": {
                "filename": NATIVE_SOURCE_FILENAME,
                "sha256": NATIVE_SOURCE_SHA256,
            },
        },
        "public_challenge": public_challenge,
        "public_challenge_sha256": public_challenge_sha256,
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": "fresh_fullround_42_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_independent_three_block_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "pre_target_official_KAT_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "candidate_execution_against_public_A237_target_before_freeze": False,
            "all_2^42_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "independent_three_block_confirmation_required": True,
            "bit_flipped_control_required": True,
            "authentic_AI_native_causal_artifact_required": True,
            "authentic_CausalReader_reopen_required": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_ciphertexts": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_protocol_builder": False,
            "unknown_assignment_available_to_runner_before_execution": False,
            "A237_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
        },
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            research_root
            / "configs"
            / "speck32_64_metal_width42_recovery_v1.json"
        ),
    )
    parser.add_argument(
        "--qualification",
        type=Path,
        default=(
            research_root / "results" / "v1" / QUALIFICATION_FILENAME
        ),
    )
    parser.add_argument(
        "--native-source",
        type=Path,
        default=Path(__file__).with_name(NATIVE_SOURCE_FILENAME),
    )
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"A237 protocol already exists: {args.output}")
    protocol = build_protocol(
        qualification=args.qualification, native_source=args.native_source
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "unknown_assignment_in_output": False,
                "protocol_state": protocol["protocol_state"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
