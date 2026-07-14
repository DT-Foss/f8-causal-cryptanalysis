#!/usr/bin/env python3
"""Create the one-shot pre-execution protocol for A240 Threefish-256 W38."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import threefish256_encrypt

ATTEMPT_ID = "A240"
SCHEMA = "threefish256-metal-width38-recovery-protocol-v1"
UNKNOWN_BITS = 38
OUTER_BITS = 6
KNOWN_KEY_BITS = 256 - UNKNOWN_BITS
INNER_CANDIDATES = 1 << 32
OUTER_SLICES = 1 << OUTER_BITS
LOGICAL_CANDIDATES = 1 << UNKNOWN_BITS
STREAM_CANDIDATES = 1 << 28
FILTER_BITS = 256
KNOWN_MATERIAL_LABEL = "threefish256/a240/fullround/w38/known-material/v1"
QUALIFICATION_FILENAME = "threefish256_metal_qualification_v1.json"
QUALIFICATION_SHA256 = "1ef2c82a70f4fbb394c6b0cd490ec2e38c57222812a66d8002ff0fd1c2d52a1b"
NATIVE_SOURCE_FILENAME = "threefish256_metal_native.swift"
NATIVE_SOURCE_SHA256 = "bcab26af8232b08324165b93f751d48ecdf1895ce6959924293fbfd15e44fbda"
MASK64 = (1 << 64) - 1


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


def _known_material() -> tuple[int, list[int], list[int], list[int], str]:
    raw = hashlib.shake_256(KNOWN_MATERIAL_LABEL.encode()).digest(80)
    words = [int.from_bytes(raw[offset : offset + 8], "little") for offset in range(0, 80, 8)]
    key0_upper26 = words[0] & (MASK64 ^ ((1 << UNKNOWN_BITS) - 1))
    key1_to_3 = words[1:4]
    tweak = words[4:6]
    plaintext = words[6:10]
    return key0_upper26, key1_to_3, tweak, plaintext, _sha256(raw)


def build_protocol(*, qualification: Path, native_source: Path) -> dict[str, Any]:
    if _file_sha256(qualification) != QUALIFICATION_SHA256:
        raise RuntimeError("A240 qualification anchor hash differs")
    qualification_payload = json.loads(qualification.read_text())
    if (
        qualification_payload.get("schema") != "threefish256-metal-qualification-v1"
        or qualification_payload.get("evidence_stage")
        != "THREEFISH256_METAL_PRE_TARGET_QUALIFICATION"
        or qualification_payload.get("official_kat_gates", {}).get("all_passed")
        is not True
        or qualification_payload.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or qualification_payload.get("boundary_filter_gate", {}).get("exact")
        is not True
        or qualification_payload.get("information_boundary", {}).get(
            "production_target_selected"
        )
        is not False
    ):
        raise RuntimeError("A240 qualification semantic gate differs")
    if _file_sha256(native_source) != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A240 native source anchor hash differs")

    key0_upper26, key1_to_3, tweak, plaintext, known_sha = _known_material()
    unknown_assignment = secrets.randbits(UNKNOWN_BITS)
    key = [key0_upper26 | unknown_assignment, *key1_to_3]
    target = threefish256_encrypt(plaintext, key, tweak, 72)
    control = list(target)
    control[-1] ^= 1
    public_challenge = {
        "cipher": "Threefish-256",
        "rounds": 72,
        "plaintext_words": plaintext,
        "target_ciphertext_words": target,
        "control_ciphertext_words": control,
        "target_ciphertext_little_u64_sha256": _sha256(
            np.array(target, dtype="<u8").tobytes()
        ),
        "control_ciphertext_little_u64_sha256": _sha256(
            np.array(control, dtype="<u8").tobytes()
        ),
        "known_material_derivation_label": KNOWN_MATERIAL_LABEL,
        "known_material_derivation_sha256": known_sha,
        "known_key0_upper26": key0_upper26,
        "known_key_words_1_through_3": key1_to_3,
        "known_tweak_words": tweak,
        "unknown_key0_low_bits": UNKNOWN_BITS,
        "unknown_assignment_bits": UNKNOWN_BITS,
        "known_master_key_bits": KNOWN_KEY_BITS,
        "candidate_encoding": "assignment=(key0_bits32_37<<32)|key0_low32",
        "unknown_assignment_included": False,
        "unknown_key0_low38_included": False,
        "control_relation": "target_ciphertext_final_word_xor_0x1",
    }
    challenge_sha = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "Threefish-256_block_cipher",
        "rounds": 72,
        "unknown_key_bits": UNKNOWN_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "known_tweak_bits": 128,
        "known_plaintext_ciphertext_pairs": 1,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_key0_bits32_37_slice_count": OUTER_SLICES,
        "inner_key0_low32_candidate_count_per_slice": INNER_CANDIDATES,
        "combined_assignment_encoding": "key0_bits32_37_times_2^32_plus_key0_low32",
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
        "full_confirmation": "independent_Python_Threefish256_all_256_output_bits",
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A240_candidate_execution",
        "primary_sources": {
            "Threefish_and_Skein_specification": (
                "https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf"
            ),
            "official_submission_KATs": (
                "Skein_1.3_NIST_submission/KAT_MCT/skein_golden_kat_short_internals.txt"
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
        "public_challenge_sha256": challenge_sha,
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": "fresh_fullround_38_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_independent_256_bit_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "pre_target_two_official_KATs_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "candidate_execution_against_public_A240_target_before_freeze": False,
            "all_2^38_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "independent_256_bit_confirmation_required": True,
            "bit_flipped_control_required": True,
            "authentic_AI_native_causal_artifact_required": True,
            "authentic_CausalReader_reopen_required": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_ciphertext": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_protocol_builder": False,
            "unknown_assignment_available_to_runner_before_execution": False,
            "A240_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
        },
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "configs" / "threefish256_metal_width38_recovery_v1.json",
    )
    parser.add_argument(
        "--qualification",
        type=Path,
        default=research_root / "results" / "v1" / QUALIFICATION_FILENAME,
    )
    parser.add_argument(
        "--native-source",
        type=Path,
        default=Path(__file__).with_name(NATIVE_SOURCE_FILENAME),
    )
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"A240 protocol already exists: {args.output}")
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
