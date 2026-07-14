#!/usr/bin/env python3
"""A240: fresh complete-domain full-round Threefish-256 W38 recovery."""

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

from arx_carry_leak.ciphers import threefish256_encrypt


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUAL = _import_sibling(
    "threefish256_metal_qualification.py", "threefish256_a240_qualification"
)

ATTEMPT_ID = "A240"
SCHEMA = "threefish256-metal-width38-recovery-v1"
PROTOCOL_SCHEMA = "threefish256-metal-width38-recovery-protocol-v1"
PROTOCOL_FILENAME = "threefish256_metal_width38_recovery_v1.json"
PROTOCOL_SHA256 = "8e3c9811d7c588a0d6f89feeec7b5d0233c970c12d6d2f0db66a78f3cd9e3d32"
PUBLIC_CHALLENGE_SHA256 = "b7bb97880b48f943e65236c7846fcade0c7131cc8dda9fce8ea5c8d6772ecc3e"
QUALIFICATION_FILENAME = "threefish256_metal_qualification_v1.json"
QUALIFICATION_SHA256 = "1ef2c82a70f4fbb394c6b0cd490ec2e38c57222812a66d8002ff0fd1c2d52a1b"
NATIVE_SOURCE_FILENAME = "threefish256_metal_native.swift"
NATIVE_SOURCE_SHA256 = "bcab26af8232b08324165b93f751d48ecdf1895ce6959924293fbfd15e44fbda"
UNKNOWN_BITS = 38
OUTER_BITS = 6
KNOWN_KEY_BITS = 218
OUTER_SLICES = 1 << OUTER_BITS
INNER_CANDIDATES = 1 << 32
LOGICAL_CANDIDATES = 1 << UNKNOWN_BITS
STREAM_CANDIDATES = 1 << 28
RESULT_CAPACITY = 64
FILTER_BITS = 256
RESULT_FILENAME = "threefish256_metal_width38_recovery_v1.json"
CAUSAL_FILENAME = "threefish256_metal_width38_recovery_v1.causal"
CHECKPOINT_FILENAME = "threefish256_metal_width38_recovery_v1.checkpoint.json"
REPORT_FILENAME = "FULLROUND_THREEFISH256_METAL_WIDTH38_RECOVERY_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
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


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value)
    temporary.replace(path)


def _execution_plan() -> dict[str, Any]:
    return {
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
        "result_capacity_per_batch": RESULT_CAPACITY,
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


def _known_material(label: str) -> tuple[int, list[int], list[int], list[int], str]:
    raw = hashlib.shake_256(label.encode()).digest(80)
    words = [int.from_bytes(raw[offset : offset + 8], "little") for offset in range(0, 80, 8)]
    key0_upper26 = words[0] & (MASK64 ^ ((1 << UNKNOWN_BITS) - 1))
    return key0_upper26, words[1:4], words[4:6], words[6:10], _sha256(raw)


def _validate_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
        or challenge.get("cipher") != "Threefish-256"
        or challenge.get("rounds") != 72
        or len(challenge.get("plaintext_words", [])) != 4
        or len(challenge.get("target_ciphertext_words", [])) != 4
        or len(challenge.get("control_ciphertext_words", [])) != 4
        or len(challenge.get("known_key_words_1_through_3", [])) != 3
        or len(challenge.get("known_tweak_words", [])) != 2
        or challenge.get("unknown_assignment_bits") != UNKNOWN_BITS
        or challenge.get("known_master_key_bits") != KNOWN_KEY_BITS
        or challenge.get("known_key0_upper26", 1) & ((1 << UNKNOWN_BITS) - 1)
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key0_low38_included") is not False
    ):
        raise RuntimeError("A240 public challenge identity gate failed")
    key0, key_rest, tweak, plaintext, derived_sha = _known_material(
        challenge["known_material_derivation_label"]
    )
    if (
        key0 != challenge["known_key0_upper26"]
        or key_rest != challenge["known_key_words_1_through_3"]
        or tweak != challenge["known_tweak_words"]
        or plaintext != challenge["plaintext_words"]
        or derived_sha != challenge["known_material_derivation_sha256"]
    ):
        raise RuntimeError("A240 public known-material derivation gate failed")
    target = np.array(challenge["target_ciphertext_words"], dtype="<u8")
    control = np.array(challenge["control_ciphertext_words"], dtype="<u8")
    expected_control = target.copy()
    expected_control[-1] ^= np.uint64(1)
    if (
        _sha256(target.tobytes())
        != challenge["target_ciphertext_little_u64_sha256"]
        or _sha256(control.tobytes())
        != challenge["control_ciphertext_little_u64_sha256"]
        or not np.array_equal(control, expected_control)
    ):
        raise RuntimeError("A240 target/control byte gate failed")


def analyze(results_dir: Path) -> dict[str, Any]:
    research_root = Path(__file__).parents[1]
    protocol_path = research_root / "configs" / PROTOCOL_FILENAME
    if _file_sha256(protocol_path) != PROTOCOL_SHA256:
        raise RuntimeError("A240 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_text())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A240_candidate_execution"
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("anchors", {}).get("qualification", {}).get("sha256")
        != QUALIFICATION_SHA256
        or protocol.get("anchors", {}).get("native_host", {}).get("sha256")
        != NATIVE_SOURCE_SHA256
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A240_candidate_outcomes_used_before_protocol_freeze")
        is not False
    ):
        raise RuntimeError("A240 frozen protocol identity gate failed")
    qualification_path = results_dir / QUALIFICATION_FILENAME
    native_path = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    if (
        _file_sha256(qualification_path) != QUALIFICATION_SHA256
        or _file_sha256(native_path) != NATIVE_SOURCE_SHA256
    ):
        raise RuntimeError("A240 implementation anchor hash differs")
    qualification = json.loads(qualification_path.read_text())
    if (
        qualification.get("official_kat_gates", {}).get("all_passed") is not True
        or qualification.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or qualification.get("boundary_filter_gate", {}).get("exact") is not True
    ):
        raise RuntimeError("A240 retained qualification gate failed")
    challenge = protocol["public_challenge"]
    _validate_challenge(challenge)
    plan = _execution_plan()
    if (
        protocol.get("execution_plan") != plan
        or protocol.get("execution_plan_sha256") != _canonical_sha256(plan)
    ):
        raise RuntimeError("A240 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "public_challenge": challenge,
        "execution_plan": plan,
        "anchor_gates": {
            "protocol_sha256": PROTOCOL_SHA256,
            "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
            "qualification_sha256": QUALIFICATION_SHA256,
            "native_source_sha256": NATIVE_SOURCE_SHA256,
        },
        "candidate_execution_started": False,
    }


def _key_words_for_outer(challenge: dict[str, Any], outer: int) -> np.ndarray:
    key0 = int(challenge["known_key0_upper26"]) | (outer << 32)
    halves = _QUAL._halves([key0, *challenge["known_key_words_1_through_3"]])
    halves[0] = 0
    return halves


def _configure_outer(
    host: _QUAL.MetalThreefish256Host,
    challenge: dict[str, Any],
    outer: int,
    target: np.ndarray,
    control: np.ndarray,
) -> None:
    if outer < 0 or outer >= OUTER_SLICES:
        raise ValueError("A240 outer assignment is outside the six-bit domain")
    host.configure(
        plaintext=_QUAL._halves(challenge["plaintext_words"]),
        target=target,
        control=control,
        key_words=_key_words_for_outer(challenge, outer),
        tweak_words=_QUAL._halves(challenge["known_tweak_words"]),
    )


def _scalar_output(challenge: dict[str, Any], assignment: int) -> np.ndarray:
    if assignment < 0 or assignment >= LOGICAL_CANDIDATES:
        raise ValueError("A240 assignment is outside the W38 domain")
    key = [
        int(challenge["known_key0_upper26"]) | assignment,
        *challenge["known_key_words_1_through_3"],
    ]
    return np.array(
        threefish256_encrypt(
            challenge["plaintext_words"], key, challenge["known_tweak_words"], 72
        ),
        dtype=np.uint64,
    )


def _mapping_gate(
    host: _QUAL.MetalThreefish256Host, challenge: dict[str, Any]
) -> dict[str, Any]:
    first = 184_032
    count = 256
    offset = 73
    rows = []
    for outer in (0, OUTER_SLICES // 2, OUTER_SLICES - 1):
        expected64 = np.stack(
            [
                _scalar_output(challenge, (outer << 32) | inner)
                for inner in range(first, first + count)
            ]
        )
        expected = np.stack([_QUAL._halves(row) for row in expected64])
        target = expected[offset].copy()
        control = target.copy()
        control[-1] ^= np.uint32(1)
        _configure_outer(host, challenge, outer, target, control)
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        if (
            not np.array_equal(observed, expected)
            or filtered["factual"] != [first + offset]
            or filtered["control"] != []
        ):
            raise RuntimeError("A240 synthetic outer-slice mapping gate failed")
        rows.append(
            {
                "outer_key0_bits32_37": outer,
                "first_inner_candidate": first,
                "candidate_count": count,
                "complete_output_bits_checked": int(observed.size * 32),
                "factual_inner_candidate": first + offset,
                "factual_combined_assignment": (outer << 32) | (first + offset),
                "control_matches": [],
                "output_sha256": _sha256(
                    observed.astype("<u4", copy=False).tobytes()
                ),
            }
        )
    return {
        "outer_values_checked": [row["outer_key0_bits32_37"] for row in rows],
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": sum(
            row["complete_output_bits_checked"] for row in rows
        ),
        "rows": rows,
        "exact_scalar_filter_and_mapping_identity": True,
    }


def _confirm(
    challenge: dict[str, Any], target: np.ndarray, assignment: int
) -> dict[str, Any]:
    output = _scalar_output(challenge, assignment)
    return {
        "combined_assignment": assignment,
        "key0_low32": assignment & 0xFFFFFFFF,
        "key0_bits32_37": assignment >> 32,
        "complete_block_match": bool(np.array_equal(output, target)),
        "output_words_checked": 4,
        "output_bits_checked": FILTER_BITS,
        "candidate_output_little_u64_sha256": _sha256(
            output.astype("<u8").tobytes()
        ),
        "target_output_little_u64_sha256": _sha256(
            target.astype("<u8").tobytes()
        ),
        "implementation": "independent_Python_canonical_Threefish256",
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "threefish256-metal-width38-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "target_ciphertext_sha256": challenge[
            "target_ciphertext_little_u64_sha256"
        ],
        "control_ciphertext_sha256": challenge[
            "control_ciphertext_little_u64_sha256"
        ],
        "unknown_key_bits": UNKNOWN_BITS,
        "stream_candidates": STREAM_CANDIDATES,
        "result_capacity": RESULT_CAPACITY,
    }


def _enumerate_domain(
    *,
    host: _QUAL.MetalThreefish256Host,
    challenge: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    target64 = np.array(challenge["target_ciphertext_words"], dtype=np.uint64)
    control64 = np.array(challenge["control_ciphertext_words"], dtype=np.uint64)
    target = _QUAL._halves(target64)
    control = _QUAL._halves(control64)
    next_assignment = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    gpu_seconds = 0.0
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A240 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        gpu_seconds = float(checkpoint.get("gpu_seconds", 0.0))
        if (
            next_assignment < 0
            or next_assignment > LOGICAL_CANDIDATES
            or next_assignment % STREAM_CANDIDATES != 0
            or checkpoint.get("factual_filtered", [])
            or checkpoint.get("control_filtered", [])
            or gpu_seconds < 0.0
        ):
            raise RuntimeError("A240 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    durable_next = next_assignment
    durable_gpu_seconds = gpu_seconds
    configured_outer: int | None = None
    wall_start = time.perf_counter()
    while next_assignment < LOGICAL_CANDIDATES:
        outer = next_assignment >> 32
        first_inner = next_assignment & 0xFFFFFFFF
        count = min(
            STREAM_CANDIDATES,
            INNER_CANDIDATES - first_inner,
            LOGICAL_CANDIDATES - next_assignment,
        )
        if configured_outer != outer:
            _configure_outer(host, challenge, outer, target, control)
            configured_outer = outer
        response = host.filter(first_inner, count)
        gpu_seconds += float(response["gpu_seconds"])
        factual_filtered.extend(
            (outer << 32) | int(candidate) for candidate in response["factual"]
        )
        control_filtered.extend(
            (outer << 32) | int(candidate) for candidate in response["control"]
        )
        next_assignment += count
        if not factual_filtered and not control_filtered:
            durable_next = next_assignment
            durable_gpu_seconds = gpu_seconds
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": durable_next,
                "factual_filtered": [],
                "control_filtered": [],
                "gpu_seconds": durable_gpu_seconds,
                "candidate_matches_persisted": False,
            },
        )
        if (
            next_assignment % (4 * INNER_CANDIDATES) == 0
            or next_assignment == LOGICAL_CANDIDATES
        ):
            print(
                f"A240 Metal slices={next_assignment // INNER_CANDIDATES}/{OUTER_SLICES} "
                f"assignments={next_assignment}/{LOGICAL_CANDIDATES}",
                flush=True,
            )
    wall_seconds = time.perf_counter() - wall_start
    factual_confirmations = [
        _confirm(challenge, target64, assignment) for assignment in factual_filtered
    ]
    control_confirmations = [
        _confirm(challenge, control64, assignment) for assignment in control_filtered
    ]
    factual_full = [
        row["combined_assignment"]
        for row in factual_confirmations
        if row["complete_block_match"]
    ]
    control_full = [
        row["combined_assignment"]
        for row in control_confirmations
        if row["complete_block_match"]
    ]
    if not factual_full:
        raise RuntimeError("A240 complete-domain Reader returned no exact assignment")
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
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError(
                "dotcausal 0.3.1 is required; install requirements.txt"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    io_path = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_causal(
    path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    writer = CausalWriter(api_id="a240")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete W38 enumeration plus exact 256-bit confirmation establishes residual-key recovery.",
        pattern=["complete_domain_enumeration", "independent_exact_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_rejection",
        description="The identical search rejecting a one-bit control separates the factual relation.",
        pattern=["same_complete_search", "zero_exact_control_models"],
        conclusion="target_specific_recovery_evidence",
        confidence_modifier=1.0,
    )
    execution = payload["execution"]
    rows = [
        (
            "A238:pre_target_Metal_qualification",
            "two_official_KATs_plus_scalar_and_boundary_gates",
            "A240:qualified_fullround_Threefish256_enumerator",
            QUALIFICATION_SHA256,
            "72 rounds; exact 256-bit output identity",
            "implementation equivalence",
        ),
        (
            "A240:frozen_public_W38_relation",
            "complete_domain_enumeration",
            "A240:factual_filter_candidate_set",
            payload["execution_sha256"],
            f"{LOGICAL_CANDIDATES} assignments; no early stop",
            "full-round residual-key enumeration",
        ),
        (
            "A240:factual_filter_candidate_set",
            "independent_exact_confirmation",
            "A240:unique_verified_38_bit_residual_key",
            payload["confirmation_sha256"],
            "one block; all 256 output bits",
            "independent key confirmation",
        ),
        (
            "A240:one_bit_flipped_control_relation",
            "same_complete_search",
            "A240:control_filter_candidate_set",
            payload["execution_sha256"],
            f"{LOGICAL_CANDIDATES} assignments; identical plan",
            "matched negative control",
        ),
        (
            "A240:control_filter_candidate_set",
            "zero_exact_control_models",
            "A240:control_relation_rejected",
            payload["confirmation_sha256"],
            "zero independently confirmed assignments",
            "matched negative control",
        ),
    ]
    for trigger, mechanism, outcome, source_hash, quantification, domain in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source_hash,
            quantification=quantification,
            evidence=json.dumps(
                {
                    "factual": execution["factual_full_matches"],
                    "control": execution["control_full_matches"],
                },
                sort_keys=True,
            ),
            domain=domain,
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A240:frozen_public_W38_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome="A240:unique_verified_38_bit_residual_key",
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after full execution and 256-bit confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A240:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="A240:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_rejection",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        "A240 verified recovery chain",
        [
            "A240:frozen_public_W38_relation",
            "complete_domain_enumeration",
            "independent_exact_confirmation",
            "A240:unique_verified_38_bit_residual_key",
        ],
    )
    writer.add_cluster(
        "A240 matched control chain",
        [
            "A240:one_bit_flipped_control_relation",
            "same_complete_search",
            "zero_exact_control_models",
            "A240:control_relation_rejected",
        ],
    )
    writer.add_gap(
        "A240:unique_verified_38_bit_residual_key",
        "next_required_gain",
        "prospectively_selected_strict_subset_of_W38_domain",
        1.0,
        [
            "Which typed Threefish state-boundary operator ranks the held-out W38 slice?",
            "Does a frozen constraint reader reduce executed W38 candidates?",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(False)
    all_rows = reader.get_all_triplets(True)
    materialized = [row for row in reader._triplets if row.get("is_inferred")]
    if (
        reader.version != 1
        or reader.api_id != "a240"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A240 authentic Causal Reader reopen gate failed")
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
        "reader_source": source,
        "personal_semantic_readback": {
            "recovery_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A240:unique_verified_38_bit_residual_key"
            ],
            "control_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A240:control_relation_rejected"
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
            "# A240 — Full-round Threefish-256 W38 residual-key recovery",
            "",
            "A fresh public relation was frozen before candidate execution. The native Apple Metal runner executed every one of the `2^38` residual-key assignments for standard 72-round Threefish-256 without early stopping.",
            "",
            "## Result",
            "",
            f"- Complete domain: **{execution['logical_candidate_count']:,} / {execution['logical_candidate_count']:,}**",
            f"- Recovered assignment: **`{recovery['recovered_combined_assignments'][0]}`**",
            f"- Unknown / known master-key bits: **{UNKNOWN_BITS} / {KNOWN_KEY_BITS}**",
            f"- Independent confirmation: **{FILTER_BITS} output bits**",
            f"- Exact factual / control models: **{len(execution['factual_full_matches'])} / {len(execution['control_full_matches'])}**",
            f"- GPU time: **{execution['gpu_seconds']:.3f} s**",
            f"- Volatile wall time: **{execution['volatile_wall_seconds']:.3f} s**",
            "",
            "## Exact scope",
            "",
            "This is executed full-round partial-key recovery in a 38-bit residual domain: the low 38 bits of `K0` are unknown; the upper 26 bits of `K0`, `K1..K3`, and the 128-bit tweak are known. The complete residual domain was enumerated, so the result is a commodity-hardware full-round recovery point rather than an asymptotic search reduction.",
            "",
            "## AI-native Causal artifact",
            "",
            f"- Reader integrity gate: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized inferred: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Rules / clusters / gaps: **{causal['embedded_rules']} / {causal['clusters']} / {causal['gaps']}**",
            "- The retained next gap is a prospectively frozen strict-subset W38 reader.",
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
    analysis = analyze(results_dir)
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalThreefish256Host(executable)
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
        raise RuntimeError("A240 complete-domain recovery gate failed")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "THREEFISH256_FULLROUND_38BIT_RESIDUAL_KEY_RECOVERY_RETAINED",
        "result": (
            "The native Metal runner executed the complete fresh 38-bit residual "
            "domain for standard 72-round Threefish-256 and independently "
            "confirmed the unique assignment over all 256 output bits."
        ),
        "scope": (
            "Full-round Threefish-256 partial-key recovery with low 38 bits of "
            "K0 unknown, 218 key bits and the tweak known, complete 2^38 enumeration."
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
                if key
                not in {
                    "factual_confirmations",
                    "control_confirmations",
                    "gpu_seconds",
                    "volatile_wall_seconds",
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
            "recovered_key0_low32": [
                value & 0xFFFFFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key0_bits32_37": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "recovery_accepted_only_after_complete_domain_execution": True,
            "candidate_identities_persisted_in_checkpoint": False,
            "unknown_assignment_source_was_discarded_before_runner_construction": True,
        },
    }
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_text(report_output, _report(payload))
    checkpoint_path.unlink(missing_ok=True)
    _Writer, Reader, _source = _load_dotcausal(dotcausal_src)
    reader = Reader(str(causal_output), verify_integrity=True)
    if (
        json.loads(output.read_text()) != payload
        or _file_sha256(causal_output) != payload["causal"]["file_sha256"]
        or len(reader.get_all_triplets(True)) != 7
        or not report_output.is_file()
    ):
        raise RuntimeError("A240 final artifact reopen gate failed")
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
        default=research_root / "build" / "threefish256_metal_width38",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.analyze_only:
        print(json.dumps(analyze(args.results_dir), indent=2, sort_keys=True))
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
