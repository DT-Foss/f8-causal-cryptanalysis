#!/usr/bin/env python3
"""Prospective complete-domain recovery of one unknown ChaCha20 key word."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
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


_A177 = _import_sibling(
    "shake256_native_fullround_width32_prospective.py",
    "chacha20_partial_key_a177_anchor",
)
_A119 = _import_sibling(
    "chacha20_fullround_feedforward_reader.py",
    "chacha20_partial_key_a119_base",
)
_BITSLICED = _A177._BITSLICED

ATTEMPT_ID = "A178"
SCHEMA = "chacha20-native-fullround-partial-key-recovery-v1"
PROTOCOL_SCHEMA = "chacha20-native-fullround-partial-key-recovery-protocol-v1"
PROTOCOL_FILENAME = "chacha20_native_fullround_partial_key_recovery_v1.json"
PROTOCOL_SHA256 = "4fb2d61f104d5aa424b7ba269fad446e086025fe40dcf4091d1335b71f729573"
A177_FILENAME = _A177.RESULT_FILENAME
A177_SHA256 = "d6b85ca7f15bc198513cd05100187f2ccc0ab97d1f22a906383ccd4a62eda544"
A119_FILENAME = "chacha20_fullround_feedforward_reader_v1.json"
A119_SHA256 = "af1a7199c5eb45daf415246565b9bf2f4e0eb6a723ffc92bba8f8d7452a3c3e2"
A119_CAUSAL_FILENAME = "chacha20_fullround_feedforward_reader_v1.causal"
A119_CAUSAL_SHA256 = "ed86f9b3fcae2e06a099d841aece72b896b86a3611ced1f10314fc66d72ed302"
NATIVE_SOURCE_FILENAME = "chacha20_bitsliced_native.c"
NATIVE_SOURCE_SHA256 = "ec2759fc66e86b7b50ea7fece66b2994d1961bb5b84d9081aff3514f25cacb8e"
PUBLIC_RELATION_SHA256 = "58f9244e4a41f2e04f7d6350c628c40feafa252affdcdb25b0a2699862a57b48"
UNKNOWN_KEY_WORD_INDEX = 0
UNKNOWN_INITIAL_LANE = 4
WINDOW_BITS = 32
THREADS = 10
STREAM_PACKS = 1 << 20
FILTER_WORDS = 2
RESULT_FILENAME = "chacha20_native_fullround_partial_key_recovery_v1.json"
CAUSAL_FILENAME = "chacha20_native_fullround_partial_key_recovery_v1.causal"
CHECKPOINT_FILENAME = "chacha20_native_fullround_partial_key_recovery_v1.checkpoint.json"

_U32_PTR = ctypes.POINTER(ctypes.c_uint32)
_U64_PTR = ctypes.POINTER(ctypes.c_uint64)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A177._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A177._file_sha256(path)


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    a177_path = results_dir / A177_FILENAME
    a119_path = results_dir / A119_FILENAME
    a119_causal_path = results_dir / A119_CAUSAL_FILENAME
    source_path = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    observed = {
        "A177_result_sha256": _file_sha256(a177_path),
        "A119_result_sha256": _file_sha256(a119_path),
        "A119_causal_sha256": _file_sha256(a119_causal_path),
        "native_source_sha256": _file_sha256(source_path),
    }
    expected = {
        "A177_result_sha256": A177_SHA256,
        "A119_result_sha256": A119_SHA256,
        "A119_causal_sha256": A119_CAUSAL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A178 A119/A177/native anchor hash gate failed")

    a177 = json.loads(a177_path.read_bytes())
    a119 = json.loads(a119_path.read_bytes())
    if (
        a177.get("schema") != _A177.SCHEMA
        or a177.get("evidence_stage") != "SHAKE256_NATIVE_FULLROUND_WIDTH32_RECONSTRUCTION_RETAINED"
        or a177.get("execution", {}).get("complete_domain_executed") is not True
        or a119.get("schema") != "chacha20-fullround-feedforward-reader-v1"
        or a119.get("evidence_stage") != "FULLROUND_PUBLIC_AND_KNOWN_KEY_READERS_RETAINED"
        or a119.get("parameters", {}).get("rounds") != 20
    ):
        raise RuntimeError("A178 retained A119/A177 mechanism gate failed")

    reader = CryptoCausalReader(a119_causal_path)
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in reader.triplets(include_inferred=False)
        if row["mechanism"] == "reader_executable_complete_core_inverse"
    ]
    if (
        reader.file_sha256 != A119_CAUSAL_SHA256
        or not reader.verify_provenance()
        or len(recipes) != 1
        or recipes[0].get("rounds") != 20
        or recipes[0].get("word_bits") != 32
    ):
        raise RuntimeError("A178 ChaCha20 Causal Reader anchor gate failed")
    return {
        **observed,
        "A119_causal_graph_sha256": reader.graph_sha256,
        "A119_causal_provenance_verified": True,
        "A119_full_feedforward_recipe": recipes[0],
    }


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A178 frozen protocol hash differs")
    protocol = json.loads(raw)
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A178_candidate_execution"
        or protocol.get("anchors", {}).get("A177", {}).get("sha256") != A177_SHA256
        or protocol.get("anchors", {}).get("A119", {}).get("sha256") != A119_SHA256
        or protocol.get("native_kernel", {}).get("source_sha256") != NATIVE_SOURCE_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_RELATION_SHA256
        or protocol.get("public_challenge", {}).get("unknown_word_included") is not False
        or protocol.get("execution_plan", {}).get("complete_domain_required") is not True
        or protocol.get("information_boundary", {}).get(
            "A178_candidate_outcomes_used_before_protocol_freeze"
        )
        is not False
    ):
        raise RuntimeError("A178 frozen protocol identity gate failed")
    return protocol


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_RELATION_SHA256
        or challenge.get("unknown_key_word_index") != UNKNOWN_KEY_WORD_INDEX
        or challenge.get("unknown_initial_lane") != UNKNOWN_INITIAL_LANE
        or challenge.get("unknown_word_included") is not False
        or len(challenge.get("known_key_words_1_through_7", [])) != 7
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != 16
        or len(challenge.get("control_target_words", [])) != 16
        or challenge.get("filter_words") != FILTER_WORDS
        or challenge.get("filter_bits") != FILTER_WORDS * 32
        or challenge["control_target_words"][0] != (challenge["target_words"][0] ^ 1)
        or challenge["control_target_words"][1:] != challenge["target_words"][1:]
    ):
        raise RuntimeError("A178 public challenge gate failed")
    target = np.array(challenge["target_words"], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(target.astype("<u4", copy=False).tobytes()) != challenge["target_block_sha256"]
        or _sha256(control.astype("<u4", copy=False).tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A178 public target byte fingerprint differs")


def _initial_from_challenge(challenge: dict[str, Any]) -> np.ndarray:
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = _A119.CONSTANTS
    initial[UNKNOWN_INITIAL_LANE] = np.uint32(0)
    initial[5:12] = np.array(challenge["known_key_words_1_through_7"], dtype=np.uint32)
    initial[12] = np.uint32(challenge["counter"])
    initial[13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    return initial


def _execution_plan() -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    pack_count = candidate_count // 64
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": 20,
        "unknown_key_word_bits": WINDOW_BITS,
        "known_key_bits": 224,
        "counter_bits_known": 32,
        "nonce_bits_known": 96,
        "logical_candidate_count": candidate_count,
        "candidates_per_machine_word": 64,
        "packed_state_count": pack_count,
        "native_threads": THREADS,
        "stream_pack_count": STREAM_PACKS,
        "stream_batch_count": pack_count // STREAM_PACKS,
        "maximum_mask_memory_bytes": STREAM_PACKS * 16,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "full_confirmation": "independent_NumPy_ChaCha20_all_512_output_bits",
        "control_target_required": True,
        "wallclock_excluded_from_canonical_result": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = protocol["public_challenge"]
    _validate_public_challenge(challenge)
    plan = _execution_plan()
    if protocol["execution_plan"] != plan or protocol["execution_plan_sha256"] != _canonical_sha256(
        plan
    ):
        raise RuntimeError("A178 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "initial_template": _initial_from_challenge(challenge),
        "target": np.array(challenge["target_words"], dtype=np.uint32),
        "control_target": np.array(challenge["control_target_words"], dtype=np.uint32),
        "execution_plan": plan,
        "candidate_execution_started": False,
    }


def _compile_native(build_dir: Path, cc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    if source_sha != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A178 native source differs")
    compiler = shutil.which(cc)
    if compiler is None:
        raise FileNotFoundError(f"C compiler not found: {cc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / (
        f"libchacha20_bitslice_{source_sha[:16]}{_A177._NATIVE._shared_library_suffix()}"
    )
    base_flags = ["-O3", "-std=c11", "-fPIC", "-shared", "-pthread"]
    attempts = [["-mcpu=native", *base_flags], base_flags]
    selected_flags: list[str] | None = None
    diagnostics = []
    if not output.exists():
        for flags in attempts:
            result = subprocess.run(
                [compiler, *flags, str(source), "-o", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                selected_flags = flags
                break
            diagnostics.append(result.stderr.strip())
        if selected_flags is None:
            raise RuntimeError(
                "native ChaCha20 kernel compilation failed: "
                + " | ".join(filter(None, diagnostics))
            )
    else:
        selected_flags = base_flags
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("native ChaCha20 build produced no library")
    return output, {
        "source_sha256": source_sha,
        "language": "C11_POSIX_threads",
        "optimization": "O3",
        "candidate_pack_width": 64,
        "compiler_native_flag_attempted": True,
        "selected_flags": selected_flags,
    }


class NativeChaCha20Kernel:
    def __init__(self, path: Path):
        self.path = path
        self.library = ctypes.CDLL(str(path.resolve()))
        self.library.chacha20_bitslice_blocks64.argtypes = [_U32_PTR, _U32_PTR]
        self.library.chacha20_bitslice_blocks64.restype = ctypes.c_int
        self.library.chacha20_bitslice_filter.argtypes = [
            _U32_PTR,
            ctypes.c_uint,
            ctypes.c_uint64,
            ctypes.c_uint64,
            _U32_PTR,
            _U32_PTR,
            ctypes.c_uint,
            ctypes.c_uint,
            _U64_PTR,
            _U64_PTR,
        ]
        self.library.chacha20_bitslice_filter.restype = ctypes.c_int
        self.library.chacha20_bitslice_native_version.argtypes = []
        self.library.chacha20_bitslice_native_version.restype = ctypes.c_char_p
        if self.library.chacha20_bitslice_native_version() != b"chacha20-bitslice-native-v1":
            raise RuntimeError("unexpected native ChaCha20 kernel version")

    def blocks64(self, initial: np.ndarray) -> np.ndarray:
        values = np.ascontiguousarray(initial, dtype=np.uint32)
        if values.shape != (64, 16):
            raise ValueError("native ChaCha20 block gate requires uint32[64,16]")
        output = np.empty_like(values)
        code = self.library.chacha20_bitslice_blocks64(
            values.ctypes.data_as(_U32_PTR),
            output.ctypes.data_as(_U32_PTR),
        )
        if code != 0:
            raise RuntimeError(f"native ChaCha20 block gate returned {code}")
        return output

    def filter_masks(
        self,
        initial: np.ndarray,
        first_pack: int,
        pack_count: int,
        target: np.ndarray,
        control: np.ndarray,
        filter_words: int,
        threads: int,
    ) -> tuple[np.ndarray, np.ndarray]:
        initial_words = np.ascontiguousarray(initial, dtype=np.uint32).reshape(-1)
        target_words = np.ascontiguousarray(target, dtype=np.uint32).reshape(-1)
        control_words = np.ascontiguousarray(control, dtype=np.uint32).reshape(-1)
        if initial_words.shape != (16,) or target_words.shape != (16,):
            raise ValueError("native ChaCha20 initial/target must contain 16 words")
        if control_words.shape != (16,) or pack_count < 0 or threads < 1:
            raise ValueError("native ChaCha20 control/pack/thread inputs are invalid")
        factual = np.empty(pack_count, dtype=np.uint64)
        wrong = np.empty(pack_count, dtype=np.uint64)
        code = self.library.chacha20_bitslice_filter(
            initial_words.ctypes.data_as(_U32_PTR),
            UNKNOWN_INITIAL_LANE,
            first_pack,
            pack_count,
            target_words.ctypes.data_as(_U32_PTR),
            control_words.ctypes.data_as(_U32_PTR),
            filter_words,
            threads,
            factual.ctypes.data_as(_U64_PTR),
            wrong.ctypes.data_as(_U64_PTR),
        )
        if code != 0:
            raise RuntimeError(f"native ChaCha20 filter returned {code}")
        return factual, wrong


def _cross_implementation_gate(
    kernel: NativeChaCha20Kernel,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    initial = rng.integers(0, 1 << 32, size=(64, 16), dtype=np.uint32)
    expected = (_A119._core(initial.copy(), 20) + initial).astype(np.uint32)
    observed = kernel.blocks64(initial)
    if not np.array_equal(observed, expected):
        raise RuntimeError("native ChaCha20 cross-implementation gate failed")
    return {
        "states": 64,
        "words_checked": int(observed.size),
        "state_bits_checked": int(observed.size * 32),
        "exact_match": True,
        "input_sha256": _sha256(initial.astype("<u4").tobytes()),
        "output_sha256": _sha256(observed.astype("<u4").tobytes()),
    }


def _small_mask_gate(
    kernel: NativeChaCha20Kernel,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    initial = rng.integers(0, 1 << 32, size=16, dtype=np.uint32)
    actual = 173
    factual_initial = initial.copy()
    factual_initial[UNKNOWN_INITIAL_LANE] = np.uint32(actual)
    factual_target = (
        _A119._core(factual_initial.reshape(1, 16).copy(), 20) + factual_initial.reshape(1, 16)
    ).astype(np.uint32)[0]
    control = factual_target.copy()
    control[0] ^= np.uint32(1)
    native_factual, native_control = kernel.filter_masks(
        initial,
        0,
        4,
        factual_target,
        control,
        FILTER_WORDS,
        1,
    )
    candidates = np.arange(256, dtype=np.uint32)
    scalar = np.repeat(initial.reshape(1, 16), 256, axis=0)
    scalar[:, UNKNOWN_INITIAL_LANE] = candidates
    outputs = (_A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)

    def masks_for(target: np.ndarray) -> np.ndarray:
        matches = np.all(outputs[:, :FILTER_WORDS] == target[:FILTER_WORDS], axis=1)
        masks = np.zeros(4, dtype=np.uint64)
        for candidate in np.flatnonzero(matches):
            masks[candidate // 64] |= np.uint64(1) << np.uint64(candidate % 64)
        return masks

    expected_factual = masks_for(factual_target)
    expected_control = masks_for(control)
    if not np.array_equal(native_factual, expected_factual) or not np.array_equal(
        native_control, expected_control
    ):
        raise RuntimeError("native/scalar ChaCha20 mask gate failed")
    return {
        "logical_candidates": 256,
        "packed_states": 4,
        "factual_assignment": actual,
        "factual_mask_sha256": _sha256(native_factual.astype("<u8").tobytes()),
        "control_mask_sha256": _sha256(native_control.astype("<u8").tobytes()),
        "exact_native_scalar_identity": True,
    }


def _independent_confirm(
    initial_template: np.ndarray,
    target: np.ndarray,
    candidate: int,
) -> dict[str, Any]:
    initial = initial_template.copy().reshape(1, 16)
    initial[0, UNKNOWN_INITIAL_LANE] = np.uint32(candidate)
    output = (_A119._core(initial.copy(), 20) + initial).astype(np.uint32)
    expected = target.reshape(1, 16)
    return {
        "candidate_key_word": candidate,
        "complete_block_match": bool(np.array_equal(output, expected)),
        "output_words_checked": 16,
        "output_bits_checked": 512,
        "candidate_block_sha256": _sha256(output.astype("<u4").tobytes()),
        "target_block_sha256": _sha256(expected.astype("<u4").tobytes()),
        "implementation": "independent_NumPy_RFC8439_ChaCha20_core",
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "chacha20-partial-key-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "target_block_sha256": challenge["target_block_sha256"],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
        "window_bits": WINDOW_BITS,
        "threads": THREADS,
        "stream_packs": STREAM_PACKS,
    }


def _enumerate_key_word(
    *,
    kernel: NativeChaCha20Kernel,
    initial: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
    challenge: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    pack_count = candidate_count // 64
    next_pack = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A178 checkpoint fingerprint differs")
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
            raise RuntimeError("A178 checkpoint progress is invalid")
    resumed_pack_count = next_pack
    while next_pack < pack_count:
        batch_count = min(STREAM_PACKS, pack_count - next_pack)
        factual_masks, control_masks = kernel.filter_masks(
            initial,
            next_pack,
            batch_count,
            target,
            control,
            FILTER_WORDS,
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
        _A177._NATIVE._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_pack": next_pack,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
            },
        )
        print(f"A178 native packs={next_pack}/{pack_count}", flush=True)
    factual_confirmations = [
        _independent_confirm(initial, target, candidate) for candidate in factual_filtered
    ]
    control_confirmations = [
        _independent_confirm(initial, control, candidate) for candidate in control_filtered
    ]
    factual_full = [
        row["candidate_key_word"] for row in factual_confirmations if row["complete_block_match"]
    ]
    control_full = [
        row["candidate_key_word"] for row in control_confirmations if row["complete_block_match"]
    ]
    if not factual_full:
        raise RuntimeError("A178 complete-domain Reader returned no exact key word")
    return {
        "unknown_key_word_index": UNKNOWN_KEY_WORD_INDEX,
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
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
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_key_word": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "packed_evaluation_reduction_factor": candidate_count / pack_count,
        "unknown_key_word_available_to_runner_before_execution": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_native_fullround_partial_key_recovery",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 20,
            "unknown_key_word_bits": WINDOW_BITS,
            "known_key_bits": 224,
            "logical_candidates": 1 << WINDOW_BITS,
            "native_threads": THREADS,
        },
    )
    ids = [
        "chacha20-a119-fullround-feedforward-anchor",
        "chacha20-a178-public-partial-key-challenge",
        "chacha20-a178-native-candidate-axis-reader",
        "chacha20-a178-complete-keyword-domain-execution",
        "chacha20-a178-independent-partial-key-recovery",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A119:retained_standard_ChaCha20_fullround_block_reader",
        mechanism="anchor_the_RFC8439_20_round_block_and_feedforward_semantics",
        outcome="A178:ChaCha20_partial_key_recovery_question",
        confidence=1.0,
        evidence_kind="retained_fullround_ChaCha20_anchor",
        source=A119_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A178:ChaCha20_partial_key_recovery_question",
        mechanism="freeze_224_known_key_bits_counter_nonce_and_standard_block_target_while_omitting_one_32_bit_key_word",
        outcome="A178:prospectively_frozen_public_key_word_challenge",
        confidence=1.0,
        evidence_kind="pre_execution_public_challenge_freeze",
        source=PUBLIC_RELATION_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A178:prospectively_frozen_public_key_word_challenge",
        mechanism="compile_and_cross_validate_the_64_candidate_bitsliced_ChaCha20_C11_reader",
        outcome="A178:verified_native_ChaCha20_candidate_reader",
        confidence=1.0,
        evidence_kind="native_independent_cross_implementation_gate",
        source=NATIVE_SOURCE_SHA256,
        provenance=[ids[1]],
        attrs={
            "native_build": payload["native_build"],
            "cross_gate": payload["native_cross_implementation_gate"],
            "mask_gate": payload["native_scalar_mask_gate"],
        },
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A178:verified_native_ChaCha20_candidate_reader",
        mechanism="enumerate_all_2^32_key_word_assignments_without_early_stop",
        outcome="A178:complete_67108864_pack_key_word_filter_result",
        confidence=1.0,
        evidence_kind="complete_native_partial_key_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A178:complete_67108864_pack_key_word_filter_result",
        mechanism="confirm_every_64_bit_filter_candidate_with_independent_RFC8439_NumPy_over_all_512_output_bits",
        outcome="A178:prospective_fullround_32_bit_partial_key_recovery",
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
        raise RuntimeError("A178 Causal provenance chain failed validation")
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
    library_path, native_build = _compile_native(build_dir, cc)
    kernel = NativeChaCha20Kernel(library_path)
    kat = _A119._kat()
    cross_gate = _cross_implementation_gate(kernel, 178_032)
    mask_gate = _small_mask_gate(kernel, 178_064)
    execution = _enumerate_key_word(
        kernel=kernel,
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
        challenge=analysis["public_challenge"],
        checkpoint_path=checkpoint_path,
        resume=resume,
    )
    if not execution["complete_domain_executed"]:
        raise RuntimeError("A178 did not execute the complete key-word domain")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "CHACHA20_FULLROUND_32BIT_PARTIAL_KEY_RECOVERY_RETAINED"
            if execution["unique_exact_key_word"] and execution["control_target_rejected"]
            else "CHACHA20_FULLROUND_32BIT_PARTIAL_KEY_SET_RETAINED"
        ),
        "result": (
            "The native Causal Reader executes the complete unknown 32-bit ChaCha20 "
            "key-word domain and independently confirms every key word matching the "
            "standard 20-round block output."
        ),
        "scope": (
            "Standard ChaCha20 block-function partial-key recovery with one 32-bit "
            "key word unknown, the other 224 key bits plus counter and nonce known, "
            "and complete 2^32 enumeration."
        ),
        "parameters": {
            "rounds": 20,
            "unknown_key_word_index": UNKNOWN_KEY_WORD_INDEX,
            "unknown_key_word_bits": WINDOW_BITS,
            "known_key_bits": 224,
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
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "kat": kat,
        "native_build": native_build,
        "native_cross_implementation_gate": cross_gate,
        "native_scalar_mask_gate": mask_gate,
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
            "recovered_key_word_index": UNKNOWN_KEY_WORD_INDEX,
            "recovered_key_words": execution["factual_full_matches"],
            "first_reveal_occurs_after_complete_domain_execution": True,
            "unknown_word_source_was_discarded_before_runner_construction": True,
        },
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
        raise RuntimeError("A178 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "logical_candidate_count": execution["logical_candidate_count"],
        "packed_state_count": execution["packed_state_count"],
        "factual_filter_matches": execution["factual_filter_matches"],
        "recovered_key_words": execution["factual_full_matches"],
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
        default=Path(__file__).parents[2] / "build" / "chacha-native",
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
                cc=args.cc,
                resume=args.resume,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
