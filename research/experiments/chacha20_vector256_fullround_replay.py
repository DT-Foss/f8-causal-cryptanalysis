#!/usr/bin/env python3
"""Complete-domain ChaCha20 replay with a four-lane vector bit-sliced kernel."""

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


_A178 = _import_sibling(
    "chacha20_native_fullround_partial_key_recovery.py",
    "chacha20_vector256_a178_anchor",
)
_A119 = _A178._A119
_BITSLICED = _A178._BITSLICED

ATTEMPT_ID = "A179"
SCHEMA = "chacha20-vector256-fullround-replay-v1"
PROTOCOL_SCHEMA = "chacha20-vector256-fullround-replay-protocol-v1"
PROTOCOL_FILENAME = "chacha20_vector256_fullround_replay_v1.json"
PROTOCOL_SHA256 = "fc552a21f14a827293996cdff6707dd7b31ac6ffdcc18cc55ac45b624d784e40"
A178_FILENAME = _A178.RESULT_FILENAME
A178_SHA256 = "80fee52a0a2222efab161d74eb7ee124f6d94b56ca0cf759c5ffc4ca2881bea1"
A178_CAUSAL_FILENAME = _A178.CAUSAL_FILENAME
A178_CAUSAL_SHA256 = "94c651c6ea5432f482c054ae6d839c84563e8eae81e98625beb158344da16995"
A178_NATIVE_SOURCE_FILENAME = _A178.NATIVE_SOURCE_FILENAME
A178_NATIVE_SOURCE_SHA256 = _A178.NATIVE_SOURCE_SHA256
NATIVE_SOURCE_FILENAME = "chacha20_bitsliced_vector256.c"
NATIVE_SOURCE_SHA256 = "4b4807911580831d0f7925cd74c886694d3d6b19e30be2f0e21a602a6e6ba9dc"
PUBLIC_RELATION_SHA256 = _A178.PUBLIC_RELATION_SHA256
EXPECTED_KEY_WORD = 2_419_963_719
UNKNOWN_KEY_WORD_INDEX = _A178.UNKNOWN_KEY_WORD_INDEX
UNKNOWN_INITIAL_LANE = _A178.UNKNOWN_INITIAL_LANE
WINDOW_BITS = 32
VECTOR_WIDTH = 256
UINT64_SUBLANES = 4
THREADS = 10
STREAM_VECTOR_STATES = 1 << 18
FILTER_WORDS = 2
RESULT_FILENAME = "chacha20_vector256_fullround_replay_v1.json"
CAUSAL_FILENAME = "chacha20_vector256_fullround_replay_v1.causal"
CHECKPOINT_FILENAME = "chacha20_vector256_fullround_replay_v1.checkpoint.json"

_U32_PTR = ctypes.POINTER(ctypes.c_uint32)
_U64_PTR = ctypes.POINTER(ctypes.c_uint64)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A178._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A178._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A179 frozen protocol hash differs")
    protocol = json.loads(raw)
    qualification = protocol.get("pre_freeze_implementation_qualification", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_small_implementation_gates_before_any_A179_complete_domain_execution"
        or protocol.get("anchors", {}).get("A178", {}).get("sha256") != A178_SHA256
        or protocol.get("anchors", {}).get("A178", {}).get("causal_sha256") != A178_CAUSAL_SHA256
        or protocol.get("native_kernel", {}).get("source_sha256") != NATIVE_SOURCE_SHA256
        or qualification.get("exact_scalar_identity") is not True
        or qualification.get("complete_domain_execution_performed") is not False
        or boundary.get("A178_recovered_word_used_to_prune_or_stop_enumeration") is not False
        or boundary.get("A179_complete_domain_outcome_used_before_freeze") is not False
        or protocol.get("execution_plan", {}).get("complete_domain_required") is not True
    ):
        raise RuntimeError("A179 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    result_path = results_dir / A178_FILENAME
    causal_path = results_dir / A178_CAUSAL_FILENAME
    v1_source_path = Path(__file__).with_name(A178_NATIVE_SOURCE_FILENAME)
    observed = {
        "A178_result_sha256": _file_sha256(result_path),
        "A178_causal_sha256": _file_sha256(causal_path),
        "A178_native_source_sha256": _file_sha256(v1_source_path),
    }
    expected = {
        "A178_result_sha256": A178_SHA256,
        "A178_causal_sha256": A178_CAUSAL_SHA256,
        "A178_native_source_sha256": A178_NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A179 A178 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    if (
        result.get("schema") != _A178.SCHEMA
        or result.get("evidence_stage") != "CHACHA20_FULLROUND_32BIT_PARTIAL_KEY_RECOVERY_RETAINED"
        or result.get("execution", {}).get("complete_domain_executed") is not True
        or result.get("execution", {}).get("factual_full_matches") != [EXPECTED_KEY_WORD]
        or result.get("execution", {}).get("control_full_matches") != []
        or result.get("execution", {}).get("logical_candidate_count") != 1 << WINDOW_BITS
        or result.get("public_challenge_sha256") != PUBLIC_RELATION_SHA256
    ):
        raise RuntimeError("A179 retained A178 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A178_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
        or len(reader.triplets(include_inferred=False)) != 5
    ):
        raise RuntimeError("A179 retained A178 Causal gate failed")
    return result, {
        **observed,
        "A178_causal_graph_sha256": reader.graph_sha256,
        "A178_causal_provenance_verified": True,
        "A178_recovered_key_word": EXPECTED_KEY_WORD,
        "A178_complete_domain_executed": True,
    }


def _execution_plan() -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    vector_state_count = candidate_count // VECTOR_WIDTH
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": 20,
        "unknown_key_word_bits": WINDOW_BITS,
        "known_key_bits": 224,
        "counter_bits_known": 32,
        "nonce_bits_known": 96,
        "logical_candidate_count": candidate_count,
        "logical_candidates_per_vector_state": VECTOR_WIDTH,
        "uint64_sublanes_per_vector_state": UINT64_SUBLANES,
        "vector_state_count": vector_state_count,
        "A178_uint64_pack_count": candidate_count // 64,
        "structural_vector_state_reduction_factor": UINT64_SUBLANES,
        "native_threads": THREADS,
        "stream_vector_state_count": STREAM_VECTOR_STATES,
        "stream_batch_count": vector_state_count // STREAM_VECTOR_STATES,
        "maximum_mask_memory_bytes": STREAM_VECTOR_STATES * UINT64_SUBLANES * 16,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "full_confirmation": "independent_NumPy_ChaCha20_all_512_output_bits",
        "control_target_required": True,
        "replays_A178_public_challenge": True,
        "wallclock_excluded_from_canonical_result": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a178, anchors = _load_anchor_gates(results_dir)
    challenge = a178["public_challenge"]
    _A178._validate_public_challenge(challenge)
    plan = _execution_plan()
    if protocol["execution_plan"] != plan or protocol["execution_plan_sha256"] != _canonical_sha256(
        plan
    ):
        raise RuntimeError("A179 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "initial_template": _A178._initial_from_challenge(challenge),
        "target": np.array(challenge["target_words"], dtype=np.uint32),
        "control_target": np.array(challenge["control_target_words"], dtype=np.uint32),
        "execution_plan": plan,
        "candidate_execution_started": False,
    }


def _compile_native(build_dir: Path, cc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    if source_sha != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A179 vector256 native source differs")
    compiler = shutil.which(cc)
    if compiler is None:
        raise FileNotFoundError(f"C compiler not found: {cc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    suffix = _A178._A177._NATIVE._shared_library_suffix()
    output = build_dir / f"libchacha20_vector256_{source_sha[:16]}{suffix}"
    temporary = output.with_name(f".{output.name}.tmp")
    base_flags = [
        "-O3",
        "-std=c11",
        "-fPIC",
        "-shared",
        "-pthread",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
    ]
    attempts = [["-mcpu=native", *base_flags], ["-march=native", *base_flags], base_flags]
    selected_flags: list[str] | None = None
    diagnostics = []
    for flags in attempts:
        temporary.unlink(missing_ok=True)
        result = subprocess.run(
            [compiler, *flags, str(source), "-o", str(temporary)],
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
            "native vector256 ChaCha20 kernel compilation failed: "
            + " | ".join(filter(None, diagnostics))
        )
    temporary.replace(output)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("native vector256 ChaCha20 build produced no library")
    return output, {
        "source_sha256": source_sha,
        "shared_library_sha256": _file_sha256(output),
        "language": "C11_POSIX_threads_with_compiler_vector_extension",
        "optimization": "O3",
        "logical_candidate_width": VECTOR_WIDTH,
        "uint64_sublanes": UINT64_SUBLANES,
        "strict_warning_gate": True,
        "selected_flags": selected_flags,
    }


class NativeChaCha20Vector256Kernel:
    def __init__(self, path: Path):
        self.path = path
        self.library = ctypes.CDLL(str(path.resolve()))
        self.library.chacha20_bitslice_blocks256.argtypes = [_U32_PTR, _U32_PTR]
        self.library.chacha20_bitslice_blocks256.restype = ctypes.c_int
        self.library.chacha20_bitslice_filter256.argtypes = [
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
        self.library.chacha20_bitslice_filter256.restype = ctypes.c_int
        self.library.chacha20_bitslice_vector256_version.argtypes = []
        self.library.chacha20_bitslice_vector256_version.restype = ctypes.c_char_p
        if self.library.chacha20_bitslice_vector256_version() != b"chacha20-bitslice-vector256-v1":
            raise RuntimeError("unexpected vector256 ChaCha20 kernel version")

    def blocks256(self, initial: np.ndarray) -> np.ndarray:
        values = np.ascontiguousarray(initial, dtype=np.uint32)
        if values.shape != (VECTOR_WIDTH, 16):
            raise ValueError("vector256 ChaCha20 block gate requires uint32[256,16]")
        output = np.empty_like(values)
        code = self.library.chacha20_bitslice_blocks256(
            values.ctypes.data_as(_U32_PTR),
            output.ctypes.data_as(_U32_PTR),
        )
        if code != 0:
            raise RuntimeError(f"vector256 ChaCha20 block gate returned {code}")
        return output

    def filter_masks(
        self,
        initial: np.ndarray,
        first_vector_pack: int,
        vector_pack_count: int,
        target: np.ndarray,
        control: np.ndarray,
        filter_words: int,
        threads: int,
    ) -> tuple[np.ndarray, np.ndarray]:
        initial_words = np.ascontiguousarray(initial, dtype=np.uint32).reshape(-1)
        target_words = np.ascontiguousarray(target, dtype=np.uint32).reshape(-1)
        control_words = np.ascontiguousarray(control, dtype=np.uint32).reshape(-1)
        if initial_words.shape != (16,) or target_words.shape != (16,):
            raise ValueError("vector256 ChaCha20 initial/target must contain 16 words")
        if (
            control_words.shape != (16,)
            or first_vector_pack < 0
            or vector_pack_count < 0
            or threads < 1
        ):
            raise ValueError("vector256 ChaCha20 pack/control/thread inputs are invalid")
        mask_count = vector_pack_count * UINT64_SUBLANES
        factual = np.empty(mask_count, dtype=np.uint64)
        wrong = np.empty(mask_count, dtype=np.uint64)
        code = self.library.chacha20_bitslice_filter256(
            initial_words.ctypes.data_as(_U32_PTR),
            UNKNOWN_INITIAL_LANE,
            first_vector_pack,
            vector_pack_count,
            target_words.ctypes.data_as(_U32_PTR),
            control_words.ctypes.data_as(_U32_PTR),
            filter_words,
            threads,
            factual.ctypes.data_as(_U64_PTR),
            wrong.ctypes.data_as(_U64_PTR),
        )
        if code != 0:
            raise RuntimeError(f"vector256 ChaCha20 filter returned {code}")
        return factual, wrong


def _cross_implementation_gate(
    kernel: NativeChaCha20Vector256Kernel,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    qualification = protocol["pre_freeze_implementation_qualification"]
    seed = int(qualification["cross_gate_seed"])
    rng = np.random.default_rng(seed)
    initial = rng.integers(0, 1 << 32, size=(VECTOR_WIDTH, 16), dtype=np.uint32)
    expected = (_A119._core(initial.copy(), 20) + initial).astype(np.uint32)
    observed = kernel.blocks256(initial)
    input_sha = _sha256(initial.astype("<u4", copy=False).tobytes())
    output_sha = _sha256(observed.astype("<u4", copy=False).tobytes())
    if (
        not np.array_equal(observed, expected)
        or input_sha != qualification["cross_gate_input_sha256"]
        or output_sha != qualification["cross_gate_output_sha256"]
    ):
        raise RuntimeError("A179 vector256/scalar cross-implementation gate failed")
    return {
        "seed": seed,
        "states": VECTOR_WIDTH,
        "words_checked": int(observed.size),
        "state_bits_checked": int(observed.size * 32),
        "exact_match": True,
        "input_sha256": input_sha,
        "output_sha256": output_sha,
    }


def _boundary_mask_gate(
    kernel: NativeChaCha20Vector256Kernel,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    qualification = protocol["pre_freeze_implementation_qualification"]
    packs = [int(value) for value in qualification["boundary_mask_packs_checked"]]
    rng = np.random.default_rng(179_064)
    initial = rng.integers(0, 1 << 32, size=16, dtype=np.uint32)
    offset = 173
    rows = []
    for vector_pack in packs:
        first_candidate = vector_pack * VECTOR_WIDTH
        candidates = (np.uint64(first_candidate) + np.arange(VECTOR_WIDTH, dtype=np.uint64)).astype(
            np.uint32
        )
        scalar = np.repeat(initial.reshape(1, 16), VECTOR_WIDTH, axis=0)
        scalar[:, UNKNOWN_INITIAL_LANE] = candidates
        outputs = (_A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
        target = outputs[offset].copy()
        control = target.copy()
        control[0] ^= np.uint32(1)
        factual, wrong = kernel.filter_masks(
            initial,
            vector_pack,
            1,
            target,
            control,
            FILTER_WORDS,
            1,
        )

        def scalar_masks(
            observed: np.ndarray,
            expected: np.ndarray,
        ) -> np.ndarray:
            matches = np.all(
                observed[:, :FILTER_WORDS] == expected[:FILTER_WORDS],
                axis=1,
            )
            masks = np.zeros(UINT64_SUBLANES, dtype=np.uint64)
            for candidate in np.flatnonzero(matches):
                masks[candidate // 64] |= np.uint64(1) << np.uint64(candidate % 64)
            return masks

        expected_factual = scalar_masks(outputs, target)
        expected_wrong = scalar_masks(outputs, control)
        factual_sha = _sha256(factual.astype("<u8", copy=False).tobytes())
        if (
            not np.array_equal(factual, expected_factual)
            or not np.array_equal(wrong, expected_wrong)
            or factual_sha != qualification["boundary_factual_mask_sha256"]
        ):
            raise RuntimeError("A179 boundary vector-mask gate failed")
        rows.append(
            {
                "vector_pack": vector_pack,
                "first_candidate": first_candidate,
                "expected_assignment": first_candidate + offset,
                "factual_mask_sha256": factual_sha,
                "control_mask_sha256": _sha256(wrong.astype("<u8", copy=False).tobytes()),
                "exact_scalar_identity": True,
            }
        )
    return {
        "logical_candidates_checked": len(rows) * VECTOR_WIDTH,
        "vector_packs_checked": packs,
        "boundary_rows": rows,
        "exact_scalar_identity": True,
    }


def _v1_v2_filter_equivalence_gate(
    *,
    v1: _A178.NativeChaCha20Kernel,
    v2: NativeChaCha20Vector256Kernel,
    initial: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
) -> dict[str, Any]:
    vector_state_count = (1 << WINDOW_BITS) // VECTOR_WIDTH
    positions = [0, EXPECTED_KEY_WORD // VECTOR_WIDTH, vector_state_count - 1]
    rows = []
    for vector_pack in positions:
        v2_factual, v2_control = v2.filter_masks(
            initial, vector_pack, 1, target, control, FILTER_WORDS, 1
        )
        v1_factual, v1_control = v1.filter_masks(
            initial,
            vector_pack * UINT64_SUBLANES,
            UINT64_SUBLANES,
            target,
            control,
            FILTER_WORDS,
            1,
        )
        if not np.array_equal(v2_factual, v1_factual) or not np.array_equal(v2_control, v1_control):
            raise RuntimeError("A179 vector256/v1 filter-equivalence gate failed")
        rows.append(
            {
                "vector_pack": vector_pack,
                "first_candidate": vector_pack * VECTOR_WIDTH,
                "factual_mask_sha256": _sha256(v2_factual.astype("<u8").tobytes()),
                "control_mask_sha256": _sha256(v2_control.astype("<u8").tobytes()),
                "exact_v1_v2_identity": True,
            }
        )
    return {
        "vector_packs_checked": positions,
        "logical_candidates_checked": len(positions) * VECTOR_WIDTH,
        "exact_v1_v2_identity": True,
        "rows": rows,
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "chacha20-vector256-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "target_block_sha256": challenge["target_block_sha256"],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
        "window_bits": WINDOW_BITS,
        "vector_width": VECTOR_WIDTH,
        "threads": THREADS,
        "stream_vector_states": STREAM_VECTOR_STATES,
    }


def _enumerate_key_word(
    *,
    kernel: NativeChaCha20Vector256Kernel,
    initial: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
    challenge: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    vector_state_count = candidate_count // VECTOR_WIDTH
    next_vector_state = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A179 checkpoint fingerprint differs")
        next_vector_state = int(checkpoint["next_vector_state"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        if (
            next_vector_state < 0
            or next_vector_state > vector_state_count
            or next_vector_state % STREAM_VECTOR_STATES != 0
            or any(
                value < 0 or value >= next_vector_state * VECTOR_WIDTH for value in factual_filtered
            )
            or any(
                value < 0 or value >= next_vector_state * VECTOR_WIDTH for value in control_filtered
            )
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A179 checkpoint progress is invalid")
    resumed_vector_state_count = next_vector_state
    while next_vector_state < vector_state_count:
        batch_count = min(STREAM_VECTOR_STATES, vector_state_count - next_vector_state)
        factual_masks, control_masks = kernel.filter_masks(
            initial,
            next_vector_state,
            batch_count,
            target,
            control,
            FILTER_WORDS,
            THREADS,
        )
        first_uint64_pack = next_vector_state * UINT64_SUBLANES
        factual_filtered.extend(
            _BITSLICED._indices_from_masks(
                factual_masks,
                first_uint64_pack,
                candidate_count,
            )
        )
        control_filtered.extend(
            _BITSLICED._indices_from_masks(
                control_masks,
                first_uint64_pack,
                candidate_count,
            )
        )
        next_vector_state += batch_count
        _A178._A177._NATIVE._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_vector_state": next_vector_state,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
            },
        )
        print(
            f"A179 vector states={next_vector_state}/{vector_state_count}",
            flush=True,
        )
    factual_confirmations = [
        _A178._independent_confirm(initial, target, candidate) for candidate in factual_filtered
    ]
    control_confirmations = [
        _A178._independent_confirm(initial, control, candidate) for candidate in control_filtered
    ]
    factual_full = [
        row["candidate_key_word"] for row in factual_confirmations if row["complete_block_match"]
    ]
    control_full = [
        row["candidate_key_word"] for row in control_confirmations if row["complete_block_match"]
    ]
    return {
        "unknown_key_word_index": UNKNOWN_KEY_WORD_INDEX,
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
        "logical_candidate_count": candidate_count,
        "logical_candidates_per_vector_state": VECTOR_WIDTH,
        "uint64_sublanes_per_vector_state": UINT64_SUBLANES,
        "vector_state_count": vector_state_count,
        "A178_uint64_pack_count": candidate_count // 64,
        "native_threads": THREADS,
        "stream_vector_state_count": STREAM_VECTOR_STATES,
        "stream_batch_count": vector_state_count // STREAM_VECTOR_STATES,
        "resumed_vector_state_count": resumed_vector_state_count,
        "newly_executed_vector_state_count": vector_state_count - resumed_vector_state_count,
        "complete_domain_executed": next_vector_state == vector_state_count,
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
        "logical_packing_factor": candidate_count / vector_state_count,
        "structural_vector_state_reduction_factor_vs_A178": (
            (candidate_count // 64) / vector_state_count
        ),
        "A178_recovered_word_used_to_prune_or_stop_enumeration": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_vector256_fullround_replay",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 20,
            "unknown_key_word_bits": WINDOW_BITS,
            "logical_candidates": 1 << WINDOW_BITS,
            "logical_candidates_per_vector_state": VECTOR_WIDTH,
            "native_threads": THREADS,
        },
    )
    ids = [
        "chacha20-a178-full-domain-recovery-anchor",
        "chacha20-a179-vector256-protocol-freeze",
        "chacha20-a179-vector256-native-equivalence",
        "chacha20-a179-vector256-complete-domain-replay",
        "chacha20-a179-fullround-vector-packing-advance",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A178:retained_fullround_32_bit_partial_key_recovery",
        mechanism="anchor_the_complete_2^32_ChaCha20_domain_and_exact_recovered_word",
        outcome="A179:vectorized_complete_domain_replay_question",
        confidence=1.0,
        evidence_kind="retained_A178_complete_domain_anchor",
        source=A178_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A179:vectorized_complete_domain_replay_question",
        mechanism="freeze_a_four_uint64_sublane_representation_before_any_complete_domain_execution",
        outcome="A179:frozen_vector256_replay_protocol",
        confidence=1.0,
        evidence_kind="pre_complete_domain_protocol_freeze",
        source=PROTOCOL_SHA256,
        provenance=[ids[0]],
        attrs={"protocol_gate": payload["protocol_gate"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A179:frozen_vector256_replay_protocol",
        mechanism="cross_validate_256_blocks_boundary_masks_and_v1_filter_masks_exactly",
        outcome="A179:verified_vector256_candidate_reader",
        confidence=1.0,
        evidence_kind="scalar_and_v1_native_equivalence_gates",
        source=NATIVE_SOURCE_SHA256,
        provenance=[ids[1]],
        attrs={
            "native_build": payload["native_build"],
            "cross_gate": payload["native_cross_implementation_gate"],
            "boundary_gate": payload["native_boundary_mask_gate"],
            "v1_v2_gate": payload["native_v1_v2_filter_equivalence_gate"],
        },
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A179:verified_vector256_candidate_reader",
        mechanism="enumerate_all_2^32_assignments_as_16777216_vector_states_without_early_stop",
        outcome="A179:complete_vector256_fullround_replay",
        confidence=1.0,
        evidence_kind="complete_native_vectorized_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A179:complete_vector256_fullround_replay",
        mechanism="confirm_the_exact_A178_word_control_rejection_and_fourfold_vector_state_reduction",
        outcome="A179:fullround_vector256_equivalence_and_packing_advance",
        confidence=1.0,
        evidence_kind="complete_domain_equivalence_and_structural_reduction",
        source=payload["equivalence_sha256"],
        provenance=[ids[3]],
        attrs={"equivalence": payload["equivalence"]},
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
        raise RuntimeError("A179 Causal provenance chain failed validation")
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
    library_path, native_build = _compile_native(build_dir / "vector256", cc)
    kernel = NativeChaCha20Vector256Kernel(library_path)
    cross_gate = _cross_implementation_gate(kernel, analysis["protocol"])
    boundary_gate = _boundary_mask_gate(kernel, analysis["protocol"])
    v1_library_path, v1_build = _A178._compile_native(build_dir / "v1", cc)
    v1_kernel = _A178.NativeChaCha20Kernel(v1_library_path)
    v1_v2_gate = _v1_v2_filter_equivalence_gate(
        v1=v1_kernel,
        v2=kernel,
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
    )
    execution = _enumerate_key_word(
        kernel=kernel,
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
        challenge=analysis["public_challenge"],
        checkpoint_path=checkpoint_path,
        resume=resume,
    )
    equivalence = {
        "complete_domain_executed": execution["complete_domain_executed"],
        "A178_recovered_key_word": EXPECTED_KEY_WORD,
        "A179_factual_filter_matches": execution["factual_filter_matches"],
        "A179_factual_full_matches": execution["factual_full_matches"],
        "A179_control_full_matches": execution["control_full_matches"],
        "exact_A178_recovery_identity": execution["factual_full_matches"] == [EXPECTED_KEY_WORD],
        "control_target_rejected": execution["control_full_matches"] == [],
        "A178_uint64_pack_count": execution["A178_uint64_pack_count"],
        "A179_vector_state_count": execution["vector_state_count"],
        "exact_vector_state_reduction_factor": (
            execution["A178_uint64_pack_count"] / execution["vector_state_count"]
        ),
        "early_stop_used": execution["early_stop_used"],
    }
    if (
        equivalence["complete_domain_executed"] is not True
        or equivalence["exact_A178_recovery_identity"] is not True
        or equivalence["control_target_rejected"] is not True
        or equivalence["exact_vector_state_reduction_factor"] != 4.0
        or equivalence["early_stop_used"] is not False
    ):
        raise RuntimeError("A179 complete-domain equivalence gate failed")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CHACHA20_FULLROUND_VECTOR256_COMPLETE_DOMAIN_EQUIVALENCE_RETAINED",
        "result": (
            "The four-sublane native Causal Reader executes the complete 2^32 "
            "ChaCha20 key-word domain, reproduces the exact A178 full-block match, "
            "rejects the control, and reduces vector-state count exactly fourfold."
        ),
        "scope": (
            "Standard 20-round ChaCha20 block-function replay of the frozen A178 "
            "32-bit partial-key challenge using 256 logical candidates per vector state."
        ),
        "parameters": {
            "rounds": 20,
            "unknown_key_word_bits": WINDOW_BITS,
            "logical_candidate_count": 1 << WINDOW_BITS,
            "logical_candidates_per_vector_state": VECTOR_WIDTH,
            "uint64_sublanes_per_vector_state": UINT64_SUBLANES,
            "native_threads": THREADS,
            "stream_vector_state_count": STREAM_VECTOR_STATES,
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
        "A178_native_build": v1_build,
        "native_cross_implementation_gate": cross_gate,
        "native_boundary_mask_gate": boundary_gate,
        "native_v1_v2_filter_equivalence_gate": v1_v2_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key not in {"factual_confirmations", "control_confirmations"}
            }
        ),
        "equivalence": equivalence,
        "equivalence_sha256": _canonical_sha256(equivalence),
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
        raise RuntimeError("A179 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "logical_candidate_count": execution["logical_candidate_count"],
        "vector_state_count": execution["vector_state_count"],
        "structural_vector_state_reduction_factor": equivalence[
            "exact_vector_state_reduction_factor"
        ],
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
        default=Path(__file__).parents[2] / "build" / "chacha-vector256",
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
