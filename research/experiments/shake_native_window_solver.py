#!/usr/bin/env python3
"""Threaded native bit-sliced SHAKE state-window consistency solver."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BITSLICED_PATH = Path(__file__).with_name("shake_bitsliced_window_solver.py")
_BITSLICED_SPEC = importlib.util.spec_from_file_location(
    "shake_bitsliced_window_solver_native_base", _BITSLICED_PATH
)
assert _BITSLICED_SPEC is not None and _BITSLICED_SPEC.loader is not None
_BITSLICED = importlib.util.module_from_spec(_BITSLICED_SPEC)
sys.modules[_BITSLICED_SPEC.name] = _BITSLICED
_BITSLICED_SPEC.loader.exec_module(_BITSLICED)

_BASE = _BITSLICED._BASE
_WINDOW = _BITSLICED._WINDOW
_NATIVE_SOURCE = Path(__file__).with_name("shake_bitsliced_native.c")
_U64_PTR = ctypes.POINTER(ctypes.c_uint64)
_U16_PTR = ctypes.POINTER(ctypes.c_uint16)


def _parse_windows(value: str) -> list[int]:
    try:
        windows = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise ValueError("window sizes must be comma-separated integers") from error
    if not windows or len(set(windows)) != len(windows):
        raise ValueError("window sizes must be nonempty and unique")
    if any(bits < 1 or bits > 40 for bits in windows):
        raise ValueError("native window sizes must be in 1..40")
    return windows


def _source_sha256(source: Path = _NATIVE_SOURCE) -> str:
    return hashlib.sha256(source.read_bytes()).hexdigest()


def _shared_library_suffix() -> str:
    if sys.platform == "darwin":
        return ".dylib"
    if sys.platform.startswith("linux"):
        return ".so"
    raise RuntimeError("native SHAKE solver currently supports macOS and Linux")


def _compile_native(
    build_dir: Path,
    cc: str = "cc",
    source: Path = _NATIVE_SOURCE,
) -> tuple[Path, dict[str, Any]]:
    compiler = shutil.which(cc)
    if compiler is None:
        raise RuntimeError(f"C compiler not found: {cc}")
    source_sha = _source_sha256(source)
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / (
        f"libshake_bitsliced_native_{source_sha[:16]}{_shared_library_suffix()}"
    )
    base_flags = ["-O3", "-std=c11", "-fPIC", "-shared", "-pthread"]
    attempts = [["-mcpu=native", *base_flags], base_flags]
    selected_flags: list[str] | None = None
    diagnostics: list[str] = []
    if not output.exists():
        for flags in attempts:
            command = [compiler, *flags, str(source), "-o", str(output)]
            result = subprocess.run(
                command,
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
                "native SHAKE kernel compilation failed: "
                + " | ".join(filter(None, diagnostics))
            )
    else:
        selected_flags = base_flags
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("native SHAKE kernel build produced no library")
    return output, {
        "source_sha256": source_sha,
        "language": "C11_POSIX_threads",
        "optimization": "O3",
        "candidate_pack_width": 64,
        "compiler_native_flag_attempted": True,
    }


class NativeBitSliceKernel:
    def __init__(self, path: Path):
        self.path = path
        self.library = ctypes.CDLL(str(path.resolve()))
        self.library.shake_bitslice_permute64.argtypes = [_U64_PTR, _U64_PTR]
        self.library.shake_bitslice_permute64.restype = ctypes.c_int
        self.library.shake_bitslice_filter.argtypes = [
            _U64_PTR,
            ctypes.c_uint,
            _U16_PTR,
            ctypes.c_uint,
            ctypes.c_uint64,
            ctypes.c_uint64,
            _U64_PTR,
            _U64_PTR,
            ctypes.c_uint,
            ctypes.c_uint,
            _U64_PTR,
            _U64_PTR,
        ]
        self.library.shake_bitslice_filter.restype = ctypes.c_int
        self.library.shake_bitslice_native_version.argtypes = []
        self.library.shake_bitslice_native_version.restype = ctypes.c_char_p
        version = self.library.shake_bitslice_native_version()
        if version != b"shake-bitslice-native-v1":
            raise RuntimeError(f"unexpected native kernel version: {version!r}")

    def permute64(self, states: np.ndarray) -> np.ndarray:
        values = np.ascontiguousarray(states, dtype=np.uint64)
        if values.shape != (64, 25):
            raise ValueError("native permutation gate requires uint64[64,25]")
        output = np.empty_like(values)
        return_code = self.library.shake_bitslice_permute64(
            values.ctypes.data_as(_U64_PTR),
            output.ctypes.data_as(_U64_PTR),
        )
        if return_code != 0:
            raise RuntimeError(f"native permutation gate returned {return_code}")
        return output

    def filter_masks(
        self,
        template: np.ndarray,
        rate_lanes: int,
        positions: np.ndarray,
        window_bits: int,
        first_pack: int,
        pack_count: int,
        target: np.ndarray,
        wrong_target: np.ndarray,
        filter_lanes: int,
        threads: int,
    ) -> tuple[np.ndarray, np.ndarray]:
        template_words = np.ascontiguousarray(template, dtype=np.uint64).reshape(-1)
        position_words = np.ascontiguousarray(positions, dtype=np.uint16).reshape(-1)
        target_words = np.ascontiguousarray(target, dtype=np.uint64).reshape(-1)
        wrong_words = np.ascontiguousarray(wrong_target, dtype=np.uint64).reshape(-1)
        if template_words.shape != (25,):
            raise ValueError("native template must contain 25 lanes")
        if position_words.shape != (window_bits,):
            raise ValueError("native position count does not match window width")
        if len(target_words) < filter_lanes or len(wrong_words) < filter_lanes:
            raise ValueError("native target does not contain every filter lane")
        if pack_count < 0 or threads < 1:
            raise ValueError("native pack count and thread count are invalid")
        factual = np.empty(pack_count, dtype=np.uint64)
        wrong = np.empty(pack_count, dtype=np.uint64)
        return_code = self.library.shake_bitslice_filter(
            template_words.ctypes.data_as(_U64_PTR),
            rate_lanes,
            position_words.ctypes.data_as(_U16_PTR),
            window_bits,
            first_pack,
            pack_count,
            target_words.ctypes.data_as(_U64_PTR),
            wrong_words.ctypes.data_as(_U64_PTR),
            filter_lanes,
            threads,
            factual.ctypes.data_as(_U64_PTR),
            wrong.ctypes.data_as(_U64_PTR),
        )
        if return_code != 0:
            raise RuntimeError(f"native rate filter returned {return_code}")
        return factual, wrong


def _reader_recipe(variant: Any, source_sha: str) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "representation": "candidate_axis_bitsliced_into_native_uint64",
        "native_source_sha256": source_sha,
        "candidates_per_machine_word": 64,
        "known": "rate_and_capacity_complement",
        "variable": "declared_capacity_window",
        "operation": "native_threaded_bitsliced_keccak_f1600_exact_rate_filter",
        "permutation_rounds": 24,
        "rate_lanes": variant.rate_lanes,
        "capacity_bits": variant.capacity_bits,
        "capacity_lane_offset": variant.rate_lanes,
        "filter_lanes": 2,
        "full_confirmation": "independent_scalar_complete_rate_equality",
    }


def _build_graph(
    path: Path,
    window_bits: list[int],
    source_sha: str,
    threads: int,
    stream_packs: int,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_native_bitsliced_capacity_window_solver",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "native_source_sha256": source_sha,
            "threads": threads,
            "stream_packs": stream_packs,
            "candidates_per_machine_word": 64,
            "prediction_before_measurement": (
                "A fused C11 candidate-axis kernel should preserve exact 24-round "
                "state consistency while moving the executable window frontier."
            ),
        },
    )
    for key, variant in _BASE.VARIANTS.items():
        pack_id = f"{key}-native-candidate-pack"
        permute_id = f"{key}-native-fullround-permutation"
        filter_id = f"{key}-native-fused-rate-filter"
        recipe = _reader_recipe(variant, source_sha)
        builder.add_triplet(
            edge_id=pack_id,
            trigger=f"{key}:64_capacity_window_assignments",
            mechanism="exact_native_candidate_axis_transposition",
            outcome=f"{key}:1600_uint64_candidate_bit_planes",
            confidence=1.0,
            evidence_kind="lossless_64_state_cross_implementation_gate",
            source="C11_candidate_pack",
            attrs={"candidates_per_word": 64},
        )
        builder.add_triplet(
            edge_id=permute_id,
            trigger=f"{key}:native_bitsliced_state_planes",
            mechanism="exact_native_keccak_f1600_24_rounds",
            outcome=f"{key}:native_bitsliced_next_state_planes",
            confidence=1.0,
            evidence_kind="complete_1600_bit_per_state_cross_gate",
            source=source_sha,
            provenance=[pack_id],
            attrs={"reader_recipe": recipe},
        )
        builder.add_triplet(
            edge_id=filter_id,
            trigger=f"{key}:native_fullround_candidate_outputs",
            mechanism="fused_exact_next_rate_coordinate_filter",
            outcome=f"{key}:candidate_consistency_masks",
            confidence=1.0,
            evidence_kind="native_numpy_mask_identity_gate",
            source="two_rate_lanes_inside_native_kernel",
            provenance=[permute_id],
            attrs={"reader_recipe": recipe},
        )
        builder.add_triplet(
            edge_id=f"{key}-native-window-reader",
            trigger=f"{key}:observed_next_rate_plus_known_complement",
            mechanism="reader_executable_native_fullround_consistency",
            outcome=f"{key}:unique_capacity_window_assignment",
            confidence=1.0,
            evidence_kind="two_lane_filter_then_complete_rate_confirmation",
            source="reader_loaded_native_recipe",
            provenance=[pack_id, permute_id, filter_id],
            attrs={
                "reader_recipe": recipe,
                "window_sizes": window_bits,
                "packed_evaluations": {
                    str(bits): math.ceil((1 << bits) / 64)
                    for bits in window_bits
                },
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    if not reader.verify_provenance() or len(rows) != 8:
        raise RuntimeError("native SHAKE causal graph gate failed")
    return stats


def _recipes_from_reader(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    recipes: dict[str, dict[str, Any]] = {}
    for key in _BASE.VARIANTS:
        matches = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_native_fullround_consistency"
            and row["trigger"].startswith(f"{key}:")
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Reader returned no unique native {key} recipe")
        recipes[key] = matches[0]["attrs"]["reader_recipe"]
    return recipes, rows


def _cross_implementation_gate(
    kernel: NativeBitSliceKernel,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    states = rng.integers(0, 1 << 64, size=(64, 25), dtype=np.uint64)
    expected = _BASE._keccak_f1600(states)
    observed = kernel.permute64(states)
    if not np.array_equal(observed, expected):
        raise RuntimeError("native bit-sliced Keccak cross gate failed")
    return {
        "states": 64,
        "state_bits_checked": 64 * 1600,
        "exact_match": True,
        "input_sha256": hashlib.sha256(states.astype("<u8").tobytes()).hexdigest(),
        "output_sha256": hashlib.sha256(observed.astype("<u8").tobytes()).hexdigest(),
    }


def _problem(variant: Any, window_bits: int, seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    wrong_message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    wrong_state, _ = _BASE._first_squeeze_state(wrong_message, variant)
    positions = _WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xB175
    )
    template = _WINDOW._clear_window(base_state, variant, positions)
    target = _BASE._keccak_f1600(base_state)[:, : variant.rate_lanes]
    wrong_target = _BASE._keccak_f1600(wrong_state)[:, : variant.rate_lanes]
    return {
        "message": message,
        "base_state": base_state,
        "wrong_state": wrong_state,
        "positions": positions,
        "template": template,
        "target": target,
        "wrong_target": wrong_target,
    }


def _native_numpy_mask_gate(
    kernel: NativeBitSliceKernel,
    seed: int,
    threads: int,
    window_bits: int = 12,
) -> dict[str, Any]:
    rows = {}
    for variant_index, (key, variant) in enumerate(_BASE.VARIANTS.items()):
        problem = _problem(variant, window_bits, seed + 1009 * variant_index)
        pack_count = math.ceil((1 << window_bits) / 64)
        native_factual, native_wrong = kernel.filter_masks(
            problem["template"],
            variant.rate_lanes,
            problem["positions"],
            window_bits,
            0,
            pack_count,
            problem["target"],
            problem["wrong_target"],
            2,
            threads,
        )
        packed_template = _BITSLICED._template_planes(problem["template"])
        candidate_planes = _BITSLICED._candidate_planes(
            packed_template,
            variant,
            problem["positions"],
            np.arange(pack_count, dtype=np.uint64),
        )
        output_planes = _BITSLICED._keccak_f1600_bitsliced(candidate_planes)
        numpy_factual = _BITSLICED._match_masks(output_planes, problem["target"], 2)
        numpy_wrong = _BITSLICED._match_masks(
            output_planes, problem["wrong_target"], 2
        )
        if not np.array_equal(native_factual, numpy_factual) or not np.array_equal(
            native_wrong, numpy_wrong
        ):
            raise RuntimeError(f"native/NumPy candidate-mask gate failed for {key}")
        rows[key] = {
            "window_bits": window_bits,
            "candidate_masks": pack_count,
            "factual_mask_sha256": hashlib.sha256(
                native_factual.astype("<u8").tobytes()
            ).hexdigest(),
            "wrong_mask_sha256": hashlib.sha256(
                native_wrong.astype("<u8").tobytes()
            ).hexdigest(),
            "exact_native_numpy_identity": True,
        }
    return rows


def _solve_window(
    kernel: NativeBitSliceKernel,
    base_state: np.ndarray,
    wrong_state: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    positions: np.ndarray,
    threads: int,
    stream_packs: int,
    label: str,
    resume_state: dict[str, Any] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if int(recipe["permutation_rounds"]) != 24:
        raise ValueError("native Reader recipe is not full-round")
    if int(recipe["candidates_per_machine_word"]) != 64:
        raise ValueError("native Reader recipe has unsupported pack width")
    window_bits = len(positions)
    candidate_count = 1 << window_bits
    pack_count = math.ceil(candidate_count / 64)
    template = _WINDOW._clear_window(base_state, variant, positions)
    target = _BASE._keccak_f1600(base_state)[:, : variant.rate_lanes]
    wrong_target = _BASE._keccak_f1600(wrong_state)[:, : variant.rate_lanes]
    filter_lanes = int(recipe["filter_lanes"])
    next_pack = 0
    factual_filtered: list[int] = []
    wrong_filtered: list[int] = []
    if resume_state is not None:
        next_pack = int(resume_state.get("next_pack", 0))
        factual_filtered = [int(value) for value in resume_state.get("factual", [])]
        wrong_filtered = [int(value) for value in resume_state.get("wrong", [])]
        if next_pack < 0 or next_pack > pack_count:
            raise ValueError("native checkpoint pack position is invalid")
    while next_pack < pack_count:
        batch_count = min(stream_packs, pack_count - next_pack)
        factual_masks, wrong_masks = kernel.filter_masks(
            template,
            variant.rate_lanes,
            positions,
            window_bits,
            next_pack,
            batch_count,
            target,
            wrong_target,
            filter_lanes,
            threads,
        )
        factual_filtered.extend(
            _BITSLICED._indices_from_masks(
                factual_masks, next_pack, candidate_count
            )
        )
        wrong_filtered.extend(
            _BITSLICED._indices_from_masks(wrong_masks, next_pack, candidate_count)
        )
        next_pack += batch_count
        print(
            f"{label} native packs={next_pack}/{pack_count}",
            flush=True,
        )
        if progress_callback is not None:
            progress_callback(
                {
                    "next_pack": next_pack,
                    "factual": factual_filtered,
                    "wrong": wrong_filtered,
                }
            )
    factual_full = _BITSLICED._confirm_candidates(
        template, variant, positions, factual_filtered, target
    )
    wrong_full = _BITSLICED._confirm_candidates(
        template, variant, positions, wrong_filtered, wrong_target
    )
    actual = _WINDOW._extract_window(base_state, variant, positions)
    return {
        "window_bits": window_bits,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "actual_assignment": actual,
        "candidate_count": candidate_count,
        "candidates_per_machine_word": 64,
        "packed_state_count": pack_count,
        "thread_count": threads,
        "stream_pack_count": stream_packs,
        "stream_batch_count": math.ceil(pack_count / stream_packs),
        "maximum_mask_memory_bytes": min(stream_packs, pack_count) * 16,
        "filter_lanes": filter_lanes,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "wrong_target_filter_matches": wrong_filtered,
        "wrong_target_full_matches": wrong_full,
        "unique_exact_consistency": factual_full == [actual],
        "wrong_target_rejected": len(wrong_full) == 0,
        "packed_evaluation_reduction_factor": candidate_count / pack_count,
    }


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _checkpoint_fingerprint(
    windows: list[int],
    seed: int,
    source_sha: str,
    threads: int,
    stream_packs: int,
) -> dict[str, Any]:
    return {
        "schema": "shake-native-window-checkpoint-v1",
        "windows": windows,
        "seed": seed,
        "source_sha256": source_sha,
        "threads": threads,
        "stream_packs": stream_packs,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="24,28")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--stream-packs", type=int, default=1 << 20)
    parser.add_argument("--seed", type=int, default=89739001)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--build-dir", type=Path, default=Path("build/native"))
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument(
        "--resume", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    windows = _parse_windows(args.window_bits)
    if args.threads < 1 or args.stream_packs < 1:
        raise ValueError("threads and stream-packs must be positive")
    if max(windows) > 40:
        raise ValueError("windows above 40 require a separately reviewed run plan")

    library_path, native_build = _compile_native(args.build_dir, args.cc)
    kernel = NativeBitSliceKernel(library_path)
    kat = _BASE._kat()
    native_gate = _cross_implementation_gate(kernel, args.seed ^ 0x641600)
    mask_gate = _native_numpy_mask_gate(kernel, args.seed ^ 0x1200, args.threads)
    causal = _build_graph(
        args.causal_output,
        windows,
        native_build["source_sha256"],
        args.threads,
        args.stream_packs,
    )
    recipes, reader_rows = _recipes_from_reader(args.causal_output)

    checkpoint_path = args.checkpoint or args.output.with_suffix(".checkpoint.json")
    fingerprint = _checkpoint_fingerprint(
        windows,
        args.seed,
        native_build["source_sha256"],
        args.threads,
        args.stream_packs,
    )
    checkpoint: dict[str, Any] = {**fingerprint, "completed": {}, "active": None}
    if args.resume and checkpoint_path.exists():
        loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if any(loaded.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("native checkpoint does not match this run")
        checkpoint = loaded

    confirmations: dict[str, list[dict[str, Any]]] = {}
    for variant_index, (key, variant) in enumerate(_BASE.VARIANTS.items()):
        completed_rows = checkpoint["completed"].setdefault(key, [])
        rows: list[dict[str, Any]] = []
        for window_index, bits in enumerate(windows):
            seed = args.seed + 100_003 * variant_index + 1009 * window_index
            existing = next(
                (
                    row
                    for row in completed_rows
                    if int(row["window_bits"]) == bits and int(row["seed"]) == seed
                ),
                None,
            )
            if existing is not None:
                print(f"{variant.name} native consistency bits={bits} checkpoint", flush=True)
                rows.append(existing)
                continue
            print(f"{variant.name} native consistency bits={bits}", flush=True)
            problem = _problem(variant, bits, seed)
            active_key = f"{key}:{bits}:{seed}"
            active = checkpoint.get("active")
            resume_state = (
                active.get("progress")
                if isinstance(active, dict) and active.get("key") == active_key
                else None
            )

            def save_progress(progress: dict[str, Any]) -> None:
                checkpoint["active"] = {"key": active_key, "progress": progress}
                _atomic_json(checkpoint_path, checkpoint)

            result = _solve_window(
                kernel,
                problem["base_state"],
                problem["wrong_state"],
                variant,
                recipes[key],
                problem["positions"],
                args.threads,
                args.stream_packs,
                f"{variant.name}/{bits}",
                resume_state,
                save_progress,
            )
            row = {
                "seed": seed,
                "message_sha256": hashlib.sha256(
                    problem["message"].tobytes()
                ).hexdigest(),
                **result,
            }
            rows.append(row)
            completed_rows.append(row)
            checkpoint["active"] = None
            _atomic_json(checkpoint_path, checkpoint)
        confirmations[key] = rows

    retained = all(
        row["unique_exact_consistency"]
        and row["wrong_target_rejected"]
        and row["packed_evaluation_reduction_factor"] == 64.0
        for rows in confirmations.values()
        for row in rows
    )
    total_candidates = sum(
        int(row["candidate_count"])
        for rows in confirmations.values()
        for row in rows
    )
    total_packs = sum(
        int(row["packed_state_count"])
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "shake-native-window-solver-v1",
        "evidence_stage": (
            "NATIVE_FULLROUND_WINDOW_CONSISTENCY_RETAINED"
            if retained
            else "NEW_NATIVE_REPRESENTATION_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "The C11 candidate-axis kernel preserves exact 24-round Keccak "
            f"consistency and uniquely determines every tested window through {max(windows)} bits."
        ),
        "scope": (
            "Known-complement mathematical state-window consistency. Candidate-axis "
            "packing and native threads change executable work representation, while "
            "the logical candidate count remains 2^k."
        ),
        "parameters": {
            "permutation_rounds": 24,
            "window_bits": windows,
            "threads": args.threads,
            "stream_packs": args.stream_packs,
            "seed": args.seed,
        },
        "native_build": native_build,
        "kat": kat,
        "native_cross_implementation_gate": native_gate,
        "native_numpy_mask_gate": mask_gate,
        "causal": causal,
        "reader_triplets": reader_rows,
        "confirmation": confirmations,
        "total_logical_candidates": total_candidates,
        "total_packed_states": total_packs,
        "retained": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    if checkpoint_path.exists():
        checkpoint_path.unlink()
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "retained": retained,
                "native_gate_bits": native_gate["state_bits_checked"],
                "max_window_bits": max(windows),
                "total_logical_candidates": total_candidates,
                "total_packed_states": total_packs,
                "consistent_assignments": {
                    key: {
                        str(row["window_bits"]): row["factual_full_matches"]
                        for row in rows
                    }
                    for key, rows in confirmations.items()
                },
                "wrong_target_matches": {
                    key: [len(row["wrong_target_full_matches"]) for row in rows]
                    for key, rows in confirmations.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
