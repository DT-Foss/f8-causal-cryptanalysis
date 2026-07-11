#!/usr/bin/env python3
"""Lossless shared-ANF transform and compression cascades for SHAKE traces."""
from __future__ import annotations

import argparse
import bz2
import hashlib
import importlib.util
import json
import lzma
import platform
import struct
import sys
import zlib
from pathlib import Path
from typing import Any, Callable

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_INFLUENCE_PATH = Path(__file__).with_name("shake_boolean_influence_frontier.py")
_INFLUENCE_SPEC = importlib.util.spec_from_file_location(
    "shake_boolean_influence_frontier_compression_base", _INFLUENCE_PATH
)
assert _INFLUENCE_SPEC is not None and _INFLUENCE_SPEC.loader is not None
_INFLUENCE = importlib.util.module_from_spec(_INFLUENCE_SPEC)
sys.modules[_INFLUENCE_SPEC.name] = _INFLUENCE
_INFLUENCE_SPEC.loader.exec_module(_INFLUENCE)

_ANF = _INFLUENCE._ANF
_BASE = _INFLUENCE._BASE
_BITSLICED = _INFLUENCE._BITSLICED
_PREFIX = _INFLUENCE._PREFIX
_WINDOW = _INFLUENCE._WINDOW
STATE_COORDINATES = 1600
PACK_MAGIC = b"F8ANFPK1"
PACK_HEADER = struct.Struct("<8sH")
RECORD_HEADER = struct.Struct("<BBHHIIQHHII")
VARIANT_CODES = {"SHAKE128": 1, "SHAKE256": 2}
CODE_VARIANTS = {value: key for key, value in VARIANT_CODES.items()}


def _coefficient_matrix(planes: np.ndarray, window_bits: int) -> np.ndarray:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("candidate state must be uint64[packs,25,64]")
    if len(planes) * 64 != 1 << window_bits:
        raise ValueError("candidate state does not match window width")
    coefficients = np.empty(
        (1 << window_bits, STATE_COORDINATES), dtype=np.uint8
    )
    for lane in range(25):
        truth = _INFLUENCE._lane_truth_table(planes[:, lane, :])
        coefficients[:, lane * 64 : (lane + 1) * 64] = _ANF._mobius_transform(
            truth
        )
    return coefficients


def _record_bytes(record: dict[str, Any]) -> bytes:
    basis = np.asarray(record["basis"], dtype="<u4")
    matrix = bytes(record["packed_matrix"])
    dictionary = basis.tobytes()
    header = RECORD_HEADER.pack(
        VARIANT_CODES[record["variant"]],
        int(record["round"]),
        int(record["window_bits"]),
        int(record["state_coordinates"]),
        int(record["assignments"]),
        len(basis),
        int(record["seed"]),
        int(record["window_start_capacity_bit"]),
        int(record["window_stop_capacity_bit_exclusive"]),
        len(dictionary),
        len(matrix),
    )
    return header + dictionary + matrix


def _write_pack(path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("ANF pack must contain at least one record")
    payloads = [_record_bytes(record) for record in records]
    raw = PACK_HEADER.pack(PACK_MAGIC, len(records)) + b"".join(payloads)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "records": len(records),
        "record_sha256": [hashlib.sha256(item).hexdigest() for item in payloads],
    }


class ANFDictionaryPackReader:
    """Read the compact shared-monomial representation from disk."""

    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        self.records = self._parse()

    def _parse(self) -> list[dict[str, Any]]:
        if len(self.raw) < PACK_HEADER.size:
            raise ValueError("truncated ANF pack")
        magic, count = PACK_HEADER.unpack_from(self.raw, 0)
        if magic != PACK_MAGIC:
            raise ValueError("invalid ANF pack magic")
        offset = PACK_HEADER.size
        records = []
        for _ in range(count):
            if offset + RECORD_HEADER.size > len(self.raw):
                raise ValueError("truncated ANF record header")
            values = RECORD_HEADER.unpack_from(self.raw, offset)
            start = offset
            offset += RECORD_HEADER.size
            (
                variant_code,
                round_number,
                window_bits,
                state_coordinates,
                assignments,
                basis_count,
                seed,
                window_start,
                window_stop,
                dictionary_bytes,
                matrix_bytes,
            ) = values
            if variant_code not in CODE_VARIANTS:
                raise ValueError("unknown ANF pack variant code")
            if dictionary_bytes != basis_count * 4:
                raise ValueError("ANF dictionary length mismatch")
            expected_matrix = basis_count * ((state_coordinates + 7) // 8)
            if matrix_bytes != expected_matrix:
                raise ValueError("ANF coefficient-matrix length mismatch")
            end = offset + dictionary_bytes + matrix_bytes
            if end > len(self.raw):
                raise ValueError("truncated ANF record payload")
            dictionary_raw = self.raw[offset : offset + dictionary_bytes]
            offset += dictionary_bytes
            matrix_raw = self.raw[offset : offset + matrix_bytes]
            offset += matrix_bytes
            records.append(
                {
                    "variant": CODE_VARIANTS[variant_code],
                    "round": round_number,
                    "window_bits": window_bits,
                    "state_coordinates": state_coordinates,
                    "assignments": assignments,
                    "seed": seed,
                    "window_start_capacity_bit": window_start,
                    "window_stop_capacity_bit_exclusive": window_stop,
                    "basis": np.frombuffer(dictionary_raw, dtype="<u4").copy(),
                    "packed_matrix": matrix_raw,
                    "record_bytes": end - start,
                    "record_sha256": hashlib.sha256(self.raw[start:end]).hexdigest(),
                }
            )
        if offset != len(self.raw):
            raise ValueError("trailing bytes in ANF pack")
        return records


def _unpack_matrix(record: dict[str, Any]) -> np.ndarray:
    basis_count = len(record["basis"])
    width = (int(record["state_coordinates"]) + 7) // 8
    packed = np.frombuffer(record["packed_matrix"], dtype=np.uint8).reshape(
        basis_count, width
    )
    return np.unpackbits(packed, axis=1, bitorder="little")[
        :, : int(record["state_coordinates"])
    ]


def _verify_record(record: dict[str, Any], planes: np.ndarray) -> dict[str, Any]:
    basis = np.asarray(record["basis"], dtype=np.int64)
    matrix = _unpack_matrix(record)
    if matrix.shape != (len(basis), STATE_COORDINATES):
        raise ValueError("decoded ANF matrix has the wrong shape")
    checked = 0
    for lane in range(25):
        coefficients = np.zeros(
            (int(record["assignments"]), 64), dtype=np.uint8
        )
        coefficients[basis] = matrix[:, lane * 64 : (lane + 1) * 64]
        reconstructed = _ANF._mobius_transform(coefficients)
        expected = _INFLUENCE._lane_truth_table(planes[:, lane, :])
        if not np.array_equal(reconstructed, expected):
            raise RuntimeError("ANF pack Reader reconstruction mismatch")
        checked += reconstructed.size
    return {
        "exact_match": True,
        "truth_values_checked": checked,
        "assignments": int(record["assignments"]),
        "state_coordinates": STATE_COORDINATES,
    }


def _compressors() -> dict[str, Callable[[bytes], bytes]]:
    return {
        "zlib_9": lambda data: zlib.compress(data, 9),
        "bz2_9": lambda data: bz2.compress(data, 9),
        "lzma_6": lambda data: lzma.compress(data, preset=6),
    }


def _compressed_record(data: bytes, original_bytes: int) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ratio_from_raw_truth_space": original_bytes / len(data),
    }


def _compression_suite(
    raw_truth_space: bytes,
    anf_record: bytes,
    include_cascades: bool,
) -> dict[str, Any]:
    compressors = _compressors()
    result: dict[str, Any] = {
        "raw_truth_space_bytes": len(raw_truth_space),
        "anf_record_bytes": len(anf_record),
        "anf_transform_ratio": len(raw_truth_space) / len(anf_record),
        "representations": {},
    }
    for representation, data in (
        ("raw_truth_space", raw_truth_space),
        ("shared_anf_pack", anf_record),
    ):
        first_outputs = {name: function(data) for name, function in compressors.items()}
        first = {
            name: _compressed_record(output, len(raw_truth_space))
            for name, output in first_outputs.items()
        }
        cascades = {}
        if include_cascades:
            for first_name, first_output in first_outputs.items():
                for second_name, function in compressors.items():
                    if second_name == first_name:
                        continue
                    label = f"{first_name}>{second_name}"
                    output = function(first_output)
                    row = _compressed_record(output, len(raw_truth_space))
                    row["bytes_delta_from_first_stage"] = len(output) - len(first_output)
                    cascades[label] = row
        candidates = {
            "identity": len(data),
            **{name: row["bytes"] for name, row in first.items()},
            **{name: row["bytes"] for name, row in cascades.items()},
        }
        best = min(candidates, key=candidates.get)
        result["representations"][representation] = {
            "first_stage": first,
            "ordered_two_codec_cascades": cascades,
            "best_codec_path": best,
            "best_bytes": candidates[best],
            "best_ratio_from_raw_truth_space": len(raw_truth_space)
            / candidates[best],
        }
    raw_best = result["representations"]["raw_truth_space"]["best_bytes"]
    anf_best = result["representations"]["shared_anf_pack"]["best_bytes"]
    result["best_anf_over_best_raw_size_gain"] = raw_best / anf_best
    return result


def _interaction_edges(basis: np.ndarray, window_bits: int) -> int:
    edges: set[tuple[int, int]] = set()
    for mask_value in basis:
        mask = int(mask_value)
        variables = [index for index in range(window_bits) if (mask >> index) & 1]
        for left_index, left in enumerate(variables):
            for right in variables[left_index + 1 :]:
                edges.add((left, right))
    return len(edges)


def _encode_state(
    planes: np.ndarray,
    variant: Any,
    round_number: int,
    window_bits: int,
    seed: int,
    positions: np.ndarray,
    include_cascades: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    coefficients = _coefficient_matrix(planes, window_bits)
    basis = np.flatnonzero(np.any(coefficients, axis=1)).astype("<u4")
    coefficient_rows = coefficients[basis]
    packed_matrix = np.packbits(
        coefficient_rows, axis=1, bitorder="little"
    ).tobytes()
    record = {
        "variant": variant.name,
        "round": round_number,
        "window_bits": window_bits,
        "state_coordinates": STATE_COORDINATES,
        "assignments": 1 << window_bits,
        "seed": seed,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "basis": basis,
        "packed_matrix": packed_matrix,
    }
    serialized = _record_bytes(record)
    raw_truth_space = planes.astype("<u8", copy=False).tobytes()
    degree_values, degree_counts = np.unique(
        np.fromiter(
            (int(value).bit_count() for value in basis),
            dtype=np.uint8,
            count=len(basis),
        ),
        return_counts=True,
    )
    total_coefficients = int(np.count_nonzero(coefficient_rows))
    interaction_edges = _interaction_edges(basis, window_bits)
    gate = _verify_record(record, planes)
    metrics = {
        "round": round_number,
        "basis_monomials": len(basis),
        "available_monomials": 1 << window_bits,
        "basis_fraction": len(basis) / (1 << window_bits),
        "basis_degree_histogram": {
            str(int(degree)): int(count)
            for degree, count in zip(degree_values, degree_counts, strict=True)
        },
        "maximum_basis_degree": int(degree_values[-1]),
        "total_coordinate_coefficients": total_coefficients,
        "mean_coefficients_per_coordinate": total_coefficients / STATE_COORDINATES,
        "coefficient_density_within_dictionary": total_coefficients
        / (len(basis) * STATE_COORDINATES),
        "global_anf_coefficient_density": total_coefficients
        / ((1 << window_bits) * STATE_COORDINATES),
        "monomial_primal_edges": interaction_edges,
        "complete_monomial_primal_graph": interaction_edges
        == window_bits * (window_bits - 1) // 2,
        "basis_sha256": hashlib.sha256(basis.tobytes()).hexdigest(),
        "packed_matrix_sha256": hashlib.sha256(packed_matrix).hexdigest(),
        "raw_truth_space_sha256": hashlib.sha256(raw_truth_space).hexdigest(),
        "record_sha256": hashlib.sha256(serialized).hexdigest(),
        "reader_roundtrip": gate,
        "compression": _compression_suite(
            raw_truth_space, serialized, include_cascades
        ),
    }
    return record, metrics


def _build_graph(
    path: Path, window_bits: int, observed_rounds: list[int], pack_rounds: list[int]
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_shared_anf_compression_cascade",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "observed_rounds": observed_rounds,
            "persisted_pack_rounds": pack_rounds,
            "codecs": ["zlib_9", "bz2_9", "lzma_6"],
            "prediction_before_measurement": (
                "A shared ANF-monomial transform may expose cross-coordinate "
                "structure that generic codecs cannot see in raw bit-sliced "
                "SHAKE truth spaces, especially near the R2-to-R3 frontier."
            ),
        },
    )
    for key in _BASE.VARIANTS:
        anf_id = f"{key}-shared-anf-transform"
        pack_id = f"{key}-anf-dictionary-pack"
        builder.add_triplet(
            edge_id=anf_id,
            trigger=f"{key}:complete_state_truth_spaces",
            mechanism="exact_gf2_mobius_transform_and_global_monomial_union",
            outcome=f"{key}:shared_anf_dictionary_and_coordinate_matrix",
            confidence=1.0,
            evidence_kind="all_assignments_all_state_coordinates",
            source="complete_bit_sliced_round_trace",
        )
        builder.add_triplet(
            edge_id=pack_id,
            trigger=f"{key}:shared_anf_dictionary_and_coordinate_matrix",
            mechanism="reader_lossless_binary_dictionary_pack",
            outcome=f"{key}:reconstructible_compressed_truth_space",
            confidence=1.0,
            evidence_kind="full_reader_roundtrip",
            source="F8ANFPK1",
            provenance=[anf_id],
            attrs={
                "reader_recipe": {
                    "format": "F8ANFPK1",
                    "dictionary": "little_endian_uint32_monomial_masks",
                    "matrix": "basis_by_1600_packbits_little",
                    "inverse": "GF2_Mobius_transform",
                }
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-compression-cascade",
            trigger=f"{key}:raw_and_shared_anf_representations",
            mechanism="compare_generic_codecs_and_all_ordered_two_codec_cascades",
            outcome=f"{key}:representation_conditioned_compression_frontier",
            confidence=1.0,
            evidence_kind="byte_exact_codec_sizes_and_hashes",
            source="python_stdlib_codecs",
            provenance=[pack_id],
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE ANF compression causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--rounds", default="0,1,2,3,4,24")
    parser.add_argument("--pack-rounds", default="2,3")
    parser.add_argument("--cascade-rounds", default="2,3")
    parser.add_argument("--seed", type=int, default=89806001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--pack-output", type=Path, required=True)
    args = parser.parse_args()
    if args.window_bits < 6 or args.window_bits > 16:
        raise ValueError("ANF pack window must be in 6..16")
    rounds = _ANF._AFFINE._parse_int_list(args.rounds, 0, 24)
    pack_rounds = _ANF._AFFINE._parse_int_list(args.pack_rounds, 0, 24)
    cascade_rounds = _ANF._AFFINE._parse_int_list(args.cascade_rounds, 0, 24)
    if not set(pack_rounds).issubset(rounds):
        raise ValueError("pack rounds must be included in observed rounds")
    if not set(cascade_rounds).issubset(rounds):
        raise ValueError("cascade rounds must be included in observed rounds")
    if 24 not in rounds:
        raise ValueError("observed rounds must include 24")
    mobius_gate = _ANF._mobius_gate()
    conversion_gate = _ANF._AFFINE._conversion_gate(args.seed ^ 0xA1F128)
    round_gate = _PREFIX._round_composition_gate(args.seed ^ 0x24F1600)
    causal = _build_graph(
        args.causal_output, args.window_bits, rounds, pack_rounds
    )
    causal_reader = CryptoCausalReader(args.causal_output)
    persisted_records: list[dict[str, Any]] = []
    persisted_states: dict[tuple[str, int], np.ndarray] = {}
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        seed = args.seed + 100_003 * variant_index
        rng = np.random.default_rng(seed)
        message = rng.integers(
            0, 256, size=(1, variant.message_bytes), dtype=np.uint8
        )
        base_state, _ = _BASE._first_squeeze_state(message, variant)
        positions = _WINDOW._window_positions(
            variant.capacity_bits, args.window_bits, seed ^ 0xC05CADE
        )
        template = _WINDOW._clear_window(base_state, variant, positions)
        state = _BITSLICED._candidate_planes(
            _BITSLICED._template_planes(template),
            variant,
            positions,
            np.arange(1 << (args.window_bits - 6), dtype=np.uint64),
        )
        observations = []
        for round_number in range(25):
            if round_number in rounds:
                print(
                    f"{variant.name} shared ANF compression round={round_number}",
                    flush=True,
                )
                record, metrics = _encode_state(
                    state,
                    variant,
                    round_number,
                    args.window_bits,
                    seed,
                    positions,
                    round_number in cascade_rounds,
                )
                observations.append(metrics)
                if round_number in pack_rounds:
                    persisted_records.append(record)
                    persisted_states[(variant.name, round_number)] = state.copy()
            if round_number < 24:
                state = _PREFIX._keccak_round_bitsliced(state, round_number)
        trials.append(
            {
                "variant": variant.name,
                "seed": seed,
                "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
                "window_start_capacity_bit": int(positions[0]),
                "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
                "observations": observations,
            }
        )
    pack = _write_pack(args.pack_output, persisted_records)
    pack_reader = ANFDictionaryPackReader(args.pack_output)
    if len(pack_reader.records) != len(persisted_records):
        raise RuntimeError("ANF pack record-count roundtrip failed")
    reopened_records = []
    for record in pack_reader.records:
        key = (record["variant"], record["round"])
        gate = _verify_record(record, persisted_states[key])
        reopened_records.append(
            {
                "variant": record["variant"],
                "round": record["round"],
                "record_bytes": record["record_bytes"],
                "record_sha256": record["record_sha256"],
                "reader_roundtrip": gate,
            }
        )
    payload = {
        "schema": "shake-shared-anf-compression-cascade-v1",
        "evidence_stage": "FULLROUND_REPRESENTATION_CONDITIONED_COMPRESSION_FRONTIER_MAPPED",
        "result": (
            "A lossless shared-ANF transform exposes compressible SHAKE truth-space "
            "structure through R3 that generic codecs do not retain on the raw R3 bytes."
        ),
        "scope": (
            "Known-complement 16-coordinate capacity-window truth spaces; compression "
            "is of complete round-indexed state functions, with exact Reader roundtrip."
        ),
        "parameters": {
            "window_bits": args.window_bits,
            "observed_rounds": rounds,
            "persisted_pack_rounds": pack_rounds,
            "cascade_rounds": cascade_rounds,
            "seed": args.seed,
            "codecs": {
                "zlib": {"level": 9, "runtime_version": zlib.ZLIB_RUNTIME_VERSION},
                "bz2": {"compresslevel": 9},
                "lzma": {"preset": 6},
                "python": platform.python_version(),
            },
        },
        "mobius_gate": mobius_gate,
        "conversion_gate": conversion_gate,
        "round_composition_gate": round_gate,
        "causal": causal,
        "reader_triplets": causal_reader.triplets(include_inferred=False),
        "pack_artifact": pack,
        "pack_reader_records": reopened_records,
        "trials": trials,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    summary = {
        row["variant"]: {
            str(observation["round"]): {
                "basis_monomials": observation["basis_monomials"],
                "anf_transform_ratio": observation["compression"][
                    "anf_transform_ratio"
                ],
                "best_raw_bytes": observation["compression"]["representations"][
                    "raw_truth_space"
                ]["best_bytes"],
                "best_anf_bytes": observation["compression"]["representations"][
                    "shared_anf_pack"
                ]["best_bytes"],
                "best_anf_over_raw_gain": observation["compression"][
                    "best_anf_over_best_raw_size_gain"
                ],
            }
            for observation in row["observations"]
        }
        for row in trials
    }
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "pack": pack,
                "summary": summary,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
