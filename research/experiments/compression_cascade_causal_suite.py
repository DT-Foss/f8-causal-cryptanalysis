#!/usr/bin/env python3
"""Search for structure emerging only after lossless compression cascades.

Six distinct compressor families are applied to full-round cipher output:
DEFLATE, BWT/bzip2, LZMA, Zstandard, LZ4 and Brotli. All 36 ordered depth-two
cascades are evaluated, including repeated algorithms. Each exact same path is
applied to a length-matched deterministic random control. A candidate requires
an incremental stage-two effect beyond its stage-one parent after BH-FDR
correction across all paths.

Compression is a deterministic representation transform, not a cryptographic
oracle. The causal graph records only lossless transformation identities and
paired target-minus-random measurements.
"""

from __future__ import annotations

import argparse
import bz2
import functools
import hashlib
import itertools
import json
import lzma
import math
import platform
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import brotli
import lz4.frame
import numpy as np
import zstandard

from arx_carry_leak.ciphers import FULL_ROUNDS, get_generator
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, ExactRule
from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score


@dataclass(frozen=True)
class Compressor:
    name: str
    compress: Callable[[bytes], bytes]
    decompress: Callable[[bytes], bytes]


_ZSTD_COMPRESSOR = zstandard.ZstdCompressor(level=9)
_ZSTD_DECOMPRESSOR = zstandard.ZstdDecompressor()

COMPRESSORS = (
    Compressor("zlib", lambda data: zlib.compress(data, level=9), zlib.decompress),
    Compressor("bz2", lambda data: bz2.compress(data, compresslevel=9), bz2.decompress),
    Compressor("lzma", lambda data: lzma.compress(data, preset=6), lzma.decompress),
    Compressor("zstd", _ZSTD_COMPRESSOR.compress, _ZSTD_DECOMPRESSOR.decompress),
    Compressor(
        "lz4",
        lambda data: lz4.frame.compress(
            data, compression_level=9, block_linked=True, content_checksum=True
        ),
        lz4.frame.decompress,
    ),
    Compressor(
        "brotli",
        lambda data: brotli.compress(data, quality=9),
        brotli.decompress,
    ),
)


def _entropy(data: bytes) -> float:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _nibble_mutual_information(data: bytes) -> float:
    values = np.frombuffer(data, dtype=np.uint8)
    if len(values) < 2:
        return 0.0
    first = values[:-1] >> 4
    second = values[1:] >> 4
    joint = np.bincount(first.astype(np.int64) * 16 + second, minlength=256).reshape(16, 16)
    probabilities = joint / joint.sum()
    px = probabilities.sum(axis=1, keepdims=True)
    py = probabilities.sum(axis=0, keepdims=True)
    expected = px @ py
    valid = probabilities > 0
    return float(np.sum(probabilities[valid] * np.log2(probabilities[valid] / expected[valid])))


def _fingerprint(data: bytes, raw_length: int) -> dict[str, float | int]:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = len(data) / 256
    chi_square = float(np.sum((counts - expected) ** 2 / expected))
    return {
        "bytes": len(data),
        "ratio_to_raw": len(data) / raw_length,
        "entropy_bits_per_byte": _entropy(data),
        "adjacent_nibble_mutual_information": _nibble_mutual_information(data),
        "byte_uniform_reduced_chi_square": chi_square / 255,
    }


def _paired_test(values: list[float]) -> dict[str, float | int]:
    differences = np.asarray(values, dtype=float)
    observed = float(np.mean(differences))
    null = np.asarray(
        [np.mean(differences * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(differences))]
    )
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "mean": observed,
        "sample_sd_ddof1": float(np.std(differences, ddof=1)) if len(differences) > 1 else 0.0,
        "seed_pairs": len(differences),
        "exact_assignments": len(null),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def _bh_qvalues(p_values: list[float]) -> list[float]:
    count = len(p_values)
    order = np.argsort(p_values)
    q_values = np.ones(count)
    running = 1.0
    for reverse_rank in range(count - 1, -1, -1):
        index = int(order[reverse_rank])
        rank = reverse_rank + 1
        running = min(running, p_values[index] * count / rank)
        q_values[index] = running
    return [float(value) for value in q_values]


def _f8_output(rows: np.ndarray, shift: int = 5) -> float:
    if len(rows) < 32:
        return float("nan")
    first, second = rows[:-1], rows[1:]
    source = first >> shift
    delta = (first ^ second) >> shift
    bins = 2 ** (8 - shift)
    significant = tested = 0
    for i in range(32):
        for j in range(32):
            flat = source[:, i].astype(np.int64) * bins + delta[:, j]
            table = np.bincount(flat, minlength=bins * bins).reshape(bins, bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            tested += 1
            significant += result[1] < 0.05
    return significant / max(tested, 1)


def _deep_metrics(data: bytes, seed: int) -> dict[str, float | int]:
    usable = len(data) - len(data) % 32
    rows = np.frombuffer(data[:usable], dtype=np.uint8).reshape(-1, 32).copy()
    standard = compute_casi_score(rows, baseline_seed=0xC0A5 + seed)
    amplified = compute_amplified_score(rows, baseline_seed=0xC0A5 + seed)
    return {
        "rows": len(rows),
        "casi": float(max(standard["casi"], amplified["casi"])),
        "f8_output_rate": _f8_output(rows),
    }


def _apply_path(data: bytes, path: tuple[Compressor, ...]) -> tuple[bytes, bool]:
    transformed = data
    for compressor in path:
        transformed = compressor.compress(transformed)
    reconstructed = transformed
    for compressor in reversed(path):
        reconstructed = compressor.decompress(reconstructed)
    return transformed, reconstructed == data


def _seed_run(target: str, blocks: int, seed: int) -> dict[str, Any]:
    generator = get_generator(target)
    raw, _, _ = generator(blocks, FULL_ROUNDS[target], seed)
    rng = np.random.default_rng(0xA11CE + seed)
    random_control = rng.integers(0, 256, size=len(raw), dtype=np.uint8).tobytes()
    streams = {"target": raw, "random": random_control}
    record: dict[str, Any] = {
        "seed": seed,
        "raw_bytes": len(raw),
        "raw": {name: _fingerprint(data, len(raw)) for name, data in streams.items()},
        "stage1": {},
        "stage2": {},
    }
    stage1_cache: dict[tuple[str, str], bytes] = {}
    for compressor in COMPRESSORS:
        path_name = compressor.name
        record["stage1"][path_name] = {}
        for stream_name, data in streams.items():
            transformed, exact = _apply_path(data, (compressor,))
            stage1_cache[(stream_name, compressor.name)] = transformed
            record["stage1"][path_name][stream_name] = {
                **_fingerprint(transformed, len(raw)),
                "lossless_gate": exact,
            }
    for first, second in itertools.product(COMPRESSORS, repeat=2):
        path_name = f"{first.name}->{second.name}"
        record["stage2"][path_name] = {}
        for stream_name, data in streams.items():
            transformed = second.compress(stage1_cache[(stream_name, first.name)])
            reconstructed = first.decompress(second.decompress(transformed))
            record["stage2"][path_name][stream_name] = {
                **_fingerprint(transformed, len(raw)),
                "lossless_gate": reconstructed == data,
                "ratio_to_stage1": len(transformed) / len(stage1_cache[(stream_name, first.name)]),
            }
    return record


def _target_run(target: str, blocks: int, seeds: int, alpha: float) -> dict[str, Any]:
    records = [_seed_run(target, blocks, 42 + 1000 * index) for index in range(seeds)]
    stage1_tests = {}
    for compressor in COMPRESSORS:
        name = compressor.name
        differences = [
            record["stage1"][name]["target"]["ratio_to_raw"]
            - record["stage1"][name]["random"]["ratio_to_raw"]
            for record in records
        ]
        stage1_tests[name] = _paired_test(differences)
    path_names = [f"{first.name}->{second.name}" for first, second in itertools.product(COMPRESSORS, repeat=2)]
    total_tests = []
    incremental_tests = []
    for path_name in path_names:
        first_name = path_name.split("->", 1)[0]
        total_differences = []
        incremental_differences = []
        for record in records:
            stage1_excess = (
                record["stage1"][first_name]["target"]["ratio_to_raw"]
                - record["stage1"][first_name]["random"]["ratio_to_raw"]
            )
            stage2_excess = (
                record["stage2"][path_name]["target"]["ratio_to_raw"]
                - record["stage2"][path_name]["random"]["ratio_to_raw"]
            )
            total_differences.append(stage2_excess)
            incremental_differences.append(stage2_excess - stage1_excess)
        total_tests.append(_paired_test(total_differences))
        incremental_tests.append(_paired_test(incremental_differences))
    total_q = _bh_qvalues([float(test["two_sided_p"]) for test in total_tests])
    incremental_q = _bh_qvalues([float(test["two_sided_p"]) for test in incremental_tests])
    cascades = {}
    candidates = []
    for index, path_name in enumerate(path_names):
        first_name = path_name.split("->", 1)[0]
        result = {
            "total_target_minus_random": {**total_tests[index], "bh_q": total_q[index]},
            "incremental_beyond_stage1": {
                **incremental_tests[index],
                "bh_q": incremental_q[index],
            },
            "stage1_parent": stage1_tests[first_name],
        }
        cascades[path_name] = result
        if (
            result["total_target_minus_random"]["mean"] < 0
            and result["total_target_minus_random"]["bh_q"] < alpha
            and result["incremental_beyond_stage1"]["mean"] < 0
            and result["incremental_beyond_stage1"]["bh_q"] < alpha
        ):
            candidates.append(path_name)
    return {
        "target": target,
        "full_rounds": FULL_ROUNDS[target],
        "records": records,
        "stage1_tests": stage1_tests,
        "cascade_tests": cascades,
        "emergent_candidates": candidates,
        "all_lossless_gates_passed": all(
            value["lossless_gate"]
            for record in records
            for stage in (record["stage1"], record["stage2"])
            for path in stage.values()
            for value in path.values()
        ),
    }


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="compression_cascade_causal_suite", parameters=parameters)
    builder.add_rule(
        ExactRule(
            name="lossless_transform_composition",
            first="lossless_transform",
            second="lossless_transform",
            conclusion="lossless_transform",
            confidence_modifier=1.0,
        )
    )
    for result in results:
        target = result["target"]
        for compressor in COMPRESSORS:
            name = compressor.name
            builder.add_triplet(
                edge_id=f"{target}-{name}",
                trigger=f"{target}:raw",
                mechanism="lossless_transform",
                outcome=f"{target}:{name}",
                confidence=1.0,
                evidence_kind="lossless_roundtrip_verified",
                source=source,
                attrs={"algorithm": name, "paired_test": result["stage1_tests"][name]},
            )
        for path_name, test in result["cascade_tests"].items():
            first, second = path_name.split("->")
            builder.add_triplet(
                edge_id=f"{target}-{first}-{second}",
                trigger=f"{target}:{first}",
                mechanism="lossless_transform",
                outcome=f"{target}:{path_name}",
                confidence=1.0,
                evidence_kind="lossless_roundtrip_verified",
                source=source,
                attrs={"algorithm": second, "paired_tests": test},
            )
        for path_name in result["emergent_candidates"]:
            test = result["cascade_tests"][path_name]
            builder.add_triplet(
                edge_id=f"{target}-{path_name}-emergence",
                trigger=f"{target}:{path_name}",
                mechanism="incremental_structure_after_second_compressor",
                outcome="target_more_compressible_than_random_control",
                confidence=1.0 - float(test["incremental_beyond_stage1"]["bh_q"]),
                evidence_kind="paired_seed_test_bh_corrected",
                source=source,
                attrs=test,
            )
    builder.infer_exact_closure(max_hops=3)
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--targets", nargs="*", default=list(FULL_ROUNDS))
    args = parser.parse_args()
    if args.blocks < 1000 or args.seeds < 2:
        raise ValueError("blocks >= 1000 and seeds >= 2 required")
    unknown = sorted(set(args.targets) - set(FULL_ROUNDS))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    parameters = {
        "blocks": args.blocks,
        "seeds": args.seeds,
        "alpha": args.alpha,
        "targets": args.targets,
        "compressors": [compressor.name for compressor in COMPRESSORS],
        "ordered_depth_two_paths": len(COMPRESSORS) ** 2,
    }
    results = []
    for target in args.targets:
        print(f"compression cascade causal sweep: {target}", flush=True)
        results.append(_target_run(target, args.blocks, args.seeds, args.alpha))
    payload = {
        "schema_version": 1,
        "experiment": "compression_cascade_causal_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "platform": platform.platform(),
            "zstandard": zstandard.__version__,
            "lz4": lz4.__version__,
            "brotli": brotli.__version__,
        },
        "results": results,
        "scope_note": (
            "Lossless representation study. Candidate emergence requires paired target-vs-random and incremental "
            "stage-two effects after BH correction; it is not a key-recovery or security claim."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    graph_stats = _graph(results, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({graph_stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
