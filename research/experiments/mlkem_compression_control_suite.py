#!/usr/bin/env python3
"""Replicated ML-KEM compression/packing isolation using real ciphertexts."""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    u_bytes: int
    coefficient_bits: int
    coefficient_count: int


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", 640, 10, 512),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", 960, 10, 768),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", 1408, 11, 1024),
)


def _decode_little_endian(data: bytes, width: int, count: int) -> np.ndarray:
    accumulator = 0
    bits = 0
    values: list[int] = []
    mask = (1 << width) - 1
    for byte in data:
        accumulator |= byte << bits
        bits += 8
        while bits >= width and len(values) < count:
            values.append(accumulator & mask)
            accumulator >>= width
            bits -= width
    if len(values) != count:
        raise ValueError(f"decoded {len(values)} coefficients, expected {count}")
    return np.asarray(values, dtype=np.uint16)


def _score(stream: bytes, baseline_seed: int) -> dict[str, float | int]:
    usable = len(stream) - (len(stream) % 32)
    rows = np.frombuffer(stream[:usable], dtype=np.uint8).reshape(-1, 32).copy()
    standard = compute_casi_score(rows, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(rows, baseline_seed=baseline_seed)
    compressed = zlib.compress(stream, level=9)
    return {
        "rows": len(rows),
        "casi_standard": float(standard["casi"]),
        "casi_amplified": float(amplified["casi"]),
        "casi_operational_max": float(max(standard["casi"], amplified["casi"])),
        "compression_ratio": len(compressed) / len(stream),
    }


def _one_seed(variant: Variant, operations: int, seed: int) -> dict[str, Any]:
    module = importlib.import_module(variant.module)
    rng = np.random.default_rng(seed)
    original_parts: list[bytes] = []
    coefficients: list[np.ndarray] = []
    roundtrips = 0
    for _ in range(operations):
        public_key, secret_key = module.generate_keypair()
        ciphertext, shared_secret = module.encrypt(public_key)
        roundtrips += module.decrypt(secret_key, ciphertext) == shared_secret
        packed_u = ciphertext[: variant.u_bytes]
        original_parts.append(packed_u)
        coefficients.append(_decode_little_endian(packed_u, variant.coefficient_bits, variant.coefficient_count))
    original = b"".join(original_parts)
    actual = np.concatenate(coefficients)
    mask = (1 << variant.coefficient_bits) - 1
    high_mask = np.uint16(0xFFFF ^ mask)
    padding_b = rng.integers(0, 65536, size=len(actual), dtype=np.uint16)
    stream_b = ((actual & np.uint16(mask)) | (padding_b & high_mask)).astype("<u2").tobytes()
    uniform = rng.integers(0, mask + 1, size=len(actual), dtype=np.uint16)
    padding_c = rng.integers(0, 65536, size=len(actual), dtype=np.uint16)
    stream_c = ((uniform & np.uint16(mask)) | (padding_c & high_mask)).astype("<u2").tobytes()
    stream_d = rng.integers(0, 256, size=len(original), dtype=np.uint8).tobytes()
    streams = {
        "A_real_packed_u": original,
        "B_real_coefficients_random_high_bits": stream_b[: len(original)],
        "C_uniform_coefficients_random_high_bits": stream_c[: len(original)],
        "D_uniform_random_bytes": stream_d,
    }
    baseline_seed = 0xC0DEC0DE + seed
    return {
        "seed": seed,
        "operations": operations,
        "successful_decapsulations": roundtrips,
        "coefficient_count": len(actual),
        "scores": {name: _score(stream, baseline_seed) for name, stream in streams.items()},
    }


def _summary(records: list[dict[str, Any]], key: str) -> dict[str, float | list[float]]:
    values = [float(record["scores"][key]["casi_operational_max"]) for record in records]
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
    }


def _run_variant(variant: Variant, operations: int, seeds: int) -> dict[str, Any]:
    records = [_one_seed(variant, operations, 42 + 7919 * index) for index in range(seeds)]
    names = list(records[0]["scores"])
    summaries = {name: _summary(records, name) for name in names}
    return {
        "variant": variant.name,
        "u_coefficient_bits": variant.coefficient_bits,
        "u_coefficients_per_operation": variant.coefficient_count,
        "records": records,
        "summaries": summaries,
        "effect_estimates": {
            "packing_A_minus_B": summaries["A_real_packed_u"]["mean"] - summaries["B_real_coefficients_random_high_bits"]["mean"],
            "coefficient_model_B_minus_C": summaries["B_real_coefficients_random_high_bits"]["mean"] - summaries["C_uniform_coefficients_random_high_bits"]["mean"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=500)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--variants", nargs="*", default=[variant.name for variant in VARIANTS])
    args = parser.parse_args()
    if args.operations < 32 or args.seeds < 2:
        raise ValueError("operations >= 32 and seeds >= 2 are required")
    available = {variant.name: variant for variant in VARIANTS}
    unknown = sorted(set(args.variants) - set(available))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    results = []
    for name in args.variants:
        print(f"running {name}", flush=True)
        results.append(_run_variant(available[name], args.operations, args.seeds))
    payload = {
        "schema_version": 1,
        "experiment": "mlkem_compression_control_suite",
        "parameters": {"operations": args.operations, "seeds": args.seeds, "variants": args.variants},
        "environment": {"python": sys.version, "platform": platform.platform()},
        "method": "A/B/C/D isolates real packed ciphertext, real decoded coefficients, uniform matched coefficients, and uniform bytes.",
        "results": results,
        "security_scope": "Distribution/format measurement only; no security or key-recovery claim.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
