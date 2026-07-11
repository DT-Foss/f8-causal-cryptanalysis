#!/usr/bin/env python3
"""Trace real ML-KEM ciphertext v-polynomials through decompress and NTT.

This experiment uses exported PQClean functions from the pinned pqcrypto wheel.
It is an internal representation study, not a public-output distinguisher and
not an IND-CPA/IND-CCA security test.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.bvn import route_ensemble, verify_routes


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    prefix: str
    v_bytes: int


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", "PQCLEAN_MLKEM512_CLEAN", 128),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", "PQCLEAN_MLKEM768_CLEAN", 128),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", "PQCLEAN_MLKEM1024_CLEAN", 160),
)


def _native_lib(module_path: str) -> ctypes.CDLL:
    module = __import__(module_path, fromlist=["x"])
    extension_path = Path(module.__file__).parents[1] / "_kem" / (Path(module.__file__).stem + ".cpython-313-darwin.so")
    if not extension_path.exists():
        candidates = list((Path(module.__file__).parents[1] / "_kem").glob(f"{Path(module.__file__).stem}*.so"))
        if len(candidates) != 1:
            raise RuntimeError(f"cannot locate extension for {module_path}")
        extension_path = candidates[0]
    return ctypes.CDLL(str(extension_path))


def _metric(first: np.ndarray, second: np.ndarray, shift: int = 5) -> dict[str, float | int]:
    """F8-style dependence of byte matrices with a matched shape."""
    if first.shape != second.shape:
        raise ValueError("representation matrices must have equal shape")
    n_bins = 2 ** (8 - shift)
    difference = first ^ second
    source, delta = first >> shift, difference >> shift
    tested = significant = 0
    max_chi2 = 0.0
    for i in range(first.shape[1]):
        for j in range(first.shape[1]):
            flat = source[:, i].astype(np.int64) * n_bins + delta[:, j]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            chi2, p_value = result
            tested += 1
            significant += p_value < 0.05
            max_chi2 = max(max_chi2, chi2)
    return {
        "tested_pairs": tested,
        "significant_pairs": significant,
        "significant_rate": significant / max(tested, 1),
        "max_chi2": max_chi2,
        "alpha": 0.05,
    }


def _field_metric(first: np.ndarray, second: np.ndarray, bins: int = 8) -> dict[str, float | int]:
    """F8-Fq: quantized dependence over ML-KEM's coefficient field, not bytes."""
    if first.shape != second.shape:
        raise ValueError("coefficient matrices must have equal shape")
    q = 3329
    positions = np.arange(0, first.shape[1], 16)
    source = np.minimum((first * bins) // q, bins - 1)
    delta = np.minimum((((second - first) % q) * bins) // q, bins - 1)
    tested = significant = 0
    max_chi2 = 0.0
    for i in positions:
        for j in positions:
            flat = source[:, i].astype(np.int64) * bins + delta[:, j]
            table = np.bincount(flat, minlength=bins * bins).reshape(bins, bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            chi2, p_value = result
            tested += 1
            significant += p_value < 0.05
            max_chi2 = max(max_chi2, chi2)
    return {
        "tested_pairs": tested,
        "significant_pairs": significant,
        "significant_rate": significant / max(tested, 1),
        "max_chi2": max_chi2,
        "alpha": 0.05,
        "field_modulus": q,
        "bins": bins,
        "positions": [int(position) for position in positions],
    }


def _metric_summary(metrics: list[dict[str, float | int]]) -> dict[str, float | list[float]]:
    """Summarize route controls without treating routes as independent samples."""
    rates = [float(metric["significant_rate"]) for metric in metrics]
    return {
        "significant_rate_values": rates,
        "significant_rate_mean": float(np.mean(rates)),
        "significant_rate_sample_sd_ddof1": float(np.std(rates, ddof=1)) if len(rates) > 1 else 0.0,
        "significant_rate_minimum": float(np.min(rates)),
        "significant_rate_maximum": float(np.max(rates)),
    }


def _trace_variant(variant: Variant, operations: int, permutations: int, bvn_routes: int) -> dict[str, Any]:
    module = __import__(variant.module, fromlist=["x"])
    lib = _native_lib(variant.module)
    decompress = getattr(lib, f"{variant.prefix}_poly_decompress")
    compress = getattr(lib, f"{variant.prefix}_poly_compress")
    ntt = getattr(lib, f"{variant.prefix}_ntt")
    decompress.argtypes = [ctypes.POINTER(ctypes.c_int16), ctypes.POINTER(ctypes.c_uint8)]
    compress.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_int16)]
    ntt.argtypes = [ctypes.POINTER(ctypes.c_int16)]

    packed_rows: list[np.ndarray] = []
    coeff_rows: list[np.ndarray] = []
    ntt_rows: list[np.ndarray] = []
    coeff_field_rows: list[np.ndarray] = []
    ntt_field_rows: list[np.ndarray] = []
    recompression_ok = 0
    roundtrip_ok = 0
    for _ in range(operations):
        public_key, secret_key = module.generate_keypair()
        ciphertext, shared_secret = module.encrypt(public_key)
        roundtrip_ok += module.decrypt(secret_key, ciphertext) == shared_secret
        packed = ciphertext[-variant.v_bytes :]
        packed_buffer = (ctypes.c_uint8 * variant.v_bytes).from_buffer_copy(packed)
        coefficients = (ctypes.c_int16 * 256)()
        decompress(coefficients, packed_buffer)
        recompressed = (ctypes.c_uint8 * variant.v_bytes)()
        compress(recompressed, coefficients)
        recompression_ok += bytes(recompressed) == packed
        coeff_bytes = np.frombuffer(bytes(coefficients), dtype=np.uint8)
        coeff_field = np.frombuffer(bytes(coefficients), dtype=np.int16).astype(np.int64) % 3329
        ntt(coefficients)
        ntt_bytes = np.frombuffer(bytes(coefficients), dtype=np.uint8)
        ntt_field = np.frombuffer(bytes(coefficients), dtype=np.int16).astype(np.int64) % 3329
        # All representations are truncated to the packed v width so their
        # F8-style matrices differ only in representation, never in sample count.
        packed_rows.append(np.frombuffer(packed, dtype=np.uint8))
        coeff_rows.append(coeff_bytes[: variant.v_bytes])
        ntt_rows.append(ntt_bytes[: variant.v_bytes])
        coeff_field_rows.append(coeff_field)
        ntt_field_rows.append(ntt_field)

    packed_matrix = np.stack(packed_rows)
    coeff_matrix = np.stack(coeff_rows)
    ntt_matrix = np.stack(ntt_rows)
    coeff_field_matrix = np.stack(coeff_field_rows)
    ntt_field_matrix = np.stack(ntt_field_rows)
    rng = np.random.default_rng(0x4E5454 + variant.v_bytes)
    shuffled = []
    field_shuffled = []
    for _ in range(permutations):
        permutation = rng.permutation(operations)
        shuffled.append(_metric(coeff_matrix, ntt_matrix[permutation]))
        field_shuffled.append(_field_metric(coeff_field_matrix, ntt_field_matrix[permutation]))
    routes = route_ensemble(operations, bvn_routes, 0xB0A000 + variant.v_bytes)
    bvn_routed = [_metric(coeff_matrix, ntt_matrix[route]) for route in routes]
    field_bvn_routed = [_field_metric(coeff_field_matrix, ntt_field_matrix[route]) for route in routes]
    return {
        "variant": variant.name,
        "operations": operations,
        "functional_roundtrips": roundtrip_ok,
        "recompression_exact": recompression_ok,
        "representation_metrics": {
            "packed_v_to_coefficients": _metric(packed_matrix, coeff_matrix),
            "coefficients_to_ntt": _metric(coeff_matrix, ntt_matrix),
            "coefficients_to_shuffled_ntt": shuffled,
            "coefficients_to_bvn_routed_ntt": bvn_routed,
            "coefficients_to_bvn_routed_ntt_summary": _metric_summary(bvn_routed),
            "field_coefficients_to_ntt": _field_metric(coeff_field_matrix, ntt_field_matrix),
            "field_coefficients_to_shuffled_ntt": field_shuffled,
            "field_coefficients_to_bvn_routed_ntt": field_bvn_routed,
            "field_coefficients_to_bvn_routed_ntt_summary": _metric_summary(field_bvn_routed),
        },
        "bvn_route_check": verify_routes(routes),
        "scope_note": (
            "NTT is public implementation structure; this measures only representation dependence. "
            "BvN routes preserve each NTT sample row exactly while breaking the matched operation pairing."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=200)
    parser.add_argument("--permutations", type=int, default=5)
    parser.add_argument("--bvn-routes", type=int, default=16)
    parser.add_argument("--variants", nargs="*", default=[item.name for item in VARIANTS])
    args = parser.parse_args()
    if args.operations < 32 or args.permutations < 1 or args.bvn_routes < 4:
        raise ValueError("operations >= 32, permutations >= 1, and bvn-routes >= 4 are required")
    known = {item.name: item for item in VARIANTS}
    unknown = sorted(set(args.variants) - set(known))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    results = []
    for name in args.variants:
        print(f"tracing {name}", flush=True)
        results.append(_trace_variant(known[name], args.operations, args.permutations, args.bvn_routes))
    payload = {
        "schema_version": 1,
        "experiment": "mlkem_ntt_trace_suite",
        "parameters": {
            "operations": args.operations,
            "permutations": args.permutations,
            "bvn_routes": args.bvn_routes,
            "variants": args.variants,
        },
        "environment": {"python": sys.version, "platform": platform.platform()},
        "results": results,
        "security_scope": "No security, key-recovery, IND-CPA, IND-CCA, or external distinguisher claim is tested.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
