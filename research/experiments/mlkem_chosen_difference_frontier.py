#!/usr/bin/env python3
"""Screen chosen bit differences through real ML-KEM decompress -> NTT.

This is an open representation-inference experiment.  It mutates one public
compressed-v bit in each real ciphertext, traces both values through the
exported PQClean ``poly_decompress`` and ``ntt`` functions, and compares the
matched differential field distribution with row-repairing controls.  It is
not a valid ciphertext attack or a security-game experiment.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.f8 import _chi_square

Q = 3329
BIN_COUNT = 16


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
    module = importlib.import_module(module_path)
    extension_dir = Path(module.__file__).parents[1] / "_kem"
    stem = Path(module.__file__).stem
    preferred = extension_dir / f"{stem}.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so"
    if preferred.exists():
        return ctypes.CDLL(str(preferred))
    candidates = list(extension_dir.glob(f"{stem}*.so"))
    if len(candidates) != 1:
        raise RuntimeError(f"cannot locate ABI-matched extension for {module_path}: {candidates}")
    return ctypes.CDLL(str(candidates[0]))


def _trace_rows(variant: Variant, operations: int) -> tuple[np.ndarray, np.ndarray, int]:
    module = importlib.import_module(variant.module)
    lib = _native_lib(variant.module)
    decompress = getattr(lib, f"{variant.prefix}_poly_decompress")
    ntt = getattr(lib, f"{variant.prefix}_ntt")
    decompress.argtypes = [ctypes.POINTER(ctypes.c_int16), ctypes.POINTER(ctypes.c_uint8)]
    ntt.argtypes = [ctypes.POINTER(ctypes.c_int16)]
    packed_rows: list[np.ndarray] = []
    base_ntt_rows: list[np.ndarray] = []
    roundtrips = 0
    for _ in range(operations):
        public_key, secret_key = module.generate_keypair()
        ciphertext, shared_secret = module.encrypt(public_key)
        roundtrips += int(module.decrypt(secret_key, ciphertext) == shared_secret)
        packed = np.frombuffer(ciphertext[-variant.v_bytes :], dtype=np.uint8).copy()
        packed_buffer = (ctypes.c_uint8 * variant.v_bytes).from_buffer_copy(packed)
        coefficients = (ctypes.c_int16 * 256)()
        decompress(coefficients, packed_buffer)
        ntt(coefficients)
        field = np.frombuffer(bytes(coefficients), dtype=np.int16).astype(np.int32) % Q
        packed_rows.append(packed)
        base_ntt_rows.append(field)
    return np.stack(packed_rows), np.stack(base_ntt_rows), roundtrips


def _trace_mutated(variant: Variant, packed_rows: np.ndarray, bit: int) -> np.ndarray:
    bits = np.full(len(packed_rows), bit, dtype=np.int64)
    return _trace_mutated_bits(variant, packed_rows, bits)


def _trace_mutated_bits(variant: Variant, packed_rows: np.ndarray, bits: np.ndarray) -> np.ndarray:
    if bits.shape != (len(packed_rows),) or np.any(bits < 0) or np.any(bits >= variant.v_bytes * 8):
        raise ValueError("bits must contain one valid compressed-v bit per row")
    lib = _native_lib(variant.module)
    decompress = getattr(lib, f"{variant.prefix}_poly_decompress")
    ntt = getattr(lib, f"{variant.prefix}_ntt")
    decompress.argtypes = [ctypes.POINTER(ctypes.c_int16), ctypes.POINTER(ctypes.c_uint8)]
    ntt.argtypes = [ctypes.POINTER(ctypes.c_int16)]
    mutated = packed_rows.copy()
    rows = np.arange(len(packed_rows))
    byte_indices = bits // 8
    bit_masks = (1 << (bits % 8)).astype(np.uint8)
    mutated[rows, byte_indices] ^= bit_masks
    rows = []
    for packed in mutated:
        packed_buffer = (ctypes.c_uint8 * variant.v_bytes).from_buffer_copy(packed)
        coefficients = (ctypes.c_int16 * 256)()
        decompress(coefficients, packed_buffer)
        ntt(coefficients)
        rows.append(np.frombuffer(bytes(coefficients), dtype=np.int16).astype(np.int32) % Q)
    return np.stack(rows)


def _entropy_deficit(delta: np.ndarray) -> float:
    quantized = (delta.astype(np.int64) * BIN_COUNT // Q).astype(np.int64)
    max_entropy = np.log2(BIN_COUNT)
    deficits = []
    for index in range(quantized.shape[1]):
        counts = np.bincount(quantized[:, index], minlength=BIN_COUNT)
        probabilities = counts[counts > 0] / len(quantized)
        deficits.append(max_entropy + float(np.sum(probabilities * np.log2(probabilities))))
    return float(np.sum(deficits))


def _field_dependence(first: np.ndarray, second: np.ndarray) -> dict[str, float]:
    delta = (second.astype(np.int64) - first.astype(np.int64)) % Q
    return {
        "entropy_deficit_sum": _entropy_deficit(delta),
        "mean_delta": float(np.mean(delta)),
        "nonzero_fraction": float(np.mean(delta != 0)),
    }


def _analyse(first: np.ndarray, second: np.ndarray, *, routes: int, seed: int) -> dict[str, Any]:
    actual = _field_dependence(first, second)
    rng = np.random.default_rng(seed)
    controls = [_field_dependence(first, second[rng.permutation(len(second))]) for _ in range(routes)]
    effects = {}
    for metric in actual:
        values = np.asarray([control[metric] for control in controls], dtype=float)
        sd = float(values.std(ddof=1))
        difference = float(actual[metric] - values.mean())
        effects[metric] = {
            "difference": difference,
            "control_mean": float(values.mean()),
            "control_sd_ddof1": sd,
            "route_z": 0.0 if sd <= 1e-12 else difference / sd,
        }
    return {"actual": actual, "controls": controls, "effects": effects}


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": values,
        "mean": float(array.mean()),
        "sample_sd_ddof1": float(array.std(ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(array.min()),
        "maximum": float(array.max()),
    }


def _exact_sign_flip(values: list[float]) -> dict[str, float | int]:
    differences = np.asarray(values, dtype=float)
    observed = float(differences.mean())
    null = np.asarray([
        float(np.mean(differences * signs))
        for signs in np.array(np.meshgrid(*([(-1.0, 1.0)] * len(differences)))).T.reshape(-1, len(differences))
    ])
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "seed_pairs": len(differences),
    }


def _run_variant(variant: Variant, args: argparse.Namespace) -> dict[str, Any]:
    records: dict[int, list[dict[str, Any]]] = {bit: [] for bit in args.bits}
    roundtrips = []
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        np.random.seed(seed)
        print(f"mlkem chosen frontier {variant.name} seed={seed}", flush=True)
        packed, base, valid = _trace_rows(variant, args.operations)
        roundtrips.append(valid)
        random_controls = []
        random_rng = np.random.default_rng(seed ^ 0xB17B17)
        for _ in range(args.random_bit_routes):
            random_bits = random_rng.integers(0, variant.v_bytes * 8, size=args.operations, dtype=np.int64)
            random_mutated = _trace_mutated_bits(variant, packed, random_bits)
            random_controls.append(_field_dependence(base, random_mutated))
        for bit in args.bits:
            mutated = _trace_mutated(variant, packed, bit)
            analysis = _analyse(base, mutated, routes=args.routes, seed=seed ^ bit)
            random_effect = {}
            for metric in ("entropy_deficit_sum", "mean_delta", "nonzero_fraction"):
                null_values = np.asarray([control[metric] for control in random_controls], dtype=float)
                actual_value = _field_dependence(base, mutated)[metric]
                random_effect[metric] = {
                    "difference": float(actual_value - null_values.mean()),
                    "control_mean": float(null_values.mean()),
                    "control_sd_ddof1": float(null_values.std(ddof=1)),
                }
            analysis["random_bit_effects"] = random_effect
            analysis["seed"] = seed
            records[bit].append(analysis)
    results = []
    for bit, rows in records.items():
        metrics = {}
        for metric in ("entropy_deficit_sum", "mean_delta", "nonzero_fraction"):
            effects = [row["effects"][metric]["difference"] for row in rows]
            random_effects = [row["random_bit_effects"][metric]["difference"] for row in rows]
            metrics[metric] = {
                "effect": _summary(effects),
                "fixed_bit_vs_random_bit": {
                    "effect": _summary(random_effects),
                    "exact_sign_flip": _exact_sign_flip(random_effects),
                },
                "route_z": _summary([row["effects"][metric]["route_z"] for row in rows]),
                "exact_sign_flip": _exact_sign_flip(effects),
            }
        results.append({"bit": bit, "metrics": metrics})
    for row in results:
        row["entropy_deficit_sum_p"] = row["metrics"]["entropy_deficit_sum"]["exact_sign_flip"]["two_sided_p"]
    return {
        "variant": variant.name,
        "v_bytes": variant.v_bytes,
        "operations_per_seed": args.operations,
        "seeds": args.seeds,
        "random_bit_routes": args.random_bit_routes,
        "functional_roundtrips": roundtrips,
        "all_roundtrips_exact": all(value == args.operations for value in roundtrips),
        "results": results,
        "scope_note": "Public compressed-v mutation through exported decompress and NTT; no valid-ciphertext or security claim.",
    }


def _causal(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, path: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="mlkem_chosen_difference_frontier", parameters=parameters)
    for variant in results:
        for row in variant["results"]:
            metric = row["metrics"]["entropy_deficit_sum"]
            builder.add_triplet(
                edge_id=f"{variant['variant']}-vbit{row['bit']}",
                trigger=f"{variant['variant']}:compressed_v_xor_bit_{row['bit']}",
                mechanism="poly_decompress_then_ntt",
                outcome="field_output_differential_entropy_vs_repairing",
                confidence=1.0 - float(metric["exact_sign_flip"]["two_sided_p"]),
                evidence_kind="chosen_public_representation_screen",
                source=source,
                attrs={"effect_mean": metric["effect"]["mean"], "scope": "representation_inference"},
            )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if len(reader.triplets()) != stats["triplets"] or not reader.verify_provenance():
        raise RuntimeError("ML-KEM causal artifact failed reader round-trip")
    stats["reader_roundtrip"] = {"triplets": len(reader.triplets()), "graph_sha256": reader.graph_sha256, "file_sha256": reader.file_sha256}
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--variants", nargs="+", default=["mlkem512"])
    parser.add_argument("--bits", type=int, nargs="+", default=None)
    parser.add_argument("--operations", type=int, default=500)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--random-bit-routes", type=int, default=8)
    parser.add_argument("--seed-base", type=int, default=485001)
    args = parser.parse_args()
    known = {item.name: item for item in VARIANTS}
    if any(name not in known for name in args.variants):
        raise ValueError(f"unknown variants: {args.variants}")
    if args.operations < 32 or args.seeds < 2 or args.routes < 4 or args.random_bit_routes < 2:
        raise ValueError("operations >=32, seeds >=2, routes >=4, random-bit-routes >=2 required")
    args.bits = args.bits if args.bits is not None else list(range(known[args.variants[0]].v_bytes * 8))
    if any(bit < 0 or bit >= max(known[name].v_bytes for name in args.variants) * 8 for bit in args.bits):
        raise ValueError("bit outside selected compressed-v widths")
    results = [_run_variant(known[name], args) for name in args.variants]
    parameters = {
        "variants": args.variants,
        "bits": args.bits,
        "operations_per_seed": args.operations,
        "seeds": args.seeds,
        "routes": args.routes,
        "random_bit_routes": args.random_bit_routes,
        "seed_base": args.seed_base,
        "primary_metric": "entropy_deficit_sum over 16 quantized Z_q delta bins",
        "null": "independent row re-pairing of the exact mutated NTT output multiset",
        "scope": "open public representation inference, not a security game",
    }
    payload = {
        "schema": "mlkem-chosen-difference-frontier-v1",
        "parameters": parameters,
        "environment": {"python": sys.version, "numpy": np.__version__, "platform": platform.platform()},
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    args.output.write_bytes(encoded)
    causal = _causal(results, parameters, str(args.output), args.causal_output)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "causal": causal}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
