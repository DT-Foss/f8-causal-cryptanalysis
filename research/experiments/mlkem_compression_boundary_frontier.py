#!/usr/bin/env python3
"""Screen chosen ML-KEM field-coordinate perturbations at the NTT/Compress boundary."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import itertools
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader

Q = 3329


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    prefix: str
    v_bytes: int
    bits: int


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", "PQCLEAN_MLKEM512_CLEAN", 128, 4),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", "PQCLEAN_MLKEM768_CLEAN", 128, 4),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", "PQCLEAN_MLKEM1024_CLEAN", 160, 5),
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


def _decode(data: bytes, width: int, count: int = 256) -> np.ndarray:
    accumulator = bits = 0
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
    return np.asarray(values, dtype=np.int32)


def _compress(values: np.ndarray, width: int) -> np.ndarray:
    return ((((values.astype(np.int64) % Q) << width) + Q // 2) // Q & ((1 << width) - 1)).astype(np.int32)


def _ntt(lib: ctypes.CDLL, prefix: str, values: np.ndarray) -> np.ndarray:
    function = getattr(lib, f"{prefix}_ntt")
    function.argtypes = [ctypes.POINTER(ctypes.c_int16)]
    coefficients = (ctypes.c_int16 * 256)(*map(int, values.astype(np.int16)))
    function(coefficients)
    return np.frombuffer(bytes(coefficients), dtype=np.int16).astype(np.int32) % Q


def _entropy(values: np.ndarray, alphabet: int) -> float:
    counts = np.bincount(values.astype(np.int64), minlength=alphabet)
    probabilities = counts[counts > 0] / len(values)
    return -float(np.sum(probabilities * np.log2(probabilities)))


def _metrics(first: np.ndarray, second: np.ndarray, width: int) -> dict[str, float]:
    delta = (second.astype(np.int64) - first.astype(np.int64)) % (1 << width)
    changed = delta != 0
    entropy_deficit = float(np.sum([1.0 - _entropy(changed[:, i].astype(np.int64), 2) for i in range(changed.shape[1])]))
    return {
        "change_entropy_deficit_sum": entropy_deficit,
        "changed_fraction": float(np.mean(changed)),
        "mean_symbol_delta": float(np.mean(delta)),
    }


def _analyse(first: np.ndarray, second: np.ndarray, width: int, routes: int, seed: int) -> dict[str, Any]:
    actual = _metrics(first, second, width)
    rng = np.random.default_rng(seed)
    controls = [_metrics(first, second[rng.permutation(len(second))], width) for _ in range(routes)]
    effects = {}
    for metric in actual:
        values = np.asarray([row[metric] for row in controls], dtype=float)
        sd = float(values.std(ddof=1))
        difference = float(actual[metric] - values.mean())
        effects[metric] = {"difference": difference, "control_mean": float(values.mean()), "control_sd_ddof1": sd, "route_z": 0.0 if sd <= 1e-12 else difference / sd}
    return {"actual": actual, "controls": controls, "effects": effects}


def _sign_flip(values: list[float]) -> dict[str, float | int]:
    differences = np.asarray(values, dtype=float)
    observed = float(differences.mean())
    null = np.asarray([np.mean(differences * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(differences))])
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {"two_sided_p": min(1.0, 2 * min(upper, lower)), "seed_pairs": len(values)}


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {"values": values, "mean": float(array.mean()), "sample_sd_ddof1": float(array.std(ddof=1)) if len(array) > 1 else 0.0, "minimum": float(array.min()), "maximum": float(array.max())}


def _collect(variant: Variant, operations: int) -> tuple[np.ndarray, np.ndarray, int]:
    module = importlib.import_module(variant.module)
    lib = _native_lib(variant.module)
    packed_rows = []
    base_compressed = []
    valid = 0
    for _ in range(operations):
        public_key, secret_key = module.generate_keypair()
        ciphertext, shared_secret = module.encrypt(public_key)
        valid += int(module.decrypt(secret_key, ciphertext) == shared_secret)
        coeff = _decode(ciphertext[-variant.v_bytes :], variant.bits)
        transformed = _ntt(lib, variant.prefix, coeff)
        packed_rows.append(coeff)
        base_compressed.append(_compress(transformed, variant.bits))
    return np.stack(packed_rows), np.stack(base_compressed), valid


def _run_variant(variant: Variant, positions: list[int], args: argparse.Namespace) -> dict[str, Any]:
    records = {position: [] for position in positions}
    valid_runs = []
    for index in range(args.seeds):
        seed = args.seed_base + 1009 * index
        np.random.seed(seed)
        print(f"mlkem compression boundary {variant.name} seed={seed}", flush=True)
        coeff, base, valid = _collect(variant, args.operations)
        valid_runs.append(valid)
        lib = _native_lib(variant.module)
        for position in positions:
            mutated = coeff.copy()
            mutated[:, position] = (mutated[:, position] + 1) % Q
            compressed = np.stack([_compress(_ntt(lib, variant.prefix, row), variant.bits) for row in mutated])
            analysis = _analyse(base, compressed, variant.bits, args.routes, seed ^ position)
            random_rng = np.random.default_rng(seed ^ 0xC0A5)
            random_positions = random_rng.integers(0, 256, size=args.operations)
            random_mutated = coeff.copy()
            random_mutated[np.arange(args.operations), random_positions] = (random_mutated[np.arange(args.operations), random_positions] + 1) % Q
            random_compressed = np.stack([_compress(_ntt(lib, variant.prefix, row), variant.bits) for row in random_mutated])
            random_metric = _metrics(base, random_compressed, variant.bits)
            analysis["random_position_effect"] = {metric: float(analysis["actual"][metric] - random_metric[metric]) for metric in analysis["actual"]}
            records[position].append(analysis)
    results = []
    for position, rows in records.items():
        metrics = {}
        for metric in ("change_entropy_deficit_sum", "changed_fraction", "mean_symbol_delta"):
            effects = [row["effects"][metric]["difference"] for row in rows]
            random_effects = [row["random_position_effect"][metric] for row in rows]
            metrics[metric] = {"effect": _summary(effects), "exact_sign_flip": _sign_flip(effects), "random_position_effect": {"effect": _summary(random_effects), "exact_sign_flip": _sign_flip(random_effects)}}
        results.append({"position": position, "metrics": metrics})
    return {"variant": variant.name, "positions": positions, "operations_per_seed": args.operations, "seeds": args.seeds, "functional_roundtrips": valid_runs, "all_roundtrips_exact": all(value == args.operations for value in valid_runs), "results": results, "scope_note": "Public decoded-v representation followed by NTT and Compress_d; not an internal-state or security claim."}


def _causal(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, path: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="mlkem_compression_boundary_frontier", parameters=parameters)
    for variant in results:
        for row in variant["results"]:
            metric = row["metrics"]["change_entropy_deficit_sum"]
            builder.add_triplet(edge_id=f"{variant['variant']}-pos{row['position']}", trigger=f"{variant['variant']}:field_coordinate_plus_one_{row['position']}", mechanism="ntt_then_compress_d", outcome="compressed_symbol_differential_vs_repairing", confidence=1.0 - float(metric["exact_sign_flip"]["two_sided_p"]), evidence_kind="public_formula_boundary_screen", source=source, attrs={"effect_mean": metric["effect"]["mean"], "random_position_effect_mean": metric["random_position_effect"]["effect"]["mean"]})
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if len(reader.triplets()) != stats["triplets"] or not reader.verify_provenance():
        raise RuntimeError("compression-boundary causal reader round-trip failed")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--variants", nargs="+", default=["mlkem512"])
    parser.add_argument("--positions", type=int, nargs="+", default=[0, 1, 2, 3, 7, 15, 31, 63, 127, 191, 255])
    parser.add_argument("--operations", type=int, default=200)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--seed-base", type=int, default=585001)
    args = parser.parse_args()
    known = {variant.name: variant for variant in VARIANTS}
    if any(name not in known for name in args.variants) or any(position < 0 or position >= 256 for position in args.positions):
        raise ValueError("unknown variant or position outside [0,255]")
    results = [_run_variant(known[name], args.positions, args) for name in args.variants]
    parameters = {"variants": args.variants, "positions": args.positions, "operations_per_seed": args.operations, "seeds": args.seeds, "routes": args.routes, "seed_base": args.seed_base, "null": "row repair plus one-coordinate random-position mutation", "scope": "public formula boundary inference"}
    payload = {"schema": "mlkem-compression-boundary-frontier-v1", "parameters": parameters, "environment": {"python": sys.version, "numpy": np.__version__, "platform": platform.platform()}, "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.write_bytes(encoded)
    causal = _causal(results, parameters, str(args.output), args.causal_output)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "causal": causal}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
