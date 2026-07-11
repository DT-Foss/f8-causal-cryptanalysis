#!/usr/bin/env python3
"""Deterministic ML-KEM input/output F8 controls via PQClean derand APIs."""

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

from arx_carry_leak.f8 import _chi_square


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    prefix: str


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", "PQCLEAN_MLKEM512_CLEAN"),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", "PQCLEAN_MLKEM768_CLEAN"),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", "PQCLEAN_MLKEM1024_CLEAN"),
)


def _native_lib(module_path: str) -> ctypes.CDLL:
    module = importlib.import_module(module_path)
    root = Path(module.__file__).parents[1] / "_kem"
    candidates = list(root.glob(f"{Path(module.__file__).stem}.cpython-313-*.so"))
    if len(candidates) != 1:
        raise RuntimeError(f"cannot locate a unique native backend for {module_path}")
    return ctypes.CDLL(str(candidates[0]))


def _f8_relation(source: np.ndarray, target: np.ndarray) -> dict[str, float | int]:
    n_bins = 8
    delta = source ^ target
    source_q, delta_q = source >> 5, delta >> 5
    tested = significant = 0
    max_chi2 = 0.0
    for i in range(32):
        for j in range(32):
            flat = source_q[:, i].astype(np.int64) * n_bins + delta_q[:, j]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(source))
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


def _run_variant(variant: Variant, operations: int, permutations: int) -> dict[str, Any]:
    module = importlib.import_module(variant.module)
    lib = _native_lib(variant.module)
    keypair = getattr(lib, f"{variant.prefix}_crypto_kem_keypair_derand")
    encapsulate = getattr(lib, f"{variant.prefix}_crypto_kem_enc_derand")
    keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
    encapsulate.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
    key_coins = hashlib.shake_256((variant.name + ":key").encode()).digest(64)
    pk = (ctypes.c_uint8 * module.PUBLIC_KEY_SIZE)()
    sk = (ctypes.c_uint8 * module.SECRET_KEY_SIZE)()
    if keypair(pk, sk, (ctypes.c_uint8 * 64).from_buffer_copy(key_coins)) != 0:
        raise RuntimeError("deterministic keypair failed")
    coin_rows, ciphertext_rows, secret_rows = [], [], []
    roundtrips = 0
    for index in range(operations):
        coins = hashlib.shake_256(f"{variant.name}:enc:{index}".encode()).digest(32)
        ciphertext = (ctypes.c_uint8 * module.CIPHERTEXT_SIZE)()
        secret = (ctypes.c_uint8 * module.PLAINTEXT_SIZE)()
        if encapsulate(ciphertext, secret, pk, (ctypes.c_uint8 * 32).from_buffer_copy(coins)) != 0:
            raise RuntimeError("deterministic encapsulation failed")
        ct_bytes, ss_bytes = bytes(ciphertext), bytes(secret)
        roundtrips += module.decrypt(bytes(sk), ct_bytes) == ss_bytes
        coin_rows.append(np.frombuffer(coins, dtype=np.uint8))
        ciphertext_rows.append(np.frombuffer(ct_bytes[:32], dtype=np.uint8))
        secret_rows.append(np.frombuffer(ss_bytes, dtype=np.uint8))
    coins = np.stack(coin_rows)
    ciphertexts = np.stack(ciphertext_rows)
    secrets = np.stack(secret_rows)
    rng = np.random.default_rng(0xD3A11D + len(variant.name))
    shuffled_ct = [_f8_relation(coins, ciphertexts[rng.permutation(operations)]) for _ in range(permutations)]
    shuffled_ss = [_f8_relation(coins, secrets[rng.permutation(operations)]) for _ in range(permutations)]
    return {
        "variant": variant.name,
        "operations": operations,
        "successful_decapsulations": roundtrips,
        "input_coins_to_ciphertext_prefix": _f8_relation(coins, ciphertexts),
        "input_coins_to_shared_secret": _f8_relation(coins, secrets),
        "shuffled_ciphertext_controls": shuffled_ct,
        "shuffled_shared_secret_controls": shuffled_ss,
        "scope_note": "The inputs are deterministic test coins; this is a relation measurement, not a security game.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=5000)
    parser.add_argument("--permutations", type=int, default=5)
    parser.add_argument("--variants", nargs="*", default=[variant.name for variant in VARIANTS])
    args = parser.parse_args()
    if args.operations < 1000 or args.permutations < 1:
        raise ValueError("operations >= 1000 and permutations >= 1 are required")
    available = {variant.name: variant for variant in VARIANTS}
    unknown = sorted(set(args.variants) - set(available))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    results = []
    for name in args.variants:
        print(f"running {name}", flush=True)
        results.append(_run_variant(available[name], args.operations, args.permutations))
    payload = {
        "schema_version": 1,
        "experiment": "mlkem_deterministic_io_f8",
        "parameters": {"operations": args.operations, "permutations": args.permutations, "variants": args.variants},
        "environment": {"python": sys.version, "platform": platform.platform()},
        "results": results,
        "security_scope": "No IND-CPA/CCA, key-recovery, or attack claim is within scope.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
