#!/usr/bin/env python3
"""Profile concrete ML-KEM ciphertext serialization mutations with CASI and F8-O."""

from __future__ import annotations

import argparse
import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    u_bytes: int
    v_bytes: int


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", 640, 128),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", 960, 128),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", 1408, 160),
)


def _rows(ciphertexts: list[bytes]) -> np.ndarray:
    raw = b"".join(ciphertexts)
    return np.frombuffer(raw, dtype=np.uint8).reshape(-1, 32).copy()


def _f8o(rows: np.ndarray) -> float:
    bins = 8
    first, second = rows[:-1], rows[1:]
    source, delta = first >> 5, (first ^ second) >> 5
    hits = tested = 0
    for i in range(32):
        for j in range(32):
            flat = source[:, i].astype(np.int64) * bins + delta[:, j]
            table = np.bincount(flat, minlength=bins * bins).reshape(bins, bins)
            result = _chi_square(table.astype(float), len(first))
            if result is not None:
                tested += 1
                hits += result[1] < 0.05
    return hits / max(tested, 1)


def _score(ciphertexts: list[bytes], baseline_seed: int) -> dict[str, float | int]:
    rows = _rows(ciphertexts)
    standard = compute_casi_score(rows, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(rows, baseline_seed=baseline_seed)
    return {
        "rows": len(rows),
        "casi_standard": float(standard["casi"]),
        "casi_amplified": float(amplified["casi"]),
        "casi_operational_max": float(max(standard["casi"], amplified["casi"])),
        "f8_output_rate": _f8o(rows),
    }


def _mutate(ciphertext: bytes, variant: Variant, name: str) -> bytes:
    value = bytearray(ciphertext)
    if name == "valid":
        return bytes(value)
    if name == "u_lsb_flip":
        value[0] ^= 0x01
    elif name == "u_msb_flip":
        value[0] ^= 0x80
    elif name == "v_lsb_flip":
        value[variant.u_bytes] ^= 0x01
    elif name == "u_first_packing_group_swap":
        value[:5], value[5:10] = value[5:10], value[:5]
    elif name == "v_zeroed":
        value[variant.u_bytes :] = b"\0" * variant.v_bytes
    else:
        raise ValueError(name)
    return bytes(value)


def _run_variant(variant: Variant, operations: int) -> dict[str, Any]:
    module = importlib.import_module(variant.module)
    public_key, secret_key = module.generate_keypair()
    cases = {name: [] for name in ("valid", "u_lsb_flip", "u_msb_flip", "v_lsb_flip", "u_first_packing_group_swap", "v_zeroed")}
    unchanged = {name: 0 for name in cases}
    for _ in range(operations):
        ciphertext, secret = module.encrypt(public_key)
        for name in cases:
            mutated = _mutate(ciphertext, variant, name)
            cases[name].append(mutated)
            unchanged[name] += module.decrypt(secret_key, mutated) == secret
    return {
        "variant": variant.name,
        "operations": operations,
        "cases": {
            name: {
                "unchanged_shared_secrets": unchanged[name],
                "changed_shared_secret_rate": 1.0 - unchanged[name] / operations,
                **_score(ciphertexts, 0xF00D + len(name)),
            }
            for name, ciphertexts in cases.items()
        },
        "scope_note": "Mutation handling and format measurement only; no oracle, attack, or security claim.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=500)
    parser.add_argument("--variants", nargs="*", default=[variant.name for variant in VARIANTS])
    args = parser.parse_args()
    if args.operations < 64:
        raise ValueError("operations >= 64 are required")
    available = {variant.name: variant for variant in VARIANTS}
    unknown = sorted(set(args.variants) - set(available))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    payload = {
        "schema_version": 1,
        "experiment": "mlkem_mutation_profile_suite",
        "parameters": {"output": str(args.output), "operations": args.operations, "variants": args.variants},
        "results": [],
    }
    for name in args.variants:
        print(f"running {name}", flush=True)
        payload["results"].append(_run_variant(available[name], args.operations))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
