#!/usr/bin/env python3
"""PQC output study with explicit key- and order-controls.

This is deliberately *not* a round-level F8 experiment: standard PQC APIs do
not expose round traces.  It measures two separately named output-level views:

* CASI on the 32-byte row stream; and
* F8-O (F8-output): adjacent-row dependence between a row and its XOR delta.

For each target the study compares a fixed-key operation sequence to an
otherwise identical fresh-key sequence, plus a row-permutation control.  A
positive value is a format/distribution observation, not a security claim.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import numpy as np

from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score


@dataclass(frozen=True)
class Target:
    name: str
    family: str
    kind: str
    module: str


TARGETS = (
    Target("mlkem512", "ML-KEM", "kem", "pqcrypto.kem.ml_kem_512"),
    Target("mlkem768", "ML-KEM", "kem", "pqcrypto.kem.ml_kem_768"),
    Target("mlkem1024", "ML-KEM", "kem", "pqcrypto.kem.ml_kem_1024"),
    Target("mldsa44", "ML-DSA", "sign", "pqcrypto.sign.ml_dsa_44"),
    Target("mldsa65", "ML-DSA", "sign", "pqcrypto.sign.ml_dsa_65"),
    Target("mldsa87", "ML-DSA", "sign", "pqcrypto.sign.ml_dsa_87"),
    Target("hqc128", "HQC", "kem", "pqcrypto.kem.hqc_128"),
    Target("hqc192", "HQC", "kem", "pqcrypto.kem.hqc_192"),
    Target("hqc256", "HQC", "kem", "pqcrypto.kem.hqc_256"),
    # pqcrypto retains the SPHINCS+ naming; these are the hash-based family
    # controls, not a claim that this API is a FIPS 205 conformance harness.
    Target("sphincs128f", "SPHINCS+ / SLH-DSA family", "sign", "pqcrypto.sign.sphincs_sha2_128f_simple"),
    Target("sphincs192f", "SPHINCS+ / SLH-DSA family", "sign", "pqcrypto.sign.sphincs_sha2_192f_simple"),
    Target("sphincs256f", "SPHINCS+ / SLH-DSA family", "sign", "pqcrypto.sign.sphincs_sha2_256f_simple"),
)


def _rows(items: list[bytes]) -> np.ndarray:
    """Split outputs into 32-byte rows, discarding only incomplete final rows."""
    raw = b"".join(items)
    usable = len(raw) - (len(raw) % 32)
    return np.frombuffer(raw[:usable], dtype=np.uint8).reshape(-1, 32).copy()


def _score_casi(rows: np.ndarray, baseline_seed: int) -> dict[str, float]:
    standard = compute_casi_score(rows, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(rows, baseline_seed=baseline_seed)
    return {
        "standard": float(standard["casi"]),
        "classic": float(standard["casi_classic"]),
        "deep": float(standard["casi_deep"]),
        "amplified": float(amplified["casi_amplified"]),
        "operational_max": float(max(standard["casi"], amplified["casi"])),
    }


def _f8_output(rows: np.ndarray, shift: int = 5) -> dict[str, float | int]:
    """F8-O: the published quantized statistic on adjacent public output rows."""
    n_bins = 2 ** (8 - shift)
    first = rows[:-1]
    second = rows[1:]
    difference = first ^ second
    source = first >> shift
    delta = difference >> shift
    significant = 0
    tested = 0
    max_chi2 = 0.0
    for source_position in range(first.shape[1]):
        for target_position in range(first.shape[1]):
            flat = source[:, source_position].astype(np.int64) * n_bins + delta[:, target_position]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            chi2, p_value = result
            tested += 1
            significant += p_value < 0.05
            max_chi2 = max(max_chi2, chi2)
    return {
        "significant_pairs": significant,
        "tested_pairs": tested,
        "significant_rate": significant / max(tested, 1),
        "max_chi2": max_chi2,
        "alpha": 0.05,
    }


def _operation_collector(target: Target, fixed_key: bool, count: int, seed: int) -> tuple[list[bytes], bool]:
    module = importlib.import_module(target.module)
    message_rng = np.random.default_rng(seed)
    outputs: list[bytes] = []
    verified = False
    if target.kind == "kem":
        keypair: tuple[bytes, bytes] | None = module.generate_keypair() if fixed_key else None
        for index in range(count):
            public_key, secret_key = keypair if keypair is not None else module.generate_keypair()
            ciphertext, shared_secret = module.encrypt(public_key)
            if index == 0:
                verified = module.decrypt(secret_key, ciphertext) == shared_secret
            outputs.append(ciphertext)
    else:
        keypair = module.generate_keypair() if fixed_key else None
        for index in range(count):
            public_key, secret_key = keypair if keypair is not None else module.generate_keypair()
            message = message_rng.bytes(64)
            signature = module.sign(secret_key, message)
            if index == 0:
                verified = bool(module.verify(public_key, message, signature))
            outputs.append(signature)
    if not verified:
        raise RuntimeError(f"{target.name} functional gate failed")
    return outputs, verified


def _condition(
    target: Target, condition: str, count: int, seed: int, permutations: int, max_rows: int | None
) -> dict[str, Any]:
    fixed_key = condition == "fixed_key"
    outputs, verified = _operation_collector(target, fixed_key, count, seed)
    rows = _rows(outputs)
    retained_rows = min(len(rows), max_rows) if max_rows is not None else len(rows)
    rows = rows[:retained_rows]
    result: dict[str, Any] = {
        "condition": condition,
        "seed": seed,
        "operations": count,
        "output_bytes": sum(map(len, outputs)),
        "rows": int(len(rows)),
        "row_budget": max_rows,
        "functional_gate": verified,
        "casi": _score_casi(rows, 0xA11CE + seed),
        "f8_output": _f8_output(rows),
    }
    if condition == "fixed_key":
        rng = np.random.default_rng(seed ^ 0x9E3779B9)
        controls = []
        for index in range(permutations):
            permuted = rows[rng.permutation(len(rows))]
            controls.append(
                {
                    "permutation": index,
                    "casi": _score_casi(permuted, 0xA11CE + seed),
                    "f8_output": _f8_output(permuted),
                }
            )
        result["row_permutation_controls"] = controls
        # These controls preserve different pieces of a variable-length
        # public serialization.  They are essential for signatures, where a
        # row-wise F8-O effect can otherwise be mistaken for an operation-to-
        # operation dependency.
        operation_matrices = [_rows([output]) for output in outputs]
        if all(len(matrix) for matrix in operation_matrices):
            whole_operation_rows = np.vstack(
                [operation_matrices[index] for index in rng.permutation(len(operation_matrices))]
            )[:retained_rows]
            within_operation_rows = np.vstack(
                [matrix[rng.permutation(len(matrix))] for matrix in operation_matrices]
            )[:retained_rows]
            result["operation_boundary_controls"] = {
                "whole_operation_permutation": {
                    "f8_output": _f8_output(whole_operation_rows),
                    "casi": _score_casi(whole_operation_rows, 0xA11CE + seed),
                },
                "within_operation_row_permutation": {
                    "f8_output": _f8_output(within_operation_rows),
                    "casi": _score_casi(within_operation_rows, 0xA11CE + seed),
                },
            }
    return result


def _summary(records: list[dict[str, Any]], path: Callable[[dict[str, Any]], float]) -> dict[str, float | list[float]]:
    values = [float(path(record)) for record in records]
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _target_run(
    target: Target, operations: int, seeds: int, permutations: int, max_rows: int | None
) -> dict[str, Any]:
    fixed = [
        _condition(target, "fixed_key", operations, 42 + 1009 * index, permutations, max_rows)
        for index in range(seeds)
    ]
    fresh = [
        _condition(target, "fresh_key", operations, 42 + 1009 * index, 0, max_rows)
        for index in range(seeds)
    ]
    permuted = [control for record in fixed for control in record["row_permutation_controls"]]
    return {
        "target": target.name,
        "family": target.family,
        "kind": target.kind,
        "backend_module": target.module,
        "fixed_key": fixed,
        "fresh_key": fresh,
        "summaries": {
            "fixed_key_casi": _summary(fixed, lambda row: row["casi"]["operational_max"]),
            "fresh_key_casi": _summary(fresh, lambda row: row["casi"]["operational_max"]),
            "fixed_key_f8_output": _summary(fixed, lambda row: row["f8_output"]["significant_rate"]),
            "fresh_key_f8_output": _summary(fresh, lambda row: row["f8_output"]["significant_rate"]),
            "permuted_f8_output": _summary(permuted, lambda row: row["f8_output"]["significant_rate"]),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=400)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--permutations", type=int, default=3)
    parser.add_argument("--max-rows", type=int, default=None, help="cap analysed 32-byte rows per condition")
    parser.add_argument("--targets", nargs="*", default=[target.name for target in TARGETS])
    args = parser.parse_args()
    if args.operations < 32 or args.seeds < 2 or args.permutations < 1:
        raise ValueError("operations >= 32, seeds >= 2, and permutations >= 1 are required")
    selected = [target for target in TARGETS if target.name in set(args.targets)]
    if len(selected) != len(set(args.targets)):
        unknown = sorted(set(args.targets) - {target.name for target in TARGETS})
        raise ValueError(f"unknown targets: {', '.join(unknown)}")

    results = []
    for target in selected:
        print(f"running {target.name}", flush=True)
        results.append(_target_run(target, args.operations, args.seeds, args.permutations, args.max_rows))
    payload = {
        "schema_version": 1,
        "experiment": "pqc_output_control_suite",
        "method": {
            "casi": "existing portable CASI implementation, reported as a heuristic score",
            "f8_output": "adjacent-output F8 quantized independence statistic; not an internal-round F8 test",
            "controls": ["fixed key vs fresh key", "row permutation of fixed-key output"],
        },
        "parameters": {
            "output": str(args.output),
            "operations": args.operations,
            "seeds": args.seeds,
            "permutations": args.permutations,
            "max_rows": args.max_rows,
            "targets": args.targets,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "pqcrypto_version": importlib.metadata.version("pqcrypto"),
        },
        "results": results,
        "scope_note": (
            "This study measures observable output format and adjacent-row dependence. "
            "It makes no IND-CPA, IND-CCA, key-recovery, or distinguisher claim."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
