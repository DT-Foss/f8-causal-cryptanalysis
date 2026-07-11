#!/usr/bin/env python3
"""Exact carry-channel spectrum behind the SHA-2 full-compression result."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BASE_PATH = Path(__file__).with_name("sha2_fullround_feedforward_causal.py")
_SPEC = importlib.util.spec_from_file_location("sha2_fullround_feedforward_causal", _BASE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BASE
_SPEC.loader.exec_module(_BASE)


def _ideal_mi(crossover: float) -> float:
    if crossover in (0.0, 1.0):
        return math.log(2.0)
    entropy = -crossover * math.log(crossover) - (1.0 - crossover) * math.log(1.0 - crossover)
    return math.log(2.0) - entropy


def _trailing_zeros(value: int, bits: int) -> int:
    if value == 0:
        return bits
    return (value & -value).bit_length() - 1


def _measure(variant, pairs: int, routes: int, seed: int) -> dict:
    _BASE._kat(variant)
    rng = np.random.default_rng(seed)
    blocks = rng.integers(0, 256, size=(pairs, variant.block_bytes), dtype=np.uint8)
    working, output = _BASE._compress(blocks, variant)
    initial = np.asarray(variant.iv, dtype=variant.dtype)[None, :]
    delta = output ^ initial
    route_bank = _BASE._route_bank(pairs, routes, seed ^ 0xCA22)
    rows = []
    exact_equalities = 0
    for lane, constant in enumerate(variant.iv):
        trailing = _trailing_zeros(constant, variant.word_bits)
        for bit in range(variant.word_bits):
            source = ((working[:, lane] >> variant.dtype(bit)) & variant.dtype(1)).astype(np.uint8)
            target = ((delta[:, lane] >> variant.dtype(bit)) & variant.dtype(1)).astype(np.uint8)
            if bit == 0:
                lower_constant = 0
                carry = np.zeros(pairs, dtype=np.uint8)
            else:
                modulus = 1 << bit
                lower_constant = constant & (modulus - 1)
                if lower_constant == 0:
                    carry = np.zeros(pairs, dtype=np.uint8)
                else:
                    lower_working = working[:, lane] & variant.dtype(modulus - 1)
                    carry = (lower_working >= variant.dtype(modulus - lower_constant)).astype(np.uint8)
            predicted = source ^ carry
            if not np.array_equal(target, predicted):
                raise RuntimeError(f"carry identity failed at lane={lane}, bit={bit}")
            exact_equalities += pairs

            crossover = lower_constant / (1 << bit) if bit else 0.0
            ideal_mi = _ideal_mi(crossover)
            factual = _BASE._mi_binary(source, target)
            null = np.asarray([
                _BASE._mi_binary(source, target[route]) for route in route_bank
            ])
            if lower_constant == 0:
                classification = "exact_no_carry_ln2"
            elif lower_constant == (1 << (bit - 1)):
                classification = "balanced_carry_population_zero"
            else:
                classification = "biased_carry_channel"
            rows.append({
                "lane": lane,
                "bit": bit,
                "iv_word_hex": f"{constant:0{variant.word_bits // 4}x}",
                "iv_trailing_zero_count": trailing,
                "classification": classification,
                "carry_crossover_probability_under_uniform_working_word": crossover,
                "ideal_uniform_working_mi_nats": ideal_mi,
                "observed_mi_nats": factual,
                "absolute_ideal_error": abs(factual - ideal_mi),
                "bvn_mean": float(null.mean()),
                "bvn_max": float(null.max()),
                "z": float((factual - null.mean()) / (null.std(ddof=1) + 1e-30)),
                "above_all_bvn_routes": bool(factual > null.max()),
            })

    observed = np.asarray([row["observed_mi_nats"] for row in rows])
    ideal = np.asarray([row["ideal_uniform_working_mi_nats"] for row in rows])
    exact_rows = [row for row in rows if row["classification"] == "exact_no_carry_ln2"]
    balanced_rows = [
        row for row in rows if row["classification"] == "balanced_carry_population_zero"
    ]
    if len(balanced_rows) != 8:
        raise RuntimeError("expected one first-carry balanced point per SHA-2 lane")
    return {
        "rows": rows,
        "exact_conditional_carry_equalities": exact_equalities,
        "exact_no_carry_cells": len(exact_rows),
        "balanced_carry_population_zero_cells": len(balanced_rows),
        "biased_carry_channel_cells": len(rows) - len(exact_rows) - len(balanced_rows),
        "all_exact_no_carry_cells_above_all_bvn_routes": all(
            row["above_all_bvn_routes"] for row in exact_rows
        ),
        "exact_no_carry_cells_all_within_0_002_of_ln2": all(
            abs(row["observed_mi_nats"] - math.log(2.0)) < 0.002 for row in exact_rows
        ),
        "ideal_observed_pearson_r": float(np.corrcoef(ideal, observed)[0, 1]),
        "ideal_observed_rmse": float(np.sqrt(np.mean((ideal - observed) ** 2))),
        "max_absolute_ideal_error": float(np.max(np.abs(ideal - observed))),
    }


def _write_graph(path: Path, variant, measurement: dict, pairs: int, routes: int) -> dict:
    exact_rows = [
        row for row in measurement["rows"]
        if row["classification"] == "exact_no_carry_ln2"
    ]
    builder = CryptoCausalBuilder(
        experiment=f"{variant.name}_fixed_iv_feedforward_carry_spectrum",
        parameters={
            "steps": variant.steps,
            "word_bits": variant.word_bits,
            "pairs": pairs,
            "bvn_routes": routes,
            "exact_equation": "D_j = W_j xor carry_j(W mod 2^j, H_in mod 2^j)",
            "reader_policy": "only structurally exact no-carry cells are serialized",
        },
    )
    for row in exact_rows:
        builder.add_triplet(
            edge_id=f"{variant.name}-fixed-iv-exact-l{row['lane']}-b{row['bit']}",
            trigger=f"{variant.name}:working_after_step_{variant.steps}:lane_{row['lane']}:bit_{row['bit']}",
            mechanism="fixed_iv_no_incoming_carry_exact_identity",
            outcome=f"{variant.name}:hin_xor_hout:lane_{row['lane']}:bit_{row['bit']}",
            confidence=1.0,
            evidence_kind="exact_modular_addition_carry_equation_plus_bvn_measurement",
            source="SHA2_feedforward_fixed_IV_carry_spectrum",
            attrs=row,
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    if not reader.verify_provenance() or len(rows) != len(exact_rows):
        raise RuntimeError("carry-spectrum causal Reader gate failed")
    return {**stats, "reader_provenance_verified": True, "reader_triplets": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=sorted(_BASE._VARIANTS), required=True)
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88528001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    variant = _BASE._VARIANTS[args.variant]
    measurement = _measure(variant, args.pairs, args.routes, args.seed)
    causal = _write_graph(args.causal_output, variant, measurement, args.pairs, args.routes)
    payload = {
        "schema": "sha2-feedforward-carry-spectrum-v1",
        "variant": variant.name,
        "evidence_stage": "FULLWORD_CARRY_SPECTRUM_DERIVED",
        "prediction": (
            "For each IV lane, bits 0..v2(IV) are exact ln2 edges, bit v2(IV)+1 "
            "is the uniform-working balanced-carry zero, and higher bits follow the fixed-addend BSC formula."
        ),
        "parameters": {"pairs": args.pairs, "bvn_routes": args.routes, "seed": args.seed},
        "measurement": measurement,
        "causal": causal,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "variant": variant.name,
        "exact_equalities": measurement["exact_conditional_carry_equalities"],
        "exact_ln2_cells": measurement["exact_no_carry_cells"],
        "balanced_zero_cells": measurement["balanced_carry_population_zero_cells"],
        "biased_carry_cells": measurement["biased_carry_channel_cells"],
        "pearson_r": measurement["ideal_observed_pearson_r"],
        "rmse": measurement["ideal_observed_rmse"],
    }, indent=2))


if __name__ == "__main__":
    main()
