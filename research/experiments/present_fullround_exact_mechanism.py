#!/usr/bin/env python3
"""Exact mechanism theorem for PRESENT cross-round F8.

This is not another statistical reproduction of the established PRESENT-80
or new PRESENT-128 full-round hit.  It derives the complete population-level
64x64 single-bit MI support from the round equation, writes only the seven
nonzero edges to a causal graph, and compares that prediction with the already
retained PRESENT-128 discovery/localization artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.nano_ciphers import (
    _PRESENT_PERM,
    _PRESENT_PERM_MASK,
    _PRESENT_SBOX,
    _present_key_schedule_128,
)


_BASE_PATH = Path(__file__).with_name("present128_fullround_causal_f8.py")
_SPEC = importlib.util.spec_from_file_location("present128_fullround_causal_f8", _BASE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BASE)


def _mi_and_counts(first: list[int], second: list[int]) -> tuple[float, list[int]]:
    counts = [
        sum(x == x_value and y == y_value for x, y in zip(first, second, strict=True))
        for x_value, y_value in ((0, 0), (0, 1), (1, 0), (1, 1))
    ]
    row = [counts[0] + counts[1], counts[2] + counts[3]]
    column = [counts[0] + counts[2], counts[1] + counts[3]]
    size = len(first)
    value = 0.0
    for index, count in enumerate(counts):
        if count:
            x_value, y_value = divmod(index, 2)
            value += (count / size) * math.log((count * size) / (row[x_value] * column[y_value]))
    return value, counts


def derive_population_support() -> dict:
    """Derive every nonzero cell without sampling cipher executions."""
    inverse = [0] * 64
    for source, target in enumerate(_PRESENT_PERM):
        inverse[target] = source

    fixed_points = [bit for bit, target in enumerate(_PRESENT_PERM) if bit == target]
    same_nibble_targets = [
        target for target, preimage in enumerate(inverse) if target // 4 == preimage // 4
    ]
    balanced_sbox_output_bits = [
        sum((_PRESENT_SBOX[value] >> bit) & 1 for value in range(16)) == 8
        for bit in range(4)
    ]
    if fixed_points != [0, 21, 42, 63]:
        raise RuntimeError(f"unexpected pLayer fixed points: {fixed_points}")
    if same_nibble_targets != fixed_points:
        raise RuntimeError("PRESENT same-nibble targets are not exactly its pLayer fixed points")
    if not all(balanced_sbox_output_bits):
        raise RuntimeError("PRESENT S-box output coordinate is not balanced")

    cells = []
    for target in fixed_points:
        nibble_base = 4 * (target // 4)
        target_local = target % 4
        delta = [
            ((value >> target_local) & 1)
            ^ ((_PRESENT_SBOX[value] >> target_local) & 1)
            for value in range(16)
        ]
        for source_local in range(4):
            source_values = [(value >> source_local) & 1 for value in range(16)]
            population_mi, joint_counts = _mi_and_counts(source_values, delta)
            if population_mi > 1e-15:
                cells.append({
                    "source_bit": nibble_base + source_local,
                    "target_bit": target,
                    "source_local_bit": source_local,
                    "target_local_bit": target_local,
                    "population_mi_nats": population_mi,
                    "joint_counts_over_16_sbox_inputs": joint_counts,
                })

    if len(cells) != 7:
        raise RuntimeError(f"expected seven exact nonzero cells, derived {len(cells)}")
    return {
        "pLayer_fixed_points": fixed_points,
        "same_nibble_targets": same_nibble_targets,
        "balanced_sbox_output_bits": balanced_sbox_output_bits,
        "nonzero_cells": cells,
        "nonzero_cell_count": len(cells),
        "zero_cell_count": 64 * 64 - len(cells),
        "population_total_mi_nats": sum(cell["population_mi_nats"] for cell in cells),
    }


def _sp_layer(values: np.ndarray) -> np.ndarray:
    sbox = np.asarray(_PRESENT_SBOX, dtype=np.uint64)
    substituted = np.zeros_like(values)
    for nibble_index in range(16):
        nibble = ((values >> np.uint64(4 * nibble_index)) & np.uint64(0xF)).astype(np.uint8)
        substituted |= sbox[nibble] << np.uint64(4 * nibble_index)
    permuted = np.zeros_like(values)
    for source, target in _PRESENT_PERM_MASK:
        permuted |= ((substituted >> np.uint64(source)) & np.uint64(1)) << np.uint64(target)
    return permuted


def verify_round_identity(seed: int = 88328001) -> dict:
    """Implementation gate for E_(r+1) = P(S(E_r)) xor K_(r+1)."""
    _BASE._kat()
    rng = np.random.default_rng(seed)
    checked = 0
    for key_index in range(3):
        key = int.from_bytes(rng.bytes(16), "big")
        plaintexts = rng.integers(0, 2**64, size=64, dtype=np.uint64)
        for rounds in (1, 7, 31):
            current = _BASE._encrypt(plaintexts, key, rounds)
            following = _BASE._encrypt(plaintexts, key, rounds + 1)
            next_round_key = np.uint64(_present_key_schedule_128(key, rounds + 1)[rounds + 1])
            predicted = _sp_layer(current) ^ next_round_key
            if not np.array_equal(following, predicted):
                raise RuntimeError(f"round recurrence failed for key {key_index}, r={rounds}")
            checked += len(plaintexts)
    return {
        "formula": "E_(r+1)(p,k) = pLayer(SBoxLayer(E_r(p,k))) xor K_(r+1)",
        "rounds_checked": [1, 7, 31],
        "keys_checked": 3,
        "plaintexts_per_key_round": 64,
        "exact_equalities_checked": checked,
        "all_passed": True,
    }


def _cell_set(rows: list[dict]) -> set[tuple[int, int]]:
    return {(int(row["source_bit"]), int(row["target_bit"])) for row in rows}


def compare_empirical(
    support: dict,
    transfer_path: Path,
    localization_path: Path,
) -> dict:
    transfer = json.loads(transfer_path.read_text())
    localization = json.loads(localization_path.read_text())
    if not transfer.get("retained_fullround_transfer"):
        raise RuntimeError("PRESENT-128 transfer artifact is not retained")
    if localization.get("evidence_stage") != "MECHANISM_LOCALIZED":
        raise RuntimeError("PRESENT-128 localization artifact is not retained")

    exact_cells = _cell_set(support["nonzero_cells"])
    ranked = transfer["discovery_top_cells"]
    top_seven = _cell_set(ranked[:7])
    if top_seven != exact_cells:
        raise RuntimeError("empirical discovery top seven do not equal the exact support")

    empirical_by_cell: dict[tuple[int, int], list[dict]] = {cell: [] for cell in exact_cells}
    for run in localization["runs"]:
        for row in run["fixed_point_cells"]["cells"]:
            empirical_by_cell[(row["source_bit"], row["target_bit"])].append(row)
    population_by_cell = {
        (row["source_bit"], row["target_bit"]): row["population_mi_nats"]
        for row in support["nonzero_cells"]
    }
    cell_comparison = []
    for cell in sorted(exact_cells):
        samples = empirical_by_cell[cell]
        observed = float(np.mean([row["factual_mi"] for row in samples]))
        population = population_by_cell[cell]
        cell_comparison.append({
            "source_bit": cell[0],
            "target_bit": cell[1],
            "population_mi_nats": population,
            "observed_mean_mi_nats": observed,
            "absolute_error": abs(observed - population),
            "all_five_keys_above_all_bvn_routes": all(
                row["above_all_bvn_routes"] for row in samples
            ),
        })

    observed_total = float(np.mean([
        run["fixed_point_cells"]["factual_mi"] for run in localization["runs"]
    ]))
    population_total = support["population_total_mi_nats"]
    return {
        "transfer_json": str(transfer_path),
        "localization_json": str(localization_path),
        "discovery_top_seven_exactly_equal_population_support": True,
        "discovery_ranks_8_to_16_are_outside_population_support": all(
            (row["source_bit"], row["target_bit"]) not in exact_cells for row in ranked[7:16]
        ),
        "cell_comparison": cell_comparison,
        "all_seven_cells_survive_all_five_fresh_keys_and_bvn_banks": all(
            row["all_five_keys_above_all_bvn_routes"] for row in cell_comparison
        ),
        "population_total_mi_nats": population_total,
        "observed_five_key_mean_total_mi_nats": observed_total,
        "relative_total_error": abs(observed_total - population_total) / population_total,
        "matched_nonfixed_control_mean_mi_nats": float(np.mean([
            run["matched_nonfixed_cells"]["factual_mi"] for run in localization["runs"]
        ])),
        "fixed_to_matched_observed_ratio": localization["fixed_to_matched_factual_mi_ratio"],
    }


def write_exact_graph(path: Path, support: dict, identity: dict) -> dict:
    builder = CryptoCausalBuilder(
        experiment="present_cross_round_exact_f8_mechanism",
        parameters={
            "proof_kind": "exact_round_recurrence_plus_exhaustive_4bit_sbox_enumeration",
            "round_identity": identity["formula"],
            "population_model": "uniform plaintext implies uniform E_r state because each fixed-key prefix is bijective",
            "key_schedule_scope": "independent of PRESENT-80 versus PRESENT-128 key schedule",
            "pLayer_fixed_points": support["pLayer_fixed_points"],
            "complete_64x64_single_bit_support": True,
            "zero_population_cells": support["zero_cell_count"],
        },
    )
    for row in support["nonzero_cells"]:
        builder.add_triplet(
            edge_id=f"present-exact-{row['source_bit']}-{row['target_bit']}",
            trigger=f"present:state_r_bit_{row['source_bit']}",
            mechanism="player_fixedpoint_same_sbox_nibble_survival",
            outcome=f"present:delta_r_rplus1_bit_{row['target_bit']}",
            confidence=1.0,
            evidence_kind="exact_algebraic_enumeration",
            source="PRESENT_round_recurrence_and_4bit_sbox_truth_table",
            attrs=row,
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    reader_rows = reader.triplets(include_inferred=False)
    if not reader.verify_provenance() or _cell_set([row["attrs"] for row in reader_rows]) != _cell_set(support["nonzero_cells"]):
        raise RuntimeError("exact causal Reader support gate failed")
    return {**stats, "reader_triplets": reader_rows, "reader_provenance_verified": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transfer-result",
        type=Path,
        default=Path("research/results/v1/present128_fullround_causal_f8_v1.json"),
    )
    parser.add_argument(
        "--localization-result",
        type=Path,
        default=Path("research/results/v1/present128_fixedpoint_causal_mechanism_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    support = derive_population_support()
    identity = verify_round_identity()
    empirical = compare_empirical(support, args.transfer_result, args.localization_result)
    causal = write_exact_graph(args.causal_output, support, identity)
    payload = {
        "schema": "present-cross-round-exact-mechanism-v1",
        "evidence_stage": "EXACT_MECHANISM_DERIVED",
        "not_a_fullround_anchor_rerun": True,
        "theorem": {
            "round_identity": identity["formula"],
            "fixed_point_condition": "A single-bit dependency survives iff target t and pLayer^-1(t) share a nibble; for PRESENT this is exactly t in {0,21,42,63}.",
            "complete_support_statement": "Exactly seven of 4096 state-bit/delta-bit cells have nonzero population MI; all seven values are fixed by the public S-box truth table.",
            "round_and_key_schedule_invariance": "The support and MI values are identical for every r and for PRESENT-80/PRESENT-128; K_(r+1) only flips an outcome bit and cannot change MI.",
        },
        "identity_gate": identity,
        "population_support": support,
        "empirical_comparison": empirical,
        "causal": causal,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "nonzero_cells": support["nonzero_cell_count"],
        "zero_cells": support["zero_cell_count"],
        "population_total_mi_nats": support["population_total_mi_nats"],
        "observed_total_mi_nats": empirical["observed_five_key_mean_total_mi_nats"],
        "relative_error": empirical["relative_total_error"],
    }, indent=2))


if __name__ == "__main__":
    main()
