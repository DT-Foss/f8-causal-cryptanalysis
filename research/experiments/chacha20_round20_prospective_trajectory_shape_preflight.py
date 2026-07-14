#!/usr/bin/env python3
"""Freeze A268 full-training shape model and disjoint prospective key design."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.solver_trajectory_shape import _fit, _select_lambda  # noqa: E402

ATTEMPT_ID = "A268"
SCHEMA = "chacha20-round20-prospective-trajectory-shape-preflight-v1"
OUTPUT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A267_RUNNER = (
    ROOT / "research/experiments/chacha20_round20_fresh_trajectory_shape_reader.py"
)
A267_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_fresh_trajectory_shape_reader_v1.json"
)
DESIGN_SEED = b"F8-Causal-A268-prospective-trajectory-shape-design-v1"
OLD_PREFIXES = {
    0xD6,
    0x7E,
    0x4C,
    0x3B,
    0x8D,
    0xA3,
    0xB0,
    0x41,
    0x55,
    0x6A,
    0xC8,
    0x9F,
    0x24,
    0x38,
    0xCB,
    0x74,
    0x13,
    0xEE,
}
OLD_SUFFIXES = {0x885, 0x3E3, 0xC7C, 0x71A, 0x1D1, 0xCAF, 0x61E, 0xB60}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A268 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _minimum_hamming(values: list[int]) -> int:
    return min(
        (left ^ right).bit_count()
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def _candidate_stream() -> bytes:
    return hashlib.shake_256(DESIGN_SEED).digest(8192)


def _prospective_prefixes() -> list[int]:
    pool = []
    for value in _candidate_stream():
        if (
            value not in OLD_PREFIXES
            and value not in pool
            and 2 <= value.bit_count() <= 6
        ):
            pool.append(value)
        if len(pool) >= 32:
            break
    for values in itertools.combinations(pool, 5):
        selected = list(values)
        counts = [sum((value >> bit) & 1 for value in selected) for bit in range(8)]
        if all(count in {2, 3} for count in counts) and _minimum_hamming(selected) >= 3:
            return selected
    raise RuntimeError("A268 deterministic prospective prefix search failed")


def _prospective_suffixes() -> list[int]:
    stream = _candidate_stream()[1024:]
    candidates = []
    for index in range(0, len(stream) - 2, 3):
        value = int.from_bytes(stream[index : index + 2], "little") & 0xFFF
        if value not in OLD_SUFFIXES and 4 <= value.bit_count() <= 8:
            candidates.append(value)
        if len(candidates) >= 64:
            break
    for left_index, left in enumerate(candidates):
        left_complement = left ^ 0xFFF
        if left_complement in OLD_SUFFIXES or not 4 <= left_complement.bit_count() <= 8:
            continue
        for right in candidates[left_index + 1 :]:
            values = [left, left_complement, right, right ^ 0xFFF]
            if (
                len(set(values)) == 4
                and not set(values) & OLD_SUFFIXES
                and all(4 <= value.bit_count() <= 8 for value in values)
                and _minimum_hamming(values) >= 6
            ):
                return values
    raise RuntimeError("A268 deterministic prospective suffix search failed")


def prospective_design() -> list[dict[str, Any]]:
    prefixes = _prospective_prefixes()
    suffixes = _prospective_suffixes()
    rows = []
    for prefix_index, prefix8 in enumerate(prefixes):
        for suffix_index, suffix12 in enumerate(suffixes):
            low20 = (prefix8 << 12) | suffix12
            rows.append(
                {
                    "label": f"a268_prospective_p{prefix_index:02d}_fit_s{suffix_index:02d}",
                    "prefix_split": "prospective",
                    "prefix_index": prefix_index,
                    "prefix8": prefix8,
                    "prefix8_binary": f"{prefix8:08b}",
                    "suffix_split": "fresh",
                    "suffix_index": suffix_index,
                    "suffix12": suffix12,
                    "low20": low20,
                    "low20_hex": f"{low20:05x}",
                }
            )
    validate_design(rows)
    return rows


def validate_design(rows: list[dict[str, Any]]) -> None:
    if len(rows) != 20 or len({row["low20"] for row in rows}) != 20:
        raise RuntimeError("A268 prospective design size differs")
    prefixes = list(dict.fromkeys(int(row["prefix8"]) for row in rows))
    suffixes = list(dict.fromkeys(int(row["suffix12"]) for row in rows))
    if (
        len(prefixes) != 5
        or len(suffixes) != 4
        or set(prefixes) & OLD_PREFIXES
        or set(suffixes) & OLD_SUFFIXES
        or _minimum_hamming(prefixes) < 3
        or _minimum_hamming(suffixes) < 6
    ):
        raise RuntimeError("A268 prospective design separation differs")
    if any(sum((value >> bit) & 1 for value in prefixes) not in {2, 3} for bit in range(8)):
        raise RuntimeError("A268 prospective prefix balance differs")
    if any(sum((value >> bit) & 1 for value in suffixes) != 2 for bit in range(12)):
        raise RuntimeError("A268 prospective suffix balance differs")
    for prefix_index, prefix8 in enumerate(prefixes):
        group = [row for row in rows if row["prefix8"] == prefix8]
        if len(group) != 4 or [row["suffix_index"] for row in group] != list(range(4)):
            raise RuntimeError("A268 prospective group geometry differs")
        for row in group:
            suffix_index = int(row["suffix_index"])
            if (
                row["label"]
                != f"a268_prospective_p{prefix_index:02d}_fit_s{suffix_index:02d}"
                or row["prefix8_binary"] != f"{prefix8:08b}"
                or row["low20"] != (prefix8 << 12) | row["suffix12"]
                or row["low20_hex"] != f"{row['low20']:05x}"
            ):
                raise RuntimeError("A268 prospective row identity differs")


def build_preflight() -> dict[str, Any]:
    a267 = _import_path(A267_RUNNER, "a268_a267")
    protocol, a251, a251_protocol = a267._load_protocol()
    tables, corpus = a267._load_tables(protocol, a251, a251_protocol)
    lambdas = protocol["operator"]["ridge_lambda_grid"]
    selected_lambda, selection_ledger = _select_lambda(tables, lambdas)
    model = _fit(tables, selected_lambda)
    model_dict = model.as_dict()
    design = prospective_design()
    a267_result = json.loads(A267_RESULT.read_bytes())
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "full_training_shape_model_and_disjoint_prospective_key_design_frozen_after_A267_retention_before_any_A268_target_CNF_or_solver_measurement",
        "A267": {
            "result_sha256": _file_sha256(A267_RESULT),
            "evidence_stage": a267_result["evidence_stage"],
            "mean_log2_rank_bit_gain": a267_result["evaluation"][
                "mean_log2_rank_bit_gain"
            ],
            "exact_shared_xor_p": a267_result["evaluation"]["exact_shared_xor_p"],
        },
        "frozen_model": {
            "selection_method": "leave_one_of_five_training_prefix_groups_out_over_all_twenty_A267_keys",
            "selected_ridge_lambda": selected_lambda,
            "selection_ledger": selection_ledger,
            "selection_ledger_sha256": _canonical_sha256(selection_ledger),
            "training_corpus": corpus,
            "training_table_ledger_sha256": corpus["table_ledger_sha256"],
            "model": model_dict,
            "model_sha256": _canonical_sha256(model_dict),
        },
        "prospective_design": {
            "seed_ascii": DESIGN_SEED.decode(),
            "seed_sha256": _sha256(DESIGN_SEED),
            "rows": design,
            "rows_sha256": _canonical_sha256(design),
            "prefixes": list(dict.fromkeys(row["prefix8"] for row in design)),
            "suffixes": list(dict.fromkeys(row["suffix12"] for row in design)),
            "disjoint_from_all_144_A220_low20_keys": True,
            "disjoint_from_all_A220_prefix_and_suffix_levels": True,
        },
        "information_boundary": {
            "A267_result_known_and_gate_passed": True,
            "A267_full_training_model_frozen": True,
            "prospective_rows_fixed_without_solver_or_target_outcome": True,
            "any_A268_target_block_or_CNF_generated": False,
            "any_A268_solver_measurement_started": False,
            "any_A268_rank_or_XOR_control_known": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    payload = build_preflight()
    _atomic_json(OUTPUT, payload)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "sha256": _file_sha256(OUTPUT),
                "selected_ridge_lambda": payload["frozen_model"][
                    "selected_ridge_lambda"
                ],
                "model_sha256": payload["frozen_model"]["model_sha256"],
                "design_sha256": payload["prospective_design"]["rows_sha256"],
                "prefixes": payload["prospective_design"]["prefixes"],
                "suffixes": payload["prospective_design"]["suffixes"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
