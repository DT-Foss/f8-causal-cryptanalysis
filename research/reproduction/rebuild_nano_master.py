#!/usr/bin/env python3
"""Replay the archived Nano master builder against repository-local raw data."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARCHIVED_BUILDER = ROOT / "provenance/original_nano_scripts/build_master_results.py"
ARCHIVED_TABLE_BUILDER = ROOT / "provenance/original_nano_scripts/build_table_and_figure.py"
RAW_DIR = ROOT / "data/reference/nano_iot_raw"
EXPECTED = ROOT / "data/reference/nano_iot_master_results.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_archived_builder():
    spec = importlib.util.spec_from_file_location("archived_nano_master_builder", ARCHIVED_BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ARCHIVED_BUILDER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RAW_DIR = str(RAW_DIR)
    return module


def rebuild_tables(master_payload: dict, tables_dir: Path) -> dict:
    spec = importlib.util.spec_from_file_location(
        "archived_nano_table_builder", ARCHIVED_TABLE_BUILDER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ARCHIVED_TABLE_BUILDER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tables_dir.mkdir(parents=True, exist_ok=True)
    module.TABLES_DIR = str(tables_dir)
    module.load_master = lambda: master_payload
    module.build_paper_table()

    comparisons = {}
    for filename, expected in (
        ("paper_table_1.csv", ROOT / "data/reference/paper_table_1.csv"),
        ("full_coverage_matrix.csv", ROOT / "data/reference/full_coverage_matrix.csv"),
    ):
        actual = tables_dir / filename
        comparisons[filename] = {
            "actual_path": str(actual.relative_to(ROOT)),
            "actual_sha256": sha256(actual),
            "expected_path": str(expected.relative_to(ROOT)),
            "expected_sha256": sha256(expected),
            "byte_exact": actual.read_bytes() == expected.read_bytes(),
        }
    return comparisons


def first_difference(actual, expected, path="ciphers") -> str | None:
    if type(actual) is not type(expected):
        return f"{path}: type {type(actual).__name__} != {type(expected).__name__}"
    if isinstance(actual, dict):
        if actual.keys() != expected.keys():
            return f"{path}: keys {sorted(actual)} != {sorted(expected)}"
        for key in actual:
            difference = first_difference(actual[key], expected[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(actual, list):
        if len(actual) != len(expected):
            return f"{path}: length {len(actual)} != {len(expected)}"
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            difference = first_difference(left, right, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if actual != expected:
        return f"{path}: {actual!r} != {expected!r}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tables-dir", type=Path)
    args = parser.parse_args()

    builder = load_archived_builder()
    rebuilt = builder.build_master()
    expected_payload = json.loads(EXPECTED.read_text())
    expected_ciphers = expected_payload["ciphers"]
    difference = first_difference(rebuilt, expected_ciphers)
    output_path = args.output.resolve()
    tables_dir = (args.tables_dir or output_path.parent / "nano_tables").resolve()
    table_comparisons = rebuild_tables(expected_payload, tables_dir)

    raw_files = sorted(RAW_DIR.rglob("*.json"))
    payload = {
        "schema_version": 1,
        "experiment": "archived_nano_master_rebuild",
        "adapter": "only archived module RAW_DIR was replaced",
        "archived_builder": {
            "path": str(ARCHIVED_BUILDER.relative_to(ROOT)),
            "sha256": sha256(ARCHIVED_BUILDER),
        },
        "raw_data": {
            "root": str(RAW_DIR.relative_to(ROOT)),
            "files": len(raw_files),
            "sha256": {
                str(path.relative_to(ROOT)): sha256(path) for path in raw_files
            },
        },
        "expected_master": {
            "path": str(EXPECTED.relative_to(ROOT)),
            "sha256": sha256(EXPECTED),
        },
        "cipher_entries_rebuilt": len(rebuilt),
        "exact_cipher_payload_match": difference is None,
        "first_difference": difference,
        "tables": table_comparisons,
        "ciphers": rebuilt,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"Nano master entries: {len(rebuilt)}")
    print(f"Exact ciphers match: {difference is None}")
    print(
        "Exact table matches: "
        + ", ".join(
            f"{name}={comparison['byte_exact']}"
            for name, comparison in table_comparisons.items()
        )
    )
    if difference:
        print(f"First difference: {difference}")
    print(f"wrote {output_path}")
    tables_match = all(item["byte_exact"] for item in table_comparisons.values())
    return 0 if difference is None and tables_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
