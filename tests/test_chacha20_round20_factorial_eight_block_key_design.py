from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_factorial_eight_block_key_design.py"
A220_SOURCE = ROOT / "research/experiments/chacha20_round20_factorial_key_design.py"
A220_PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _design() -> Any:
    return _load(SOURCE, "a222_eight_block_key_design_test")


def _minimum_hamming(values: list[int]) -> int:
    return min((left ^ right).bit_count() for left, right in combinations(values, 2))


def test_exact_frozen_8_by_4_ledger_and_cluster_order() -> None:
    design = _design()
    rows = design.factorial_eight_block_key_ledger()
    assert len(rows) == 32
    assert design.PREFIX_CLUSTER_IDS == tuple(f"a222_p{index:02d}" for index in range(8))
    assert design.SUFFIX_REPLICATE_IDS == tuple(f"a222_s{index:02d}" for index in range(4))
    assert [row["label"] for row in rows] == [
        f"a222_p{prefix:02d}_s{suffix:02d}" for prefix in range(8) for suffix in range(4)
    ]
    assert Counter(row["prefix_cluster_id"] for row in rows) == {
        cluster_id: 4 for cluster_id in design.PREFIX_CLUSTER_IDS
    }
    assert Counter(row["suffix_replicate_id"] for row in rows) == {
        replicate_id: 8 for replicate_id in design.SUFFIX_REPLICATE_IDS
    }
    assert all(set(row) == design.ROW_FIELDS for row in rows)
    assert all(row["prefix8_bits"] == f"{row['prefix8']:08b}" for row in rows)
    assert all(row["prefix8_hex"] == f"{row['prefix8']:02x}" for row in rows)
    assert all(row["suffix12_bits"] == f"{row['suffix12']:012b}" for row in rows)
    assert all(row["suffix12_hex"] == f"{row['suffix12']:03x}" for row in rows)
    assert all(row["low20_bits"] == f"{row['low20']:020b}" for row in rows)
    assert all(row["low20_hex"] == f"{row['low20']:05x}" for row in rows)


def test_full_disjointness_from_prior_exclusion_and_complete_a220_ledger() -> None:
    design = _design()
    a220 = _load(A220_SOURCE, "a220_factorial_key_design_for_a222_test")
    protocol = json.loads(A220_PROTOCOL.read_bytes())
    prior = protocol["factorial_design"]["prior_key_exclusion"]
    a220_rows = a220.factorial_ledger()
    rows = design.factorial_eight_block_key_ledger()

    assert tuple(prior["sorted_low20"]) == design.PRIOR_A214_A218_A219_LOW20
    assert prior["sorted_low20_sha256"] == design.EXPECTED_PRIOR_EXCLUSION_SHA256
    assert a220.ledger_sha256() == design.A220_FACTORIAL_LEDGER_SHA256
    assert len(a220_rows) == 144
    assert {row["low20"] for row in a220_rows} == set(design.A220_LOW20_LEDGER)
    assert not set(design.PREFIX8_LEVELS) & {
        value for levels in a220.PREFIX_SPLITS.values() for value in levels
    }
    assert not set(design.SUFFIX12_LEVELS) & {
        value for levels in a220.SUFFIX_SPLITS.values() for value in levels
    }
    new_keys = {row["low20"] for row in rows}
    assert not new_keys & set(design.PRIOR_A214_A218_A219_LOW20)
    assert not new_keys & set(design.A220_LOW20_LEDGER)


def test_ledger_and_order_hashes_are_frozen_and_repeated_bytes_are_identical() -> None:
    design = _design()
    first = design.ledger_bytes()
    second = design.ledger_bytes()
    assert first == second
    assert len(first) == 10257
    assert hashlib.sha256(first).hexdigest() == design.EXPECTED_LEDGER_SHA256
    assert design.ledger_sha256() == design.EXPECTED_LEDGER_SHA256
    assert design.ledger_order_sha256() == design.EXPECTED_LEDGER_ORDER_SHA256
    assert json.loads(first) == design.factorial_eight_block_key_ledger()
    assert design.design_manifest() == design.design_manifest()


def test_exact_bit_balance_nonextreme_weights_and_hamming_diversity() -> None:
    design = _design()
    rows = design.factorial_eight_block_key_ledger()
    prefixes = list(design.PREFIX8_LEVELS)
    suffixes = list(design.SUFFIX12_LEVELS)
    low20 = [row["low20"] for row in rows]
    assert [sum(value >> bit & 1 for value in prefixes) for bit in range(8)] == [4] * 8
    assert [sum(value >> bit & 1 for value in suffixes) for bit in range(12)] == [2] * 12
    assert [sum(value >> bit & 1 for value in low20) for bit in range(20)] == [16] * 20
    assert {value.bit_count() for value in prefixes} == {3, 4, 5}
    assert {value.bit_count() for value in suffixes} == {4, 6, 8}
    assert min(value.bit_count() for value in low20) == 7
    assert max(value.bit_count() for value in low20) == 13
    assert _minimum_hamming(prefixes) == 3
    assert _minimum_hamming(suffixes) == 8
    assert _minimum_hamming(low20) == 3
    distances = [(left ^ right).bit_count() for left, right in combinations(low20, 2)]
    assert min(distances) == 3
    assert max(distances) == 16
    assert sum(distances) == 5120
    assert len(distances) == 496


@pytest.mark.parametrize(
    "mutation",
    [
        "label",
        "boolean_index",
        "prefix_value",
        "prefix_bits",
        "suffix_hex",
        "low20_value",
        "drop_field",
        "extra_field",
        "swap_rows",
        "duplicate_row",
    ],
)
def test_validator_rejects_every_identity_or_order_mutation(mutation: str) -> None:
    design = _design()
    rows = copy.deepcopy(design.factorial_eight_block_key_ledger())
    if mutation == "label":
        rows[0]["label"] = "a222_p00_s01"
    elif mutation == "boolean_index":
        rows[0]["prefix_index"] = False
    elif mutation == "prefix_value":
        rows[0]["prefix8"] ^= 1
    elif mutation == "prefix_bits":
        rows[0]["prefix8_bits"] = "00000000"
    elif mutation == "suffix_hex":
        rows[0]["suffix12_hex"] = "000"
    elif mutation == "low20_value":
        rows[0]["low20"] ^= 1
    elif mutation == "drop_field":
        rows[0].pop("low20_hex")
    elif mutation == "extra_field":
        rows[0]["outcome"] = None
    elif mutation == "swap_rows":
        rows[0], rows[1] = rows[1], rows[0]
    else:
        rows[1] = copy.deepcopy(rows[0])
    with pytest.raises(RuntimeError):
        design.validate_eight_block_key_ledger(rows)


def test_validator_rejects_additional_forbidden_key_and_malformed_forbidden_value() -> None:
    design = _design()
    rows = design.factorial_eight_block_key_ledger()
    with pytest.raises(RuntimeError, match="intersects"):
        design.validate_eight_block_key_ledger(rows, additional_forbidden_low20=[rows[0]["low20"]])
    with pytest.raises(RuntimeError, match="additional forbidden"):
        design.validate_eight_block_key_ledger(rows, additional_forbidden_low20=[True])


def test_manifest_binds_identity_hashes_and_pure_information_boundary() -> None:
    design = _design()
    manifest = design.design_manifest()
    assert manifest["schema"] == design.SCHEMA
    assert manifest["attempt_id"] == "A222"
    assert manifest["ledger_sha256"] == design.EXPECTED_LEDGER_SHA256
    assert manifest["ledger_order_sha256"] == design.EXPECTED_LEDGER_ORDER_SHA256
    assert manifest["prefix_cluster_ids_sha256"] == design.EXPECTED_PREFIX_CLUSTER_IDS_SHA256
    assert manifest["suffix_replicate_ids_sha256"] == design.EXPECTED_SUFFIX_REPLICATE_IDS_SHA256
    assert manifest["balance"]["low20_bit_one_counts"] == [16] * 20
    assert manifest["diversity"]["mean_low20_hamming_numerator"] == 5120
    assert manifest["diversity"]["mean_low20_hamming_denominator"] == 496
    assert not any(manifest["information_boundary"].values())


def test_source_has_no_rng_clock_network_solver_result_or_target_access() -> None:
    tree = ast.parse(SOURCE.read_text())
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported & {
        "datetime",
        "http",
        "pathlib",
        "random",
        "requests",
        "secrets",
        "socket",
        "subprocess",
        "time",
        "urllib",
    }
    text = SOURCE.read_text().casefold()
    assert ".research_sealed" not in text
    assert "research/results" not in text
    assert "target_commit" not in text
