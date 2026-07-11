from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / "research" / "experiments" / "shake256_symbolic_r1_scaling_reader.py"
_SPEC = importlib.util.spec_from_file_location("shake256_symbolic_r1_scaling_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SHAKE256_R1 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SHAKE256_R1
_SPEC.loader.exec_module(_SHAKE256_R1)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_window_parser_and_canonical_seed_plan() -> None:
    windows = _SHAKE256_R1._parse_windows("24,16,20,16")
    assert windows == [16, 20, 24]
    assert _SHAKE256_R1._seed_plan(windows) == [
        {"window_bits": 16, "seed": 89757055},
        {"window_bits": 20, "seed": 89758064},
        {"window_bits": 24, "seed": 89759073},
    ]
    assert _SHAKE256_R1._seed_plan([24]) == [{"window_bits": 24, "seed": 89759073}]
    with pytest.raises(ValueError):
        _SHAKE256_R1._parse_windows("41")


def test_small_shake256_trial_is_correct_unique_and_checks_all_1088_bits(
    tmp_path: Path,
) -> None:
    row = _SHAKE256_R1._shake256_trial(
        4,
        89757055,
        30,
        _z3(),
        tmp_path,
        False,
    )
    assert row["variant"] == "SHAKE256"
    assert row["matches_instrumented_assignment"]
    assert row["first_solver"]["status"] == "sat"
    assert row["second_solver"]["status"] == "unsat"
    assert row["unique_assignment_proved"]
    verification = row["independent_verification"]
    assert verification["complete_rate_match"]
    assert verification["rate_lanes_checked"] == 17
    assert verification["rate_bits_checked"] == 1088
    assert verification["candidate_rate_sha256"] == verification["target_rate_sha256"]
    assert row["encoding"]["symbolic_prefix_rounds"] == 1


def test_a137_is_hash_gated_and_supplies_only_the_r1_transfer_choice(
    tmp_path: Path,
) -> None:
    path = _ROOT / "research/results/v1/shake_symbolic_split_frontier_v1.json"
    payload = _SHAKE256_R1._load_a137(path)
    selections = payload["minimum_decision_split_by_window"]
    assert selections["12"]["symbolic_prefix_rounds"] == 1
    assert selections["16"]["symbolic_prefix_rounds"] == 1
    assert _SHAKE256_R1.A137_SHA256 == (
        "19cc21bb0b60943182ac8d0c927e9090ac881c24fba04a9f646ae4972fe84583"
    )

    changed = tmp_path / "changed-a137.json"
    changed.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="retained artifact hash differs"):
        _SHAKE256_R1._load_a137(changed)


def test_reader_provenance_has_exactly_three_neutral_transfer_triplets(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shake256-symbolic-r1-scaling.causal"
    _SHAKE256_R1._build_graph(path, [16, 20, 24], 120)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3
    assert len(reader.triplets()) == 3

    by_id = {row["edge_id"]: row for row in rows}
    transfer_id = "shake256-r1-transfer-hypothesis-instance"
    query_id = "shake256-r1-model-query-observations"
    check_id = "shake256-r1-independent-complete-rate-check"
    assert by_id[transfer_id]["provenance"] == []
    assert by_id[query_id]["provenance"] == [transfer_id]
    assert by_id[check_id]["provenance"] == [query_id]
    recipe = by_id[transfer_id]["attrs"]["reader_recipe"]
    assert recipe["formulation_module"] == "shake_symbolic_r1_scaling_reader.py"
    assert recipe["transfer_role"] == "hypothesis_not_prior_SHAKE256_evidence"
    query_recipe = by_id[query_id]["attrs"]["reader_recipe"]
    assert query_recipe["output_lanes"] == 17
    assert query_recipe["output_bits"] == 1088
