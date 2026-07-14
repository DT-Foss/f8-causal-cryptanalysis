from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
PREFLIGHT = (
    ROOT
    / "research/experiments/chacha20_round20_replication_residual_two_pass_preflight.py"
)
RUNNER = (
    ROOT / "research/experiments/chacha20_round20_replication_residual_two_pass.py"
)
PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_replication_residual_two_pass_v1.json"
)
PROTOCOL_SHA256 = "1f7aa99d6b869287cb78bc9a3a321cf5d559c44137d554dc19b9435bb1f78b69"
A275_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1.json"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_a277_frozen_protocol_rebuild_is_exact() -> None:
    preflight = _load(PREFLIGHT, "a277_preflight_rebuild_test")
    # A276 was written through dotcausal's deterministic MD5 fallback. The
    # optional xxhash package is installed in the publication test environment,
    # so select the checksum mode encoded in the immutable artifact.
    sys.path.insert(0, str(preflight.DEFAULT_DOTCAUSAL_SRC))
    dotcausal_io = importlib.import_module("dotcausal.io")
    dotcausal_io.HAS_XXHASH = False
    rebuilt = preflight.build_protocol(
        root_review_acknowledged=True,
        dotcausal_src=preflight.DEFAULT_DOTCAUSAL_SRC,
    )
    assert _sha256(PROTOCOL.read_bytes()) == PROTOCOL_SHA256
    assert rebuilt == json.loads(PROTOCOL.read_bytes())
    assert rebuilt["scientific_design_sha256"] == (
        "12438bc1fc60fdb973c9cc5984a9d2e1174f726f07d00cba5df51a2eefee4553"
    )


def test_a277_quartet_order_is_the_exact_unresolved_half() -> None:
    preflight = _load(PREFLIGHT, "a277_quartet_order_test")
    a275 = json.loads(A275_RESULT.read_bytes())
    top128 = a275["analysis"]["top128_cell_order"]
    scores = a275["analysis"]["score_field"]
    order, groups = preflight._derive_quartet_order(
        top128=top128,
        scores=scores,
    )
    assert set(order) == set(range(256)) - set(top128)
    assert len(order) == len(set(order)) == 128
    assert order[:11] == [149, 83, 106, 236, 196, 223, 26, 166, 97, 93, 39]
    occupancies = [row["proved_top_occupancy"] for row in groups]
    assert occupancies == sorted(occupancies, reverse=True)
    for row in groups:
        expected = sorted(
            row["remaining_members"],
            key=lambda value: (-scores[value], value),
        )
        assert row["remaining_order"] == expected


def test_a277_each_blocking_clause_excludes_exactly_one_prefix() -> None:
    runner = _load(RUNNER, "a277_blocking_clause_test")
    blocked = list(range(0, 256, 2))
    mapping = list(range(1, 21))
    raw, manifest = runner.append_blocking_clauses(
        b"p cnf 20 0\n",
        blocked_prefixes=blocked,
        key_one_literals_bit0_through_bit19=mapping,
    )
    lines = raw.decode("ascii").splitlines()
    assert lines[0] == "p cnf 20 128"
    clauses = [[int(value) for value in line.split()[:-1]] for line in lines[1:]]
    assert len(clauses) == manifest["added_clause_count"] == 128
    assumption_variables = [mapping[bit] for bit in range(19, 11, -1)]
    for blocked_prefix, clause in zip(blocked, clauses, strict=True):
        rejected = []
        for candidate in range(256):
            bits = f"{candidate:08b}"
            assignment = dict(zip(assumption_variables, bits, strict=True))
            satisfied = any(
                (literal > 0 and assignment[abs(literal)] == "1")
                or (literal < 0 and assignment[abs(literal)] == "0")
                for literal in clause
            )
            if not satisfied:
                rejected.append(candidate)
        assert rejected == [blocked_prefix]


def test_a277_analyze_reopens_all_frozen_anchors_without_solving() -> None:
    runner = _load(RUNNER, "a277_analyze_test")
    summary = runner.analyze(PROTOCOL, PROTOCOL_SHA256)
    assert summary["attempt_id"] == "A277"
    assert summary["blocked_exact_prefixes"] == 128
    assert summary["unresolved_prefixes"] == 128
    assert summary["target_label_available"] is False
    assert summary["solver_execution_started"] is False
