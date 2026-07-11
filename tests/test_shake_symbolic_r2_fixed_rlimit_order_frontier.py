from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_fixed_rlimit_order_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_fixed_rlimit_order_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "95eefebe7b40a508fb1266782e9542cf3e27b04c2aa0d0ac7dcfcce126593f2a"
CAUSAL_SHA256 = "b23c1419b220f8a15afe09da4c5ec951a3d142e271e671edb2750748361028db"
CAUSAL_GRAPH_SHA256 = "f7e72040e09cef7b1d5765f8bf9e80317c518f5e379a1446c538f6951e30e414"
EXPECTED_FORMULAS = {
    "weighted_degree_descending": (
        8_900_978,
        "742fafd690f71aa93ec98a9b24f84fa51d4715103eecea03843d9bd46c977295",
    ),
    "weighted_degree_ascending": (
        8_901_450,
        "7b64ba9a3509fff7b28026e2c07af35da0ee9609fed9f163842b39ddf4f1ea66",
    ),
    "greedy_max_remaining_weight": (
        8_900_967,
        "81e97db7caa37668f070b1348be25868f6525269fa1bd5f7744610f1bdd67581",
    ),
    "greedy_min_remaining_weight": (
        8_901_423,
        "a6c2041dfe0cf6d1dcb48870c96798902fd21e36e40f781a5ee607f8819ad1d2",
    ),
}


def test_a158_gate_and_fixed_resource_plan_are_exact() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["anchor"]["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert analysis["fixed_resource_plan_sha256"] == (
        "41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48"
    )
    assert [row["name"] for row in analysis["fixed_resource_plan"]] == list(EXPECTED_FORMULAS)
    for row in analysis["fixed_resource_plan"]:
        expected_bytes, expected_sha = EXPECTED_FORMULAS[row["name"]]
        assert row["formula_bytes"] == expected_bytes
        assert row["formula_sha256"] == expected_sha
        assert row["rlimit"] == 500_000_000
        assert row["wallclock_solver_limit_used"] is False


def test_solver_observation_excludes_volatile_wallclock_and_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        [
            "unknown\n(:rlimit-count 500000001 :decisions 42 :time 1.25 :memory 9.0)\n",
            "unknown\n(:rlimit-count 500000001 :decisions 42 :time 9.75 :memory 99.0)\n",
        ]
    )

    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(stdout=next(outputs), stderr="", returncode=1)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    first = MODULE._run_z3_rlimit(Path("/fake/z3"), Path("formula.smt2"), [])
    second = MODULE._run_z3_rlimit(Path("/fake/z3"), Path("formula.smt2"), [])
    assert first == second
    assert first["canonical_observation_sha256"] == (second["canonical_observation_sha256"])
    assert first["stats"] == {"rlimit-count": 500_000_001, "decisions": 42}
    assert first["volatile_wallclock_and_memory_statistics_retained"] is False
    assert not any("stdout" in key or "stderr" in key for key in first)


def test_z3_code_one_is_accepted_only_for_proven_fixed_rlimit_exhaustion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = b"(check-sat)\n"
    row = {
        "name": "fixed",
        "execution_order": 0,
        "formula_bytes": len(raw),
        "formula_sha256": MODULE._sha256(raw),
        "solver_input_names": [],
    }
    result = {
        "status": "unknown",
        "solver_basis_assignment": None,
        "stats": {"rlimit-count": MODULE.Z3_RLIMIT + 1},
        "return_code": 1,
        "external_timeout": False,
        "termination": "fixed_rlimit_exhausted",
        "canonical_observation_sha256": "0" * 64,
    }
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(result))
    executions = MODULE._execute_fixed_frontier(
        formula_rows=[row],
        formulas={"fixed": raw},
        problem={},
        variant=None,
        z3=Path("/fake/z3"),
        work_dir=tmp_path / "accepted",
    )
    assert executions[0]["solver"] == result
    assert list((tmp_path / "accepted").iterdir()) == []

    rejected = {**result, "return_code": 2}
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(rejected))
    with pytest.raises(RuntimeError, match="fixed-rlimit execution failed"):
        MODULE._execute_fixed_frontier(
            formula_rows=[row],
            formulas={"fixed": raw},
            problem={},
            variant=None,
            z3=Path("/fake/z3"),
            work_dir=tmp_path / "rejected",
        )


def test_external_safety_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(["z3"], 300, output=b"", stderr=b"")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_timeout)
    with pytest.raises(RuntimeError, match="safety timeout"):
        MODULE._run_z3_rlimit(Path("/fake/z3"), Path("formula.smt2"), [])


def test_retained_a159_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gate"]["A158_artifact_sha256"] == MODULE.A158_SHA256
    assert payload["fixed_resource_plan_sha256"] == (
        "41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48"
    )
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []
    assert [row["name"] for row in payload["execution_summary"]] == list(EXPECTED_FORMULAS)
    assert [row["stats"]["rlimit-count"] for row in payload["execution_summary"]] == [
        501_080_957,
        501_080_463,
        501_080_877,
        501_080_531,
    ]
    assert [row["stats"]["decisions"] for row in payload["execution_summary"]] == [
        6_940,
        14_386,
        13_298,
        18_936,
    ]
    assert [row["stats"]["conflicts"] for row in payload["execution_summary"]] == [
        2_314,
        2_925,
        2_711,
        2_334,
    ]
    assert all(row["status"] == "unknown" for row in payload["execution_summary"])
    assert all(row["return_code"] == 1 for row in payload["execution_summary"])
    assert all(
        row["termination"] == "fixed_rlimit_exhausted" for row in payload["execution_summary"]
    )
    assert all(
        row["solver"]["volatile_wallclock_and_memory_statistics_retained"] is False
        for row in payload["execution"]
    )
    lowered = raw.decode().lower()
    assert '"wallclock_seconds"' not in lowered
    assert '"elapsed_seconds"' not in lowered
    assert '"stdout_sha256"' not in lowered
    assert '"stderr_sha256"' not in lowered
    assert payload["posthoc"]["instrumented_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_encoder_execution"] is True
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 3
    by_id = {row["edge_id"]: row for row in rows}
    assert by_id["shake128-a158-time-bounded-order-separation"]["provenance"] == []
    assert by_id["shake128-a159-fixed-resource-formula-plan"]["provenance"] == [
        "shake128-a158-time-bounded-order-separation"
    ]
    assert by_id["shake128-a159-fixed-resource-execution"]["provenance"] == [
        "shake128-a159-fixed-resource-formula-plan"
    ]
