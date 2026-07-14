from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WRAPPER = ROOT / "research/experiments/chacha20_fresh_clause_identity.py"
FIXTURE = ROOT / "tests/fixtures/cadical_fresh_clause_identity_php5_4.cnf"


@pytest.fixture(scope="module")
def runtime():
    spec = importlib.util.spec_from_file_location("clause_identity_test", WRAPPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    build = module.compile_helper()
    return module, Path(build["binary_path"]), module._load_base_wrapper()


def _run(runtime, order, mode):
    module, helper, _ = runtime
    return module.run_fresh_clause_identity(
        helper=helper,
        cnf=FIXTURE,
        mode=mode,
        order=order,
        key_one_literals_bit0_through_bit19=list(range(1, 21)),
        conflict_horizons=[1, 2, 4, 8],
        watchdog_seconds=2.0,
        external_timeout_seconds=30.0,
    )


def _stable_identity(run):
    result = {}
    for stage in run["stages"]:
        result[(stage["prefix8"], stage["horizon"])] = {
            "status": stage["status"],
            "metrics": stage["metrics_cell_cumulative_delta"],
            "clauses": stage["learned_clauses_stage"],
            "accepted": stage["learned_clause_accepted_stage"],
            "rejected": stage["learned_clause_rejected_large_stage"],
        }
    return result


def test_clause_identity_helper_captures_exact_canonical_clauses(runtime) -> None:
    module, _, base = runtime
    run = _run(runtime, base.numeric_order(), "identity_numeric")
    assert run["learned_clause_identity_complete"] is True
    assert run["bounded_variable_addition_enabled"] is False
    assert run["summary"]["learned_clause_accepted_total"] > 0
    assert run["summary"]["learned_clause_rejected_large_total"] == 0
    assert all(
        abs(literal) <= 20
        for stage in run["stages"]
        for clause in stage["learned_clauses_stage"]
        for literal in clause
    )
    assert run["learned_clause_maximum_size"] == module.MAXIMUM_LEARNED_CLAUSE_SIZE


def test_clause_identity_is_candidate_order_invariant(runtime) -> None:
    _, _, base = runtime
    numeric = _run(runtime, base.numeric_order(), "identity_numeric_order")
    reverse = _run(runtime, list(reversed(base.numeric_order())), "identity_reverse_order")
    assert _stable_identity(numeric) == _stable_identity(reverse)


def test_clause_identity_parser_rejects_out_of_range_literal(runtime) -> None:
    module, helper, base = runtime
    order = base.numeric_order()
    command = [
        str(helper),
        "--cnf",
        str(FIXTURE),
        "--mode",
        "identity_tamper",
        *base._mapping_arguments(list(range(1, 21))),
        "--cell-order",
        ",".join(order),
        "--conflict-horizons",
        "1,2,4,8",
        "--watchdog-seconds",
        "2",
    ]
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=True,
        env=module.EXECUTION_ENVIRONMENT,
    )
    lines = completed.stdout.splitlines()
    changed = False
    for index, line in enumerate(lines):
        if not line.startswith(module.STAGE_PREFIX):
            continue
        row = json.loads(line.removeprefix(module.STAGE_PREFIX))
        if not row["learned_clauses_stage"]:
            continue
        row["learned_clauses_stage"][0][0] = 21
        lines[index] = module.STAGE_PREFIX + json.dumps(row, separators=(",", ":"))
        changed = True
        break
    assert changed
    with pytest.raises(RuntimeError, match="stage validation failed"):
        module.parse_clause_identity_output(
            stdout="\n".join(lines) + "\n",
            returncode=0,
            mode="identity_tamper",
            order=order,
            key_one_literals_bit0_through_bit19=list(range(1, 21)),
            conflict_horizons=[1, 2, 4, 8],
            watchdog_seconds=2.0,
        )
