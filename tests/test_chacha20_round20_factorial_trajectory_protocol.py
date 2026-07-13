from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
PROTOCOL_PATH = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
PROTOCOL_SHA256 = "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"


def _canonical_sha256(value) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _protocol() -> dict:
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == PROTOCOL_SHA256
    return json.loads(PROTOCOL_PATH.read_bytes())


def test_protocol_anchors_public_only_core_and_preflight_are_exact() -> None:
    protocol = _protocol()
    assert protocol["schema"] == "chacha20-round20-factorial-trajectory-transfer-protocol-v1"
    assert protocol["attempt_id"] == "A220"
    for key, relative in protocol["anchors"].items():
        if not key.endswith("_path"):
            continue
        hash_key = f"{key.removesuffix('_path')}_sha256"
        if hash_key in protocol["anchors"]:
            assert (
                hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                == protocol["anchors"][hash_key]
            )

    core = _load(ROOT / protocol["anchors"]["public_core_adapter_path"], "a220_protocol_core")
    assert (
        core.validate_public_template(protocol["public_only_R20_material"])
        == protocol["public_only_R20_material"]
    )
    assert (
        _canonical_sha256(protocol["public_only_R20_material"])
        == protocol["public_only_R20_material_sha256"]
    )
    source = (ROOT / protocol["anchors"]["public_core_adapter_path"]).read_text()
    assert "result.json" not in source
    assert ".causal" not in source
    assert "analyze(" not in source

    preflight = json.loads((ROOT / protocol["anchors"]["A220P_result_path"]).read_bytes())
    assert preflight["measurement_sha256"] == protocol["anchors"]["A220P_measurement_sha256"]
    assert preflight["completion_gates"]["all_12_runs_complete"] is True
    assert (
        preflight["information_boundary"]["target_secret_or_salt_accessed_during_execution"]
        is False
    )


def test_factorial_fit_select_and_holdout_partition_is_complete_and_disjoint() -> None:
    protocol = _protocol()
    design = _load(ROOT / protocol["anchors"]["factorial_design_path"], "a220_protocol_design")
    rows = design.factorial_ledger()
    design.validate_factorial_ledger(
        rows,
        forbidden_low20=protocol["factorial_design"]["prior_key_exclusion"]["sorted_low20"],
    )
    fit_select = [
        row
        for row in rows
        if row["prefix_split"] in {"fit", "select"} and row["suffix_split"] == "fit"
    ]
    holdout = [row for row in rows if row not in fit_select]
    assert len(fit_select) == 52
    assert len(holdout) == 92
    assert _canonical_sha256(fit_select) == protocol["factorial_design"]["fit_select_rows_sha256"]
    assert (
        _canonical_sha256([row["label"] for row in fit_select])
        == protocol["factorial_design"]["fit_select_label_order_sha256"]
    )
    assert not ({row["low20"] for row in fit_select} & {row["low20"] for row in holdout})
    panels = {f"{row['prefix_split']}_by_{row['suffix_split']}": 0 for row in holdout}
    for row in holdout:
        panels[f"{row['prefix_split']}_by_{row['suffix_split']}"] += 1
    assert panels == protocol["factorial_design"]["holdout_panels"]


def test_execution_feature_learning_and_exact_holdout_design_are_closed() -> None:
    protocol = _protocol()
    collection = protocol["fit_select_collection"]
    assert len(collection["orders"]) == 6
    assert collection["schedules"] == {
        "staged_retained_resolve": [8, 16, 32, 64],
        "one_shot": [64],
    }
    assert collection["runs_per_key"] == 12
    assert collection["total_fresh_solver_processes"] == 52 * 12
    assert collection["maximum_concurrent_solver_processes"] == 2
    assert collection["failure_and_resume"][
        "fixed_outcome_independent_reexecution_of_an_incomplete_run_permitted"
    ]
    assert collection["failure_and_resume"]["completed_run_reexecution_permitted"] is False

    feature_counts = {
        row["id"]: row["feature_count"] for row in protocol["feature_protocol"]["families"]
    }
    assert feature_counts == {
        "P1_dense_local": 12,
        "P2_dense_cross": 24,
        "P3_dense_cube": 36,
        "P4_dense_path": 48,
        "P5_dense_all": 60,
    }
    learning = protocol["learning_protocol"]
    assert learning["frozen_bundle_order"] == [
        "numeric__staged_retained_resolve",
        "numeric__one_shot",
        "reflected_gray8__staged_retained_resolve",
        "reflected_gray8__one_shot",
        "formula_gray8__staged_retained_resolve",
        "formula_gray8__one_shot",
        "numeric__dual_schedule",
        "reflected_gray8__dual_schedule",
        "formula_gray8__dual_schedule",
    ]
    assert learning["frozen_feature_family_order"] == list(feature_counts)
    assert learning["frozen_readout_order"] == ["ridge_logistic", "gram_wiener_fisher"]
    assert learning["atomic_model_fits"] == 3 * 2 * 5 * 2 * 5
    assert learning["bundle_selection_rows"] == 9 * 5 * 2 * 5
    assert learning["fit_cell_rows"] == 32 * 256
    assert learning["selection_cell_rows"] == 20 * 256
    assert protocol["selection_matched_null"]["permutation_pairs_sha256"] == (
        "8e7af50c509be00878d335acc0b49c4838f74ed9ae2c96ba9ca9f6938819a588"
    )

    holdout = protocol["holdout_protocol"]
    assert math.isclose(
        holdout["uniform_random_rank_expected_mean_log2"],
        sum(math.log2(rank) for rank in range(1, 257)) / 256,
        rel_tol=0.0,
        abs_tol=1e-15,
    )
    permutations = list(itertools.permutations(range(5)))
    assert len(permutations) == holdout["primary_exact_permutations"] == 120
    assert holdout["primary_panel_keys"] == 5 * 4
    assert holdout["primary_one_sided_minimum_p"] == 1 / 120
    assert protocol["information_boundary"]["historical_r20_analyze_loader_permitted"] is False
    assert (
        protocol["information_boundary"][
            "holdout_measurements_available_during_fit_selection_or_null"
        ]
        is False
    )
