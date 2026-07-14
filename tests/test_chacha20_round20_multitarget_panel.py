from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research/experiments"
if str(EXPERIMENTS) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS))

import chacha20_round20_multitarget_common as common  # noqa: E402
import chacha20_round20_multitarget_master_preflight as master  # noqa: E402
import chacha20_round20_multitarget_measure as measure  # noqa: E402
import chacha20_round20_multitarget_recovery as recovery  # noqa: E402


def _import(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_submaster_replaces_only_public_material_and_rehashes_design() -> None:
    base = json.loads(master.BASE_MASTER.read_bytes())
    a278 = _import(master.A278_PREFLIGHT, "test_a282_a278")
    template = a278._public_template(bytes(range(32)))
    value = master.make_submaster(base, template)
    master._validate_submaster(value)
    assert value["cross_material_public_template"] == template
    assert value["cross_material_public_template"] != base[
        "cross_material_public_template"
    ]
    assert value["frozen_schedule"] == base["frozen_schedule"]
    assert value["scientific_design_sha256"] == common.canonical_sha256(
        {
            "cross_material_public_template": template,
            "frozen_schedule": value["frozen_schedule"],
            "target_generation_contract": value["target_generation_contract"],
            "information_boundary": value["information_boundary"],
        }
    )


def test_label_gate_rejects_secret_fields_at_any_depth() -> None:
    common.assert_label_free({"public": {"target_words": [1, 2, 3]}})
    with pytest.raises(RuntimeError, match="target-label field"):
        common.assert_label_free({"outer": [{"low20": 7}]})


def test_rank_readout_uses_frozen_complete_order() -> None:
    order = list(range(256))
    protocol = {"frozen_order": {"complete_cell_order": order}}
    assert recovery._rank_from_result(
        {"top_execution": {"sat_row": {"cell_index": 36, "prefix8": "00100100"}}},
        protocol,
    ) == (37, "00100100")
    assert recovery._rank_from_result(
        {
            "top_execution": {"sat_row": None},
            "residual_execution": {
                "sat_row": {"cell_index": 0, "prefix8": "11001000"}
            },
        },
        protocol,
    ) == (201, "11001000")


def test_panel_artifact_paths_are_target_isolated() -> None:
    measurement_paths = [measure._paths(index) for index in range(1, 5)]
    recovery_paths = [recovery._result_paths(index) for index in range(1, 5)]
    assert len({str(row["measurement"]) for row in measurement_paths}) == 4
    assert len({str(row["result"]) for row in recovery_paths}) == 4
    assert all(row["result"] != row["canonical"] for row in recovery_paths)
