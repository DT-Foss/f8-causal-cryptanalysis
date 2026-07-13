from __future__ import annotations

import copy
import importlib.util
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_multihorizon_preflight.py"


def _module():
    spec = importlib.util.spec_from_file_location("a220p_preflight_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _module()


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def protocol() -> dict[str, Any]:
    return MODULE._load_protocol()


def _fake_prepared(protocol: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    helper = tmp_path / "fake_helper"
    cnf = tmp_path / "fake.cnf"
    helper.write_bytes(b"fake helper")
    cnf.write_text("p cnf 20 0\n")
    anchor = protocol["known_key_anchor"]
    public = protocol["public_R20_material"]
    helper_sha256 = protocol["anchors"]["multihorizon_content_addressed_binary_sha256"]
    stable_build = {
        "returncode": 0,
        "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        "stdout_sha256": MODULE._sha256(b""),
        "stderr_sha256": MODULE._sha256(b""),
        "source_sha256_started": protocol["anchors"]["multihorizon_native_source_sha256"],
        "source_sha256_finished": protocol["anchors"]["multihorizon_native_source_sha256"],
        "compiler_sha256": "11" * 32,
        "cadical_header_sha256": "22" * 32,
        "cadical_library_sha256": "33" * 32,
        "temporary_binary_sha256": helper_sha256,
        "binary_sha256": helper_sha256,
        "content_addressed_binary": True,
    }
    return {
        "anchor_hashes": MODULE._declared_anchor_hashes(protocol),
        "known_key_identity": {
            "role": "explicit_known_calibration_key",
            "ledger_split": "train",
            "ledger_index": 0,
            "derivation_label": anchor["derivation_label"],
            "known_low20": anchor["low20"],
            "known_low20_hex": anchor["low20_hex"],
            "known_prefix8": anchor["target_prefix8"],
        },
        "known_key_confirmation_metadata": {
            "generated_block_count": 8,
            "generated_output_bits": 4096,
            "block_sha256": public["known_train_00_block_sha256"],
            "full_key_word0_hex": anchor["full_key_word0_hex"],
            "full_key_words_little_endian_sha256": anchor["full_key_words_little_endian_sha256"],
            "formula_constrained_block_index": 0,
            "formula_constrained_output_bits": 512,
            "blocks_1_through_7_used_only_for_confirmation_metadata": True,
        },
        "template_manifest": {
            "base_cnf_sha256": protocol["symbolic_template"]["base_cnf_sha256"],
            "all_mapping_probes_exact_unit_deltas": True,
        },
        "instantiation_manifest": {
            "header": "p cnf 20 0",
            "bytes": len(cnf.read_bytes()),
            "sha256": "44" * 32,
            "unit_count": 0,
            "unit_int32le_sha256": MODULE._sha256(b""),
        },
        "key_mapping": list(range(1, 21)),
        "cnf_path": cnf,
        "cnf_sha256": "44" * 32,
        "helper_path": helper,
        "helper_sha256": helper_sha256,
        "native_helper_build": {**stable_build, "elapsed_seconds": 0.125},
        "native_helper_stable_provenance": stable_build,
        "orchestrator_source_sha256_started": MODULE._file_sha256(MODULE.ORCHESTRATOR),
        "exclusive_orchestrator_lock_acquired": True,
        "target_secret_or_salt_accessed": False,
        "prospective_target_artifact_accessed": False,
    }


class _FakeRunner:
    def __init__(self, module, prepared: dict[str, Any], protocol: dict[str, Any]):
        self.module = module
        self.prepared = prepared
        self.protocol = protocol
        self.calls: list[str] = []
        self.active = 0
        self.maximum_active = 0
        self.lock = threading.Lock()

    def __call__(
        self,
        *,
        helper: Path,
        cnf: Path,
        mode: str,
        order: list[str],
        key_one_literals_bit0_through_bit19: list[int],
        conflict_horizons: list[int],
        watchdog_seconds: float,
        external_timeout_seconds: float,
    ) -> dict[str, Any]:
        assert helper == self.prepared["helper_path"]
        assert cnf == self.prepared["cnf_path"]
        assert key_one_literals_bit0_through_bit19 == list(range(1, 21))
        assert watchdog_seconds == 5.0
        assert external_timeout_seconds == 120.0 + 256.0 * len(conflict_horizons) * 5.0
        with self.lock:
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            self.calls.append(mode)
        time.sleep(0.002)
        schedule_offset = 3 if len(conflict_horizons) > 1 else 0
        cells = []
        stages = []
        for cell_index, prefix in enumerate(order):
            value = int(prefix, 2)
            conflicts = 64 + (value % 7) + schedule_offset
            decisions = 80 + ((value * 3) % 17) + schedule_offset
            propagations = 1000 + ((value * 19) % 101) + 2 * schedule_offset
            active_delta = (value % 5) - 2
            irredundant_delta = (value % 9) - 4
            redundant_delta = ((value * 5) % 23) - 11 + schedule_offset
            cells.append(
                {
                    "prefix8": prefix,
                    "cell_index": cell_index,
                    "final_status": "unknown",
                    "metrics_delta": [conflicts, decisions, propagations],
                    "active_variables_delta": active_delta,
                    "irredundant_clauses_delta": irredundant_delta,
                    "redundant_clauses_delta": redundant_delta,
                }
            )
            for stage_index, horizon in enumerate(conflict_horizons):
                stages.append(
                    {
                        "prefix8": prefix,
                        "cell_index": cell_index,
                        "stage_index": stage_index,
                        "horizon": horizon,
                        "status": "unknown",
                        "elapsed_seconds": 0.0001 * (stage_index + 1),
                    }
                )
        expected_hashes = {
            "wrapper_sha256": self.protocol["anchors"]["multihorizon_wrapper_sha256"],
            "source_sha256": self.protocol["anchors"]["multihorizon_native_source_sha256"],
            "helper_sha256": self.prepared["helper_sha256"],
            "cnf_sha256": self.prepared["cnf_sha256"],
        }
        with self.lock:
            self.active -= 1
        return {
            "mode": mode,
            "order": order,
            "conflict_horizons": conflict_horizons,
            "watchdog_seconds_per_stage": watchdog_seconds,
            "stages": stages,
            "cells": cells,
            "summary": {
                "cells": 256,
                "stages_emitted": len(stages),
                "sat_cells": 0,
                "unsat_cells": 0,
                "unknown_cells": 256,
            },
            "retained_state_continuity_verified": True,
            "all_watchdogs_clear": True,
            "command": [str(helper)],
            "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            "launch_artifact_hashes_started": expected_hashes,
            "launch_artifact_hashes_finished": expected_hashes,
            "launch_identity_verified": True,
            "process_elapsed_seconds": 0.01,
            "stdout_sha256": self.module._sha256(mode.encode()),
            "stderr_sha256": self.module._sha256(b""),
            "helper_returncode": 0,
        }


def test_protocol_order_hashes_anchors_and_reversal_semantics(
    protocol: dict[str, Any],
) -> None:
    orders = MODULE._operator_orders(protocol)
    manifests = MODULE._order_manifests(protocol, orders)
    assert list(orders) == [row["name"] for row in protocol["operator_orders"]]
    assert all(row["complete_prefix_permutation"] for row in manifests.values())
    assert orders["numeric_forward"] == [f"{value:08b}" for value in range(256)]
    assert orders["numeric_reverse_same_anchor"] == [
        "00000000",
        *(f"{value:08b}" for value in range(255, 0, -1)),
    ]
    assert manifests["numeric_reverse_same_anchor"]["reversal_semantics"] == (
        "same_anchor_directional_stress_control_with_numeric_wrap_edge_substitution_"
        "not_a_pure_edge_matched_reversal"
    )
    assert manifests["reflected_gray8_reverse_same_anchor"]["reversal_semantics"] == (
        "exact_same_anchor_cycle_reversal"
    )
    assert manifests["formula_gray8_forward"]["anchor_prefix8"] == "10110000"
    assert manifests["formula_gray8_forward"]["order_uint8_sha256"] == (
        "ba9cf4d93c1937665772c77b9091d45cb575054c70037d9cc540ee70a9609127"
    )
    assert manifests["formula_gray8_reverse_same_anchor"]["order_uint8_sha256"] == (
        "7116050e6dd5aef0a295cdd5291205b1ddac952883535f35370e521b190c5ae7"
    )
    assert (
        MODULE._declared_anchor_hashes(protocol)[
            "research/experiments/chacha20_retained_multihorizon.py"
        ]
        == "befedcd5bd91acf60838c2a7a071972968aecec67e6e04860747074aa8cf328a"
    )


def test_a214_train00_known_key_identity_without_R20_solver(
    protocol: dict[str, Any],
) -> None:
    helper_path = ROOT / protocol["anchors"]["A214_knownkey_helper_path"]
    knownkey = _load(helper_path, "a220p_test_knownkey")
    identity = MODULE._validate_known_key_ledger(protocol, knownkey)
    assert identity["known_low20"] == 0xEDA50
    assert identity["known_low20_hex"] == "eda50"
    assert identity["known_prefix8"] == "11101101"
    assert identity["derivation_label"] == "f8-causal:A214:train:0:known-low20-v1"


def test_checkpoint_resume_identity_and_completed_run_hash(
    protocol: dict[str, Any], tmp_path: Path
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    orders = MODULE._operator_orders(protocol)
    manifests = MODULE._order_manifests(protocol, orders)
    plan = MODULE._run_plan(protocol, orders)
    identity = MODULE._checkpoint_identity(prepared=prepared, order_manifests=manifests, plan=plan)
    path = tmp_path / "checkpoint.json"
    MODULE._atomic_json(path, {**identity, "completed_runs": {}}, private=True)
    loaded = MODULE._load_checkpoint(
        path,
        identity=identity,
        valid_run_ids={row["run_id"] for row in plan},
    )
    assert loaded["cnf_sha256"] == prepared["cnf_sha256"]

    changed = {**identity, "cnf_sha256": "ff" * 32}
    with pytest.raises(RuntimeError, match="checkpoint identity differs"):
        MODULE._load_checkpoint(
            path,
            identity=changed,
            valid_run_ids={row["run_id"] for row in plan},
        )

    bad_record = {
        "run_id": plan[0]["run_id"],
        "checkpoint_record_sha256": "00" * 32,
    }
    MODULE._atomic_json(
        path,
        {**identity, "completed_runs": {plan[0]["run_id"]: bad_record}},
        private=True,
    )
    with pytest.raises(RuntimeError, match="completed-run hash differs"):
        MODULE._load_checkpoint(
            path,
            identity=identity,
            valid_run_ids={row["run_id"] for row in plan},
        )


def test_orchestrator_lock_rejects_a_second_holder(tmp_path: Path) -> None:
    lock = tmp_path / "a220p.lock"
    with MODULE._exclusive_orchestrator_lock(lock):
        with pytest.raises(RuntimeError, match="already holds the launch lock"):
            with MODULE._exclusive_orchestrator_lock(lock):
                pytest.fail("a second A220P orchestrator acquired the same lock")


def test_fake_full_preflight_measurement_projection_and_hash_are_solver_free(
    protocol: dict[str, Any], tmp_path: Path
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    runner = _FakeRunner(MODULE, prepared, protocol)
    output = tmp_path / "result.json"
    checkpoint = tmp_path / "checkpoint.json"
    payload = MODULE.run(
        output,
        checkpoint,
        _test_prepared=prepared,
        _test_run_callable=runner,
    )

    assert len(runner.calls) == 12
    assert len(set(runner.calls)) == 12
    assert 1 <= runner.maximum_active <= 2
    assert checkpoint.exists() is False
    assert payload["completion_gates"]["all_12_runs_complete"] is True
    assert payload["completion_gates"]["maximum_concurrent_solver_processes"] == 2
    assert payload["completion_gates"]["exclusive_orchestrator_lock_acquired"] is True
    assert payload["completion_gates"]["orchestrator_source_unchanged"] is True
    assert payload["orchestrator_source_provenance"]["sha256_started"] == MODULE._file_sha256(
        MODULE.ORCHESTRATOR
    )
    assert (
        payload["orchestrator_source_provenance"]["sha256_finished"]
        == payload["orchestrator_source_provenance"]["sha256_started"]
    )
    assert (
        payload["information_boundary"]["target_secret_or_salt_accessed_during_execution"] is False
    )
    assert (
        payload["information_boundary"]["prospective_target_artifact_accessed_during_execution"]
        is False
    )
    assert len(payload["run_records"]) == 12
    assert len(payload["staged_vs_one_shot_comparisons"]) == 6
    for comparison in payload["staged_vs_one_shot_comparisons"].values():
        assert "not one uninterrupted solve" in comparison["staged_semantics"]
        assert set(comparison["channels"]) == set(MODULE.CHANNELS)
        for channel in comparison["channels"].values():
            assert channel["same_prefix_cells"] == 256
            assert channel["zscore_pearson"] is not None
            assert channel["average_rank_spearman"] is not None

    projection = MODULE._measurement_projection(payload)
    assert payload["measurement_sha256"] == MODULE._canonical_sha256(projection)
    changed = copy.deepcopy(payload)
    changed["volatile_observations"]["native_build_elapsed_seconds"] = 999.0
    first = next(iter(changed["volatile_observations"]["runs"].values()))
    first["process_elapsed_seconds"] = 123.0
    first["stdout_sha256"] = "ff" * 32
    assert (
        MODULE._canonical_sha256(MODULE._measurement_projection(changed))
        == payload["measurement_sha256"]
    )
    assert MODULE._verify_final(output)["measurement_sha256"] == payload["measurement_sha256"]
