from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake256_native_fullround_width32_prospective.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake256_native_fullround_width32_prospective_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake256_native_fullround_width32_prospective_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake256_native_fullround_width32_prospective_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "shake256_native_fullround_width32_prospective_v1.checkpoint.json"
RESULT_SHA256 = "d6b85ca7f15bc198513cd05100187f2ccc0ab97d1f22a906383ccd4a62eda544"
CAUSAL_SHA256 = "05ce09d28994ee6e414ff9e62265c20c3ab819b1d2b343240d3c030943a8c5ab"
CAUSAL_GRAPH_SHA256 = "147294256873d0018e064bd181b120b380f273bd0a3279c99e17ce98f9e05055"
EXECUTION_SHA256 = "2f5597ba3730a2ab6163db47a3b36ca9a7bad3193c271ec3bc9ed8157a32f84d"
CONFIRMATION_SHA256 = "c8abd5902d058fb6c7ecd2e12121b81aaf57854c2efbe9808d4202987715a5a9"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_new_sha256_width32_relation_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "f4e3ee4b43a536d7ccf51964de768953019ecf96819f661a50edaa549d6db068"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A177_candidate_execution"
    assert protocol["anchors"]["A176"]["sha256"] == MODULE.A176_SHA256
    assert protocol["anchors"]["native_reader"]["sha256"] == MODULE.NATIVE_SHA256
    assert protocol["prospective_prediction"]["prediction"] == (
        "the_complete_2^32_domain_returns_one_exact_SHAKE256_model_and_the_bit_flipped_control_returns_zero"
    )
    assert protocol["prospective_prediction"]["domain_scale_vs_retained_SHAKE256_width28"] == 16
    assert protocol["prospective_prediction"]["domain_scale_vs_A165_SHAKE128_width24"] == 256
    assert (
        protocol["information_boundary"]["A177_candidate_outcomes_used_before_protocol_freeze"]
        is False
    )
    assert (
        protocol["information_boundary"][
            "A177_instrumented_assignment_read_before_complete_domain_execution"
        ]
        is False
    )
    assert analysis["candidate_execution_started"] is False


def test_seed_derivation_and_public_fingerprints_are_exact(
    analysis: dict[str, Any],
) -> None:
    digest = hashlib.sha256(MODULE.DERIVATION_LABEL.encode()).hexdigest()
    assert digest == MODULE.DERIVATION_SHA256
    assert (int(digest[:8], 16) & 0x7FFFFFFF) == MODULE.SEED == 679_417_920
    public = analysis["public_relation"]
    assert public["variant"] == "SHAKE256"
    assert public["window_bits"] == 32
    assert public["capacity_window_positions"] == list(range(184, 216))
    assert public["capacity_window_positions_sha256"] == (
        "a11708366dd174e74599b59905cde9969aae3294a3aade1f773e0cd2e9726e39"
    )
    assert public["cleared_template_sha256"] == (
        "6154abe45a4b15942c808b05a04543b0f827d2901b12a0fb369eb6fa1cf1a962"
    )
    assert public["target_rate_sha256"] == (
        "62f4f1019011f2e380a676e70395092b114b76790ae05a7cee7f2157408c6f6c"
    )
    assert public["control_target_rate_sha256"] == (
        "8ea194e51e0c815c163f96ddb7ecd91b81e8b47ecbf98f13b4da3124736cb5f5"
    )
    assert public["target_rate_bits"] == 1_088
    assert public["instrumented_assignment_included"] is False


def test_complete_domain_plan_and_native_recipe_are_hash_bound(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "b9c263610522fcdedda070298bc3e5d4bd81a6f15369c1c7ad1cf1a968f14104"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["logical_candidate_count"] == 4_294_967_296
    assert plan["packed_state_count"] == 67_108_864
    assert plan["stream_batch_count"] == 64
    assert plan["maximum_mask_memory_bytes"] == 16_777_216
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["checkpoint_resume_enabled"] is True
    recipe = analysis["anchor_gates"]["native_reader_recipe"]
    assert recipe["variant"] == "SHAKE256"
    assert recipe["permutation_rounds"] == 24
    assert recipe["rate_lanes"] == 17
    assert recipe["capacity_bits"] == 512
    assert recipe["candidates_per_machine_word"] == 64
    assert recipe["filter_lanes"] == 2
    assert recipe["native_source_sha256"] == MODULE.NATIVE_SOURCE_SHA256


def test_analyze_never_reads_the_instrumented_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        MODULE._WINDOW,
        "_extract_window",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("pre-execution assignment read")
        ),
    )
    fresh = MODULE.analyze(RESULTS_DIR)
    assert fresh["candidate_execution_started"] is False
    assert fresh["public_relation"]["instrumented_assignment_included"] is False


def test_complete_domain_executor_supports_resume_without_early_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    analysis: dict[str, Any],
) -> None:
    recipe = dict(analysis["anchor_gates"]["native_reader_recipe"])
    monkeypatch.setattr(MODULE, "WINDOW_BITS", 8)
    monkeypatch.setattr(MODULE, "STREAM_PACKS", 2)
    monkeypatch.setattr(MODULE, "THREADS", 1)

    class FakeKernel:
        calls: list[tuple[int, int]] = []

        def filter_masks(
            self,
            _template: np.ndarray,
            _rate_lanes: int,
            _positions: np.ndarray,
            _window_bits: int,
            first_pack: int,
            pack_count: int,
            _target: np.ndarray,
            _control: np.ndarray,
            _filter_lanes: int,
            _threads: int,
        ) -> tuple[np.ndarray, np.ndarray]:
            self.calls.append((first_pack, pack_count))
            factual = np.zeros(pack_count, dtype=np.uint64)
            control = np.zeros(pack_count, dtype=np.uint64)
            if first_pack == 0:
                factual[0] = np.uint64(1 << 5)
            return factual, control

    monkeypatch.setattr(
        MODULE._A165,
        "_independent_confirm",
        lambda _template, _target, _positions, _variant, assignment: {
            "assignment": assignment,
            "complete_rate_match": assignment == 5,
        },
    )
    public_relation = {
        "capacity_window_positions_sha256": "positions",
        "cleared_template_sha256": "template",
        "target_rate_sha256": "target",
        "control_target_rate_sha256": "control",
    }
    checkpoint = tmp_path / "checkpoint.json"
    fingerprint = MODULE._checkpoint_fingerprint(public_relation)
    MODULE._NATIVE._atomic_json(
        checkpoint,
        {
            **fingerprint,
            "next_pack": 0,
            "factual_filtered": [],
            "control_filtered": [],
        },
    )
    variant = MODULE._BASE.VARIANTS[MODULE.VARIANT_KEY]
    public = {
        "template": np.zeros((1, 25), dtype=np.uint64),
        "target": np.zeros((1, 25), dtype=np.uint64),
        "positions": np.arange(8, dtype=np.uint16),
    }
    result = MODULE._enumerate_public_relation(
        kernel=FakeKernel(),
        public=public,
        public_relation=public_relation,
        variant=variant,
        recipe=recipe,
        checkpoint_path=checkpoint,
        resume=True,
    )
    assert result["logical_candidate_count"] == 256
    assert result["packed_state_count"] == 4
    assert result["complete_domain_executed"] is True
    assert result["early_stop_used"] is False
    assert result["factual_filter_matches"] == [5]
    assert result["factual_full_matches"] == [5]
    assert result["control_full_matches"] == []
    assert result["unique_exact_public_model"] is True
    assert result["control_target_rejected"] is True
    assert FakeKernel.calls == [(0, 2), (2, 2)]


def test_retained_a177_artifact_is_hash_pinned_and_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)

    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A177"
    assert payload["evidence_stage"] == (
        "SHAKE256_NATIVE_FULLROUND_WIDTH32_RECONSTRUCTION_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A176_result_sha256"] == MODULE.A176_SHA256
    assert payload["anchor_gates"]["A176_mechanism_sha256"] == MODULE.A176_RESULT_SHA256
    assert payload["anchor_gates"]["native_result_sha256"] == MODULE.NATIVE_SHA256
    assert payload["anchor_gates"]["native_causal_sha256"] == MODULE.NATIVE_CAUSAL_SHA256
    assert payload["anchor_gates"]["native_source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert payload["public_relation"] == analysis["public_relation"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["execution_plan_sha256"] == (
        "b9c263610522fcdedda070298bc3e5d4bd81a6f15369c1c7ad1cf1a968f14104"
    )

    execution = payload["execution"]
    assert execution["window_bits"] == 32
    assert execution["logical_candidate_count"] == 4_294_967_296
    assert execution["candidate_pack_width"] == 64
    assert execution["packed_state_count"] == 67_108_864
    assert execution["stream_pack_count"] == 1_048_576
    assert execution["stream_batch_count"] == 64
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["resumed_pack_count"] == 0
    assert execution["newly_executed_pack_count"] == 67_108_864
    assert execution["filter_rate_bits"] == 128
    assert execution["factual_filter_matches"] == [2_761_171_082]
    assert execution["factual_full_matches"] == [2_761_171_082]
    assert execution["unique_exact_public_model"] is True
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["control_target_rejected"] is True
    assert execution["instrumented_assignment_input_used"] is False
    assert execution["posthoc_assignment_read_before_candidate_execution"] is False

    assert len(execution["factual_confirmations"]) == 1
    confirmation = execution["factual_confirmations"][0]
    assert confirmation["assignment"] == 2_761_171_082
    assert confirmation["complete_rate_match"] is True
    assert confirmation["rate_lanes_checked"] == 17
    assert confirmation["rate_bits_checked"] == 1_088
    assert confirmation["implementation"] == "independent_NumPy_lane_core"
    assert (
        confirmation["candidate_rate_sha256"] == (payload["public_relation"]["target_rate_sha256"])
    )
    assert execution["control_confirmations"] == []

    execution_digest_input = {
        key: value
        for key, value in execution.items()
        if key not in {"factual_confirmations", "control_confirmations"}
    }
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert MODULE._canonical_sha256(execution_digest_input) == EXECUTION_SHA256
    confirmation_digest_input = {
        "factual": execution["factual_confirmations"],
        "control": execution["control_confirmations"],
    }
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256
    assert MODULE._canonical_sha256(confirmation_digest_input) == CONFIRMATION_SHA256

    posthoc = payload["posthoc_comparison"]
    assert posthoc["read_only_after_complete_domain_execution"] is True
    assert posthoc["used_for_candidate_generation_filtering_or_confirmation"] is False
    assert posthoc["instrumented_assignment"] == 2_761_171_082
    assert posthoc["recovered_assignments"] == [2_761_171_082]
    assert posthoc["unique_reconstruction_matches_instrumented_assignment"] is True
    assert posthoc["instrumented_assignment_independent_check"]["complete_rate_match"] is True

    cross_gate = payload["current_build_cross_implementation_gate"]
    assert cross_gate["states"] == 64
    assert cross_gate["state_bits_checked"] == 102_400
    assert cross_gate["exact_match"] is True
    assert payload["parameters"]["volatile_wallclock_excluded_from_canonical_result"] is True
    for volatile_field in (
        '"wallclock_seconds"',
        '"elapsed_seconds"',
        '"duration_seconds"',
        '"peak_memory',
        '"memory_bytes"',
    ):
        assert volatile_field not in raw.decode().lower()
    assert CHECKPOINT_PATH.exists() is False


def test_retained_a177_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake256-a176-derived-width32-public-freeze",
        "shake256-retained-native-fullround-reader-recipe",
        "shake256-a177-complete-packed-domain-execution",
        "shake256-a177-independent-complete-rate-confirmation",
        "shake256-a177-posthoc-prospective-comparison",
    ]
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )
