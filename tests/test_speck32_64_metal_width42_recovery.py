from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import numpy as np
import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "speck32_64_metal_width42_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "speck32_64_metal_width42_recovery_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESEARCH_ROOT = Path(__file__).parents[1] / "research"
RESULTS_DIR = RESEARCH_ROOT / "results" / "v1"
PROTOCOL_PATH = RESEARCH_ROOT / "configs" / MODULE.PROTOCOL_FILENAME
QUALIFICATION_PATH = RESULTS_DIR / MODULE.QUALIFICATION_FILENAME


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(results_dir=RESULTS_DIR)


@pytest.fixture(scope="module")
def metal_host(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[MODULE._QUAL.MetalSpeck3264Host]:
    executable, _build = MODULE._QUAL._compile_native(
        tmp_path_factory.mktemp("speck32-64-metal-width42"), "swiftc"
    )
    host = MODULE._QUAL.MetalSpeck3264Host(executable)
    try:
        yield host
    finally:
        host.close()


def test_protocol_is_hash_bound_and_secret_free(analysis: dict[str, Any]) -> None:
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == (
        MODULE.PROTOCOL_SHA256
    )
    protocol = analysis["protocol"]
    assert protocol["protocol_state"] == "frozen_before_any_A237_candidate_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["qualification"]["sha256"] == (
        MODULE.QUALIFICATION_SHA256
    )
    assert protocol["anchors"]["native_host"]["sha256"] == (
        MODULE.NATIVE_SOURCE_SHA256
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_and_execution_plan_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["unknown_assignment_bits"] == 42
    assert challenge["known_master_key_bits"] == 22
    assert challenge["known_key2_upper6"] & 0x03FF == 0
    assert challenge["unknown_assignment_included"] is False
    target = np.array(challenge["target_ciphertext_words_xy_order"], dtype="<u2")
    control = np.array(challenge["control_ciphertext_words_xy_order"], dtype="<u2")
    assert np.count_nonzero(target ^ control) == 1
    assert int(target[-1] ^ control[-1]) == 1

    plan = analysis["execution_plan"]
    assert plan["rounds"] == 22
    assert plan["logical_candidate_count"] == 2**42
    assert plan["outer_key2_low10_slice_count"] == 2**10
    assert plan["inner_key0_key1_candidate_count_per_slice"] == 2**32
    assert plan["stream_candidate_count"] == 2**30
    assert plan["stream_batch_count"] == 4096
    assert plan["filter_output_bits"] == 96
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False


def test_pre_target_qualification_artifact_is_retained() -> None:
    assert hashlib.sha256(QUALIFICATION_PATH.read_bytes()).hexdigest() == (
        MODULE.QUALIFICATION_SHA256
    )
    payload = json.loads(QUALIFICATION_PATH.read_text())
    assert payload["official_kat_gate"]["actual_ciphertext_words"] == [
        0xA868,
        0x42F2,
    ]
    assert payload["official_kat_gate"]["three_block_scalar_identity"] is True
    assert payload["cross_implementation_gate"]["exact_scalar_identity"] is True
    assert payload["boundary_filter_gate"]["exact_boundary_identity"] is True
    assert payload["information_boundary"]["production_target_selected"] is False


def test_real_metal_host_matches_three_outer_slices(
    analysis: dict[str, Any],
    metal_host: MODULE._QUAL.MetalSpeck3264Host,
) -> None:
    gate = MODULE._mapping_gate(metal_host, analysis["public_challenge"])
    assert gate["outer_values_checked"] == [0, 512, 1023]
    assert gate["logical_candidates_checked"] == 768
    assert gate["complete_output_bits_checked"] == 73_728
    assert gate["exact_scalar_filter_and_mapping_identity"] is True
    assert all(row["control_matches"] == [] for row in gate["rows"])


def test_checkpointed_executor_covers_toy_domain_without_early_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    analysis: dict[str, Any],
) -> None:
    monkeypatch.setattr(MODULE, "OUTER_SLICES", 1)
    monkeypatch.setattr(MODULE, "INNER_CANDIDATES", 16)
    monkeypatch.setattr(MODULE, "LOGICAL_CANDIDATES", 16)
    monkeypatch.setattr(MODULE, "STREAM_CANDIDATES", 4)

    class FakeHost:
        calls: list[tuple[int, int]] = []

        def configure(self, **_kwargs: Any) -> None:
            return None

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.calls.append((first, count))
            return {
                "factual": [5] if first <= 5 < first + count else [],
                "control": [],
                "gpu_seconds": 0.25,
            }

    monkeypatch.setattr(
        MODULE,
        "_confirm",
        lambda _challenge, _target, assignment: {
            "combined_assignment": assignment,
            "complete_three_block_match": assignment == 5,
        },
    )
    checkpoint = tmp_path / "checkpoint.json"
    host = FakeHost()
    execution = MODULE._enumerate_domain(
        host=host,
        challenge=analysis["public_challenge"],
        checkpoint_path=checkpoint,
        resume=False,
    )
    assert execution["logical_candidate_count"] == 16
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [5]
    assert execution["factual_full_matches"] == [5]
    assert execution["control_full_matches"] == []
    assert execution["unique_exact_assignment"] is True
    assert execution["control_target_rejected"] is True
    assert host.calls == [(0, 4), (4, 4), (8, 4), (12, 4)]
    durable = json.loads(checkpoint.read_text())
    assert durable["next_assignment"] == 4
    assert durable["factual_filtered"] == []
    assert durable["control_filtered"] == []
    assert durable["candidate_matches_persisted"] is False


def test_authentic_causal_artifact_is_materialized_and_reader_verified(
    tmp_path: Path,
) -> None:
    execution = {
        "complete_domain_executed": True,
        "factual_filter_matches": [5],
        "factual_confirmations": [
            {"combined_assignment": 5, "complete_three_block_match": True}
        ],
        "control_filter_matches": [],
        "control_confirmations": [],
    }
    payload = {
        "mapping_gate": {"exact_scalar_filter_and_mapping_identity": True},
        "execution": execution,
        "execution_sha256": "1" * 64,
        "confirmation_sha256": "2" * 64,
    }
    path = tmp_path / "a237.causal"
    result = MODULE._build_authentic_causal(
        path=path,
        payload=payload,
        dotcausal_src=MODULE.DEFAULT_DOTCAUSAL_SRC,
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["format"] == "authentic_dotcausal_v1_AI_native"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["embedded_rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"] == 1
    assert result["inference_recomputed_on_reader_open"] is False
    assert result["integrity_verified_by_authoritative_reader"] is True
