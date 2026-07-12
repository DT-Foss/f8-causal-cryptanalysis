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
    / "chacha20_metal_width36_partial_key_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_metal_width36_partial_key_recovery_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
PROTOCOL_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "configs"
    / "chacha20_metal_width36_partial_key_recovery_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_metal_width36_partial_key_recovery_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_metal_width36_partial_key_recovery_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "chacha20_metal_width36_partial_key_recovery_v1.checkpoint.json"
RESULT_SHA256 = "8450a334209f7bb78610439d604c6bc9ac69213f4f0d6c7f6068dfd07cd708e3"
CAUSAL_SHA256 = "aad208518d6718cac73937c198d0919c0e6305a56ac8a43345d02155eefdb110"
CAUSAL_GRAPH_SHA256 = "be83fdf5fc214cc21230c08c51178e2a4290814d94db62fc100766e75dd6db86"
EXECUTION_SHA256 = "bbff0b5f615e41b9397b61a2324451df1f61780576e928a41f71df05412c4c26"
CONFIRMATION_SHA256 = "81baeb0ab4d6e8182a717ad08aa85c052cac84c61adc25ab23af041a084b9893"
RECOVERED_COMBINED = 12_995_408_051
RECOVERED_WORD0 = 110_506_163
RECOVERED_NIBBLE = 3


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


@pytest.fixture(scope="module")
def metal_host(
    tmp_path_factory: pytest.TempPathFactory,
    analysis: dict[str, Any],
) -> Iterator[tuple[MODULE.SliceMetalHost, dict[str, Any]]]:
    if sys.platform != "darwin":
        pytest.skip("native Swift/Metal host requires macOS")
    executable, build = MODULE._A181._compile_native(
        tmp_path_factory.mktemp("chacha-metal-width36"),
        "swiftc",
    )
    host = MODULE.SliceMetalHost(
        executable,
        MODULE._initial_for_nibble(analysis["public_challenge"], 0),
        analysis["target"],
        analysis["control_target"],
    )
    try:
        yield host, build
    finally:
        host.close()


def test_protocol_freezes_fresh_width36_challenge_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "8c69a87b101f7f7e718b1c162a96798484f1bc6f252775c69f197c2770c72bfc"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A182_candidate_execution"
    assert protocol["anchors"]["A181"]["sha256"] == MODULE.A181_SHA256
    assert protocol["anchors"]["A181"]["causal_sha256"] == MODULE.A181_CAUSAL_SHA256
    assert protocol["native_host"]["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "fresh_fullround_36_bit_partial_key_recovery"
    )
    assert (
        protocol["required_validation_gates"][
            "candidate_execution_against_public_A182_target_before_freeze"
        ]
        is False
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A182_candidate_outcomes_used_before_protocol_freeze"] is False
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_derivation_and_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_RELATION_SHA256
    assert challenge["unknown_assignment_bits"] == 36
    assert challenge["unknown_key_word0_bits"] == 32
    assert challenge["unknown_key_word1_low_bits"] == 4
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_included"] is False
    assert challenge["unknown_key_word1_low_nibble_included"] is False
    assert challenge["known_key_word1_upper28"] & 0xF == 0

    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(44)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "7a3b211ff000f9887612e64c03af199f76aaed5e836296a08673622ec1ebc591"
    )
    assert int(words[0]) & 0xFFFFFFF0 == challenge["known_key_word1_upper28"]
    assert [int(value) for value in words[1:7]] == challenge["known_key_words_2_through_7"]
    assert int(words[7]) == challenge["counter"]
    assert [int(value) for value in words[8:11]] == challenge["nonce_words"]

    target = np.array(challenge["target_words"], dtype="<u4")
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert hashlib.sha256(target.tobytes()).hexdigest() == challenge["target_block_sha256"]
    assert (
        hashlib.sha256(control.tobytes()).hexdigest() == (challenge["control_target_block_sha256"])
    )

    secret_spellings = (
        str(RECOVERED_COMBINED),
        str(RECOVERED_WORD0),
        "3069630b3",
        "069630b3",
    )
    pre_execution_sources = [
        PROTOCOL_PATH,
        MODULE_PATH,
        MODULE_PATH.with_name(MODULE.NATIVE_SOURCE_FILENAME),
    ]
    for path in pre_execution_sources:
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in secret_spellings)


def test_width36_execution_plan_covers_exact_scope(analysis: dict[str, Any]) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "d38b357697268ec6e953b0ddc62f975040205dd5e6a987e618b810ab4a0fb028"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 20
    assert plan["unknown_key_bits"] == 36
    assert plan["known_key_bits"] == 220
    assert plan["logical_candidate_count"] == 68_719_476_736
    assert plan["outer_nibble_slice_count"] == 16
    assert plan["inner_word_candidate_count_per_slice"] == 4_294_967_296
    assert plan["stream_batches_per_slice"] == 16
    assert plan["stream_batch_count"] == 256
    assert plan["gpu_logical_thread_count"] == 68_719_476_736
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["fresh_public_challenge"] is True
    assert plan["unknown_assignment_available_to_runner_before_execution"] is False


def test_real_swift_host_and_three_slice_mapping_gate_are_exact(
    analysis: dict[str, Any],
    metal_host: tuple[MODULE.SliceMetalHost, dict[str, Any]],
) -> None:
    host, build = metal_host
    assert build["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert build["warnings_as_errors"] is True
    assert "-warnings-as-errors" in build["selected_flags"]
    assert host.identity["version"] == MODULE._A181.NATIVE_VERSION
    assert host.identity["metal"]["device"] == "Apple M4"
    assert host.identity["metal"]["filter_execution_width"] == 32
    assert host.identity["metal"]["shader_runtime_compiled"] is True

    gate = MODULE._synthetic_slice_mapping_gate(
        host,
        analysis["protocol"],
        analysis["public_challenge"],
    )
    assert gate["nibbles_checked"] == [0, 7, 15]
    assert gate["logical_candidates_checked"] == 768
    assert gate["complete_output_bits_checked"] == 393_216
    assert gate["exact_scalar_and_mapping_identity"] is True
    assert [row["factual_key_word0"] for row in gate["rows"]] == [182_105] * 3
    assert [row["factual_combined_assignment"] for row in gate["rows"]] == [
        182_105,
        30_064_953_177,
        64_424_691_545,
    ]
    assert all(row["control_matches"] == [] for row in gate["rows"])


def test_retained_a182_result_is_complete_and_hash_pinned(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A182"
    assert payload["evidence_stage"] == ("CHACHA20_FULLROUND_36BIT_PARTIAL_KEY_RECOVERY_RETAINED")
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A181_result_sha256"] == MODULE.A181_SHA256
    assert payload["anchor_gates"]["A181_causal_sha256"] == MODULE.A181_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["native_build"]["warnings_as_errors"] is True
    assert payload["host_identity"]["metal"]["device"] == "Apple M4"
    assert payload["synthetic_slice_mapping_gate"]["complete_output_bits_checked"] == 393_216

    execution = payload["execution"]
    assert execution["unknown_key_bits"] == 36
    assert execution["known_key_bits"] == 220
    assert execution["logical_candidate_count"] == 68_719_476_736
    assert execution["outer_nibble_slice_count"] == 16
    assert execution["inner_word_candidate_count_per_slice"] == 4_294_967_296
    assert execution["stream_batch_count"] == 256
    assert execution["resumed_assignment_count"] == 0
    assert execution["newly_executed_assignment_count"] == 68_719_476_736
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [RECOVERED_COMBINED]
    assert execution["factual_full_matches"] == [RECOVERED_COMBINED]
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["unique_exact_assignment"] is True
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False

    confirmation = execution["factual_confirmations"]
    assert len(confirmation) == 1
    assert confirmation[0]["combined_assignment"] == RECOVERED_COMBINED
    assert confirmation[0]["key_word0"] == RECOVERED_WORD0
    assert confirmation[0]["key_word1_low_nibble"] == RECOVERED_NIBBLE
    assert confirmation[0]["complete_block_match"] is True
    assert confirmation[0]["output_bits_checked"] == 512
    assert confirmation[0]["candidate_block_sha256"] == (
        "b1de7d354eb0c3707a37cefac54f8ede5233310a245f6d69e6c0e112d02de509"
    )

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

    recovery = payload["recovery"]
    assert recovery["recovered_combined_assignments"] == [RECOVERED_COMBINED]
    assert recovery["recovered_key_word0"] == [RECOVERED_WORD0]
    assert recovery["recovered_key_word1_low_nibble"] == [RECOVERED_NIBBLE]
    assert recovery["first_reveal_occurs_after_complete_domain_execution"] is True
    assert recovery["unknown_assignment_source_was_discarded_before_runner_construction"]
    assert format(RECOVERED_COMBINED, "09x") == "3069630b3"
    assert format(RECOVERED_WORD0, "08x") == "069630b3"
    assert payload["parameters"]["volatile_wallclock_excluded_from_canonical_result"] is True
    for volatile_field in ('"wallclock_seconds"', '"elapsed_seconds"', '"duration_seconds"'):
        assert volatile_field not in raw.decode().lower()
    assert CHECKPOINT_PATH.exists() is False


def test_retained_a182_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a181-metal-complete-domain-anchor",
        "chacha20-a182-fresh-width36-challenge-freeze",
        "chacha20-a182-two-word-slice-mapping-gate",
        "chacha20-a182-complete-width36-domain-execution",
        "chacha20-a182-independent-width36-recovery",
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
