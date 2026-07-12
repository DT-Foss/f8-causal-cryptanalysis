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
    / "chacha20_metal_width38_partial_key_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_metal_width38_partial_key_recovery_tested",
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
    / "chacha20_metal_width38_partial_key_recovery_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_metal_width38_partial_key_recovery_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_metal_width38_partial_key_recovery_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "chacha20_metal_width38_partial_key_recovery_v1.checkpoint.json"
RESULT_SHA256 = "68d4396e8c064baa2385467cfd5dd7d9aee06014d40f87ee6dfdb8c3d253be7d"
CAUSAL_SHA256 = "2f82b26e85595f50895f159db95562fa872d373b10e5f303f73ca2947ba51688"
CAUSAL_GRAPH_SHA256 = "c96230676d20de6d3b791cfc4d6a3436a17ee7e9047bd38ff62a8ca146265f6f"
EXECUTION_SHA256 = "e29673909dd5c36b31b91771379eef1cb6535cde8be42f67eb6a7669d29765a2"
CONFIRMATION_SHA256 = "a62ebadd0deb550ac35808d15559244deb60cfec1dee824be84a937d02c12e9c"
RECOVERED_COMBINED = 112_033_414_660
RECOVERED_WORD0 = 364_264_964
RECOVERED_LOW_VALUE = 26


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
        tmp_path_factory.mktemp("chacha-metal-width38"),
        "swiftc",
    )
    host = MODULE.SliceMetalHost(
        executable,
        MODULE._initial_for_low_value(analysis["public_challenge"], 0),
        analysis["target"],
        analysis["control_target"],
    )
    try:
        yield host, build
    finally:
        host.close()


def test_protocol_freezes_fresh_width38_challenge_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "91b7c70a9849b3c1e39ea51fe806b2e488db811b6672de7e7046a6319c155dcd"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A183_candidate_execution"
    assert protocol["anchors"]["A182"]["sha256"] == MODULE.A182_SHA256
    assert protocol["anchors"]["A182"]["causal_sha256"] == MODULE.A182_CAUSAL_SHA256
    assert protocol["native_host"]["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "fresh_fullround_38_bit_partial_key_recovery"
    )
    assert (
        protocol["required_validation_gates"][
            "candidate_execution_against_public_A183_target_before_freeze"
        ]
        is False
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A183_candidate_outcomes_used_before_protocol_freeze"] is False
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_derivation_and_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_RELATION_SHA256
    assert challenge["unknown_assignment_bits"] == 38
    assert challenge["unknown_key_word0_bits"] == 32
    assert challenge["unknown_key_word1_low_bits"] == 6
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_included"] is False
    assert challenge["unknown_key_word1_low_value_included"] is False
    assert challenge["known_key_word1_upper26"] & 0x3F == 0

    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(44)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "115c80b7de288e9e3c1aef9024a060ad5ec33fe075426d6dcb95de049f4479ec"
    )
    assert int(words[0]) & 0xFFFFFFC0 == challenge["known_key_word1_upper26"]
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
        "1a15b63e04",
        "15b63e04",
    )
    pre_execution_sources = [
        PROTOCOL_PATH,
        MODULE_PATH,
        MODULE_PATH.with_name(MODULE.NATIVE_SOURCE_FILENAME),
    ]
    for path in pre_execution_sources:
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in secret_spellings)


def test_width38_execution_plan_covers_exact_scope(analysis: dict[str, Any]) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "0464807aaa9dcb1641587bd70295ae2ce4ac99973ce7d4fb78d7cd60e1b3cc31"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 20
    assert plan["unknown_key_bits"] == 38
    assert plan["known_key_bits"] == 218
    assert plan["logical_candidate_count"] == 274_877_906_944
    assert plan["outer_low_bit_slice_count"] == 64
    assert plan["inner_word_candidate_count_per_slice"] == 4_294_967_296
    assert plan["stream_batches_per_slice"] == 16
    assert plan["stream_batch_count"] == 1_024
    assert plan["gpu_logical_thread_count"] == 274_877_906_944
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
    assert gate["low_values_checked"] == [0, 31, 63]
    assert gate["logical_candidates_checked"] == 768
    assert gate["complete_output_bits_checked"] == 393_216
    assert gate["exact_scalar_and_mapping_identity"] is True
    assert [row["factual_key_word0"] for row in gate["rows"]] == [183_105] * 3
    assert [row["factual_combined_assignment"] for row in gate["rows"]] == [
        183_105,
        133_144_169_281,
        270_583_122_753,
    ]
    assert all(row["control_matches"] == [] for row in gate["rows"])


def test_retained_a183_result_is_complete_and_hash_pinned(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A183"
    assert payload["evidence_stage"] == ("CHACHA20_FULLROUND_38BIT_PARTIAL_KEY_RECOVERY_RETAINED")
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A182_result_sha256"] == MODULE.A182_SHA256
    assert payload["anchor_gates"]["A182_causal_sha256"] == MODULE.A182_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["native_build"]["warnings_as_errors"] is True
    assert payload["host_identity"]["metal"]["device"] == "Apple M4"
    assert payload["synthetic_slice_mapping_gate"]["complete_output_bits_checked"] == 393_216

    execution = payload["execution"]
    assert execution["unknown_key_bits"] == 38
    assert execution["known_key_bits"] == 218
    assert execution["logical_candidate_count"] == 274_877_906_944
    assert execution["outer_low_bit_slice_count"] == 64
    assert execution["inner_word_candidate_count_per_slice"] == 4_294_967_296
    assert execution["stream_batch_count"] == 1_024
    assert execution["resumed_assignment_count"] == 0
    assert execution["newly_executed_assignment_count"] == 274_877_906_944
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [RECOVERED_COMBINED]
    assert execution["factual_full_matches"] == [RECOVERED_COMBINED]
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["unique_exact_assignment"] is True
    assert execution["control_target_rejected"] is True
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False

    confirmation = execution["factual_confirmations"]
    assert len(confirmation) == 1
    assert confirmation[0]["combined_assignment"] == RECOVERED_COMBINED
    assert confirmation[0]["key_word0"] == RECOVERED_WORD0
    assert confirmation[0]["key_word1_low_value"] == RECOVERED_LOW_VALUE
    assert confirmation[0]["complete_block_match"] is True
    assert confirmation[0]["output_bits_checked"] == 512
    assert confirmation[0]["candidate_block_sha256"] == (
        "d18e7c82b4aa873282c65b7ea22c436597865264048a18cf72253640078a1f09"
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
    assert recovery["recovered_key_word1_low_value"] == [RECOVERED_LOW_VALUE]
    assert recovery["first_reveal_occurs_after_complete_domain_execution"] is True
    assert recovery["unknown_assignment_source_was_discarded_before_runner_construction"]
    assert format(RECOVERED_COMBINED, "010x") == "1a15b63e04"
    assert format(RECOVERED_WORD0, "08x") == "15b63e04"
    assert payload["parameters"]["volatile_wallclock_excluded_from_canonical_result"] is True
    for volatile_field in ('"wallclock_seconds"', '"elapsed_seconds"', '"duration_seconds"'):
        assert volatile_field not in raw.decode().lower()
    assert CHECKPOINT_PATH.exists() is False


def test_retained_a183_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a182-width36-recovery-anchor",
        "chacha20-a183-fresh-width38-challenge-freeze",
        "chacha20-a183-two-word-slice-mapping-gate",
        "chacha20-a183-complete-width38-domain-execution",
        "chacha20-a183-independent-width38-recovery",
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
