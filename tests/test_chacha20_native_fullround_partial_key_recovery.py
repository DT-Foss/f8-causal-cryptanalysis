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
    / "chacha20_native_fullround_partial_key_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_native_fullround_partial_key_recovery_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "chacha20_native_fullround_partial_key_recovery_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_native_fullround_partial_key_recovery_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "chacha20_native_fullround_partial_key_recovery_v1.checkpoint.json"
RESULT_SHA256 = "80fee52a0a2222efab161d74eb7ee124f6d94b56ca0cf759c5ffc4ca2881bea1"
CAUSAL_SHA256 = "94c651c6ea5432f482c054ae6d839c84563e8eae81e98625beb158344da16995"
CAUSAL_GRAPH_SHA256 = "cea6f5b1c277a875be22f5e76744a2a42cbe73aa1e042a8018201bf4416a156a"
EXECUTION_SHA256 = "2cd7a5c3eda73eb7b467b6dd7ce57bdb139da9d679b680c9bef72ddeec07993c"
CONFIRMATION_SHA256 = "3f1d3d4e33c21b093c7b76d962e3d0f3defe4ac310c840fdaa10dd3ecc98b8a4"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


@pytest.fixture(scope="module")
def native_kernel(
    tmp_path_factory: pytest.TempPathFactory,
) -> MODULE.NativeChaCha20Kernel:
    path, build = MODULE._compile_native(
        tmp_path_factory.mktemp("chacha-native"),
        "cc",
    )
    assert build["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    return MODULE.NativeChaCha20Kernel(path)


def test_protocol_freezes_public_key_challenge_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "4fb2d61f104d5aa424b7ba269fad446e086025fe40dcf4091d1335b71f729573"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A178_candidate_execution"
    assert protocol["anchors"]["A177"]["sha256"] == MODULE.A177_SHA256
    assert protocol["anchors"]["A119"]["sha256"] == MODULE.A119_SHA256
    assert protocol["native_kernel"]["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "fullround_32_bit_partial_key_recovery"
    )
    assert protocol["information_boundary"]["unknown_key_word_in_protocol_or_source"] is False
    assert (
        protocol["information_boundary"]["unknown_key_word_available_to_runner_before_execution"]
        is False
    )
    assert (
        protocol["information_boundary"]["A178_candidate_outcomes_used_before_protocol_freeze"]
        is False
    )
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_contains_only_known_complement_and_target(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_RELATION_SHA256
    assert challenge["unknown_key_word_index"] == 0
    assert challenge["unknown_initial_lane"] == 4
    assert challenge["unknown_word_included"] is False
    assert challenge["unknown_word_generation"] == (
        "os_cryptographic_randomness_used_once_then_discarded"
    )
    assert len(challenge["known_key_words_1_through_7"]) == 7
    assert len(challenge["nonce_words"]) == 3
    assert len(challenge["target_words"]) == 16
    assert challenge["control_target_words"][0] == (challenge["target_words"][0] ^ 1)
    assert challenge["control_target_words"][1:] == challenge["target_words"][1:]
    assert challenge["target_block_sha256"] == (
        "0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae"
    )
    assert challenge["control_target_block_sha256"] == (
        "5e346bbcce4f88533f842f53c638d68a6c3b60d07a132ed1b01ae309dd7d6cce"
    )
    initial = analysis["initial_template"]
    assert initial.shape == (16,)
    assert int(initial[4]) == 0
    assert initial[5:12].tolist() == challenge["known_key_words_1_through_7"]
    assert int(initial[12]) == challenge["counter"]
    assert initial[13:16].tolist() == challenge["nonce_words"]


def test_complete_partial_key_plan_is_hash_bound(analysis: dict[str, Any]) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "d386bc846e4098fddd104431e23aa1f59d434ea8e1b68f8495b3459567e019be"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["primitive"] == "ChaCha20_block_function"
    assert plan["rounds"] == 20
    assert plan["known_key_bits"] == 224
    assert plan["unknown_key_word_bits"] == 32
    assert plan["logical_candidate_count"] == 4_294_967_296
    assert plan["packed_state_count"] == 67_108_864
    assert plan["stream_batch_count"] == 64
    assert plan["filter_output_bits"] == 64
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["checkpoint_resume_enabled"] is True


def test_native_kernel_matches_rfc_reference_and_scalar_masks(
    native_kernel: MODULE.NativeChaCha20Kernel,
) -> None:
    kat = MODULE._A119._kat()
    assert kat["match"] is True
    cross = MODULE._cross_implementation_gate(native_kernel, 178_032)
    assert cross["exact_match"] is True
    assert cross["states"] == 64
    assert cross["state_bits_checked"] == 32_768
    mask = MODULE._small_mask_gate(native_kernel, 178_064)
    assert mask["logical_candidates"] == 256
    assert mask["factual_assignment"] == 173
    assert mask["exact_native_scalar_identity"] is True


def test_complete_domain_executor_supports_resume_without_early_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    analysis: dict[str, Any],
) -> None:
    monkeypatch.setattr(MODULE, "WINDOW_BITS", 8)
    monkeypatch.setattr(MODULE, "STREAM_PACKS", 2)
    monkeypatch.setattr(MODULE, "THREADS", 1)

    class FakeKernel:
        calls: list[tuple[int, int]] = []

        def filter_masks(
            self,
            _initial: np.ndarray,
            first_pack: int,
            pack_count: int,
            _target: np.ndarray,
            _control: np.ndarray,
            _filter_words: int,
            _threads: int,
        ) -> tuple[np.ndarray, np.ndarray]:
            self.calls.append((first_pack, pack_count))
            factual = np.zeros(pack_count, dtype=np.uint64)
            control = np.zeros(pack_count, dtype=np.uint64)
            if first_pack == 0:
                factual[0] = np.uint64(1 << 5)
            return factual, control

    monkeypatch.setattr(
        MODULE,
        "_independent_confirm",
        lambda _initial, _target, candidate: {
            "candidate_key_word": candidate,
            "complete_block_match": candidate == 5,
        },
    )
    checkpoint = tmp_path / "checkpoint.json"
    fingerprint = MODULE._checkpoint_fingerprint(analysis["public_challenge"])
    MODULE._A177._NATIVE._atomic_json(
        checkpoint,
        {
            **fingerprint,
            "next_pack": 0,
            "factual_filtered": [],
            "control_filtered": [],
        },
    )
    result = MODULE._enumerate_key_word(
        kernel=FakeKernel(),
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
        challenge=analysis["public_challenge"],
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
    assert result["unique_exact_key_word"] is True
    assert result["control_target_rejected"] is True
    assert result["unknown_key_word_available_to_runner_before_execution"] is False
    assert FakeKernel.calls == [(0, 2), (2, 2)]


def test_native_source_hash_and_public_target_bytes_are_stable(
    analysis: dict[str, Any],
) -> None:
    source = MODULE_PATH.with_name(MODULE.NATIVE_SOURCE_FILENAME)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == MODULE.NATIVE_SOURCE_SHA256
    target = analysis["target"].astype("<u4", copy=False).tobytes()
    control = analysis["control_target"].astype("<u4", copy=False).tobytes()
    assert hashlib.sha256(target).hexdigest() == analysis["public_challenge"]["target_block_sha256"]
    assert (
        hashlib.sha256(control).hexdigest()
        == analysis["public_challenge"]["control_target_block_sha256"]
    )


def test_retained_a178_artifact_is_hash_pinned_and_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)

    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A178"
    assert payload["evidence_stage"] == ("CHACHA20_FULLROUND_32BIT_PARTIAL_KEY_RECOVERY_RETAINED")
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A177_result_sha256"] == MODULE.A177_SHA256
    assert payload["anchor_gates"]["A119_result_sha256"] == MODULE.A119_SHA256
    assert payload["anchor_gates"]["A119_causal_sha256"] == MODULE.A119_CAUSAL_SHA256
    assert payload["anchor_gates"]["native_source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["execution_plan_sha256"] == (
        "d386bc846e4098fddd104431e23aa1f59d434ea8e1b68f8495b3459567e019be"
    )

    assert payload["kat"]["match"] is True
    cross = payload["native_cross_implementation_gate"]
    assert cross["states"] == 64
    assert cross["words_checked"] == 1_024
    assert cross["state_bits_checked"] == 32_768
    assert cross["exact_match"] is True
    mask = payload["native_scalar_mask_gate"]
    assert mask["logical_candidates"] == 256
    assert mask["packed_states"] == 4
    assert mask["factual_assignment"] == 173
    assert mask["exact_native_scalar_identity"] is True

    execution = payload["execution"]
    assert execution["unknown_key_word_index"] == 0
    assert execution["unknown_initial_lane"] == 4
    assert execution["logical_candidate_count"] == 4_294_967_296
    assert execution["candidate_pack_width"] == 64
    assert execution["packed_state_count"] == 67_108_864
    assert execution["stream_pack_count"] == 1_048_576
    assert execution["stream_batch_count"] == 64
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["resumed_pack_count"] == 0
    assert execution["newly_executed_pack_count"] == 67_108_864
    assert execution["filter_output_bits"] == 64
    assert execution["factual_filter_matches"] == [2_419_963_719]
    assert execution["factual_full_matches"] == [2_419_963_719]
    assert format(execution["factual_full_matches"][0], "08x") == "903db747"
    assert execution["unique_exact_key_word"] is True
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["control_target_rejected"] is True
    assert execution["unknown_key_word_available_to_runner_before_execution"] is False

    assert len(execution["factual_confirmations"]) == 1
    confirmation = execution["factual_confirmations"][0]
    assert confirmation["candidate_key_word"] == 2_419_963_719
    assert confirmation["complete_block_match"] is True
    assert confirmation["output_words_checked"] == 16
    assert confirmation["output_bits_checked"] == 512
    assert confirmation["implementation"] == "independent_NumPy_RFC8439_ChaCha20_core"
    assert confirmation["candidate_block_sha256"] == (
        "0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae"
    )
    assert confirmation["candidate_block_sha256"] == confirmation["target_block_sha256"]
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

    recovery = payload["recovery"]
    assert recovery["recovered_key_word_index"] == 0
    assert recovery["recovered_key_words"] == [2_419_963_719]
    assert recovery["first_reveal_occurs_after_complete_domain_execution"] is True
    assert recovery["unknown_word_source_was_discarded_before_runner_construction"] is True
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


def test_retained_a178_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a119-fullround-feedforward-anchor",
        "chacha20-a178-public-partial-key-challenge",
        "chacha20-a178-native-candidate-axis-reader",
        "chacha20-a178-complete-keyword-domain-execution",
        "chacha20-a178-independent-partial-key-recovery",
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
