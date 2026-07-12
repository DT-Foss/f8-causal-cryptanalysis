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
    / "chacha20_vector256_fullround_replay.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_vector256_fullround_replay_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "chacha20_vector256_fullround_replay_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_vector256_fullround_replay_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "chacha20_vector256_fullround_replay_v1.checkpoint.json"
RESULT_SHA256 = "73874897bf3747a0c640e00e5325f9c0502d2db7b77f6fe01590c87494f7fb93"
CAUSAL_SHA256 = "ab627294751d40647d3b1c9d5f20d852195d64fa449dea761b8cad15b24291a1"
CAUSAL_GRAPH_SHA256 = "1681bf6f2647e7545a2f56163774ac7e4220fc0df171dbc9569e7eda63c5957d"
EXECUTION_SHA256 = "caec14a08dc9798b8a5230bb94f97727ba413ad1963cbd1bae06194b304b5e1e"
EQUIVALENCE_SHA256 = "ab44522328a109f8089b801c09b4515257c0a89d2373c49963c439998a5a0b45"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


@pytest.fixture(scope="module")
def native_kernels(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[
    MODULE.NativeChaCha20Vector256Kernel,
    MODULE._A178.NativeChaCha20Kernel,
    dict[str, Any],
]:
    root = tmp_path_factory.mktemp("chacha-vector256")
    v2_path, v2_build = MODULE._compile_native(root / "v2", "cc")
    v1_path, _v1_build = MODULE._A178._compile_native(root / "v1", "cc")
    return (
        MODULE.NativeChaCha20Vector256Kernel(v2_path),
        MODULE._A178.NativeChaCha20Kernel(v1_path),
        v2_build,
    )


def test_protocol_freezes_complete_domain_replay_after_only_small_gates(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "fc552a21f14a827293996cdff6707dd7b31ac6ffdcc18cc55ac45b624d784e40"
    )
    assert protocol["protocol_state"] == (
        "frozen_after_small_implementation_gates_before_any_A179_complete_domain_execution"
    )
    assert protocol["anchors"]["A178"]["sha256"] == MODULE.A178_SHA256
    assert protocol["anchors"]["A178"]["causal_sha256"] == MODULE.A178_CAUSAL_SHA256
    assert protocol["native_kernel"]["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    qualification = protocol["pre_freeze_implementation_qualification"]
    assert qualification["strict_C11_compile_with_Wall_Wextra_Wpedantic_Werror"] is True
    assert qualification["exact_scalar_identity"] is True
    assert qualification["complete_domain_execution_performed"] is False
    boundary = protocol["information_boundary"]
    assert boundary["A178_recovery_outcome_known_at_A179_freeze"] is True
    assert boundary["A178_recovered_word_used_to_prune_or_stop_enumeration"] is False
    assert boundary["A178_recovered_word_used_only_after_complete_domain_for_equivalence_gate"]
    assert boundary["A179_complete_domain_outcome_used_before_freeze"] is False
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_and_vector_execution_plan_are_hash_bound(
    analysis: dict[str, Any],
) -> None:
    assert (
        analysis["public_challenge"]
        == json.loads((RESULTS_DIR / MODULE.A178_FILENAME).read_bytes())["public_challenge"]
    )
    assert MODULE._canonical_sha256(analysis["public_challenge"]) == (MODULE.PUBLIC_RELATION_SHA256)
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "0fbeaf04432d70f81aa2c4f144b43f8c61ec6c74199a683495c0e10c22a66f63"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 20
    assert plan["logical_candidate_count"] == 4_294_967_296
    assert plan["logical_candidates_per_vector_state"] == 256
    assert plan["uint64_sublanes_per_vector_state"] == 4
    assert plan["vector_state_count"] == 16_777_216
    assert plan["A178_uint64_pack_count"] == 67_108_864
    assert plan["structural_vector_state_reduction_factor"] == 4
    assert plan["stream_batch_count"] == 64
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["replays_A178_public_challenge"] is True


def test_vector_source_and_strict_build_are_exact(
    native_kernels: tuple[
        MODULE.NativeChaCha20Vector256Kernel,
        MODULE._A178.NativeChaCha20Kernel,
        dict[str, Any],
    ],
) -> None:
    _v2, _v1, build = native_kernels
    source = MODULE_PATH.with_name(MODULE.NATIVE_SOURCE_FILENAME)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == MODULE.NATIVE_SOURCE_SHA256
    assert build["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert build["logical_candidate_width"] == 256
    assert build["uint64_sublanes"] == 4
    assert build["strict_warning_gate"] is True
    for flag in ("-Wall", "-Wextra", "-Wpedantic", "-Werror"):
        assert flag in build["selected_flags"]


def test_vector256_block_and_boundary_masks_match_scalar_exactly(
    analysis: dict[str, Any],
    native_kernels: tuple[
        MODULE.NativeChaCha20Vector256Kernel,
        MODULE._A178.NativeChaCha20Kernel,
        dict[str, Any],
    ],
) -> None:
    v2, _v1, _build = native_kernels
    cross = MODULE._cross_implementation_gate(v2, analysis["protocol"])
    assert cross["states"] == 256
    assert cross["words_checked"] == 4_096
    assert cross["state_bits_checked"] == 131_072
    assert cross["exact_match"] is True
    assert cross["input_sha256"] == (
        "4988b523384fb1b19bd10c69d84b1a107bcc0d47066b274a71878b342872819c"
    )
    assert cross["output_sha256"] == (
        "6c52fa41d8c972bd016af82afdbb4084ffe9177f9fd2b27eff4c64d8f4800947"
    )

    boundary = MODULE._boundary_mask_gate(v2, analysis["protocol"])
    assert boundary["logical_candidates_checked"] == 1_024
    assert boundary["vector_packs_checked"] == [0, 1, 257, 16_777_215]
    assert boundary["exact_scalar_identity"] is True
    assert [row["first_candidate"] for row in boundary["boundary_rows"]] == [
        0,
        256,
        65_792,
        4_294_967_040,
    ]
    assert all(row["exact_scalar_identity"] for row in boundary["boundary_rows"])


def test_vector256_and_a178_uint64_filters_are_exactly_equivalent(
    analysis: dict[str, Any],
    native_kernels: tuple[
        MODULE.NativeChaCha20Vector256Kernel,
        MODULE._A178.NativeChaCha20Kernel,
        dict[str, Any],
    ],
) -> None:
    v2, v1, _build = native_kernels
    gate = MODULE._v1_v2_filter_equivalence_gate(
        v1=v1,
        v2=v2,
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
    )
    assert gate["logical_candidates_checked"] == 768
    assert gate["vector_packs_checked"] == [0, 9_452_983, 16_777_215]
    assert gate["exact_v1_v2_identity"] is True
    assert all(row["exact_v1_v2_identity"] for row in gate["rows"])


def test_vector_executor_supports_complete_resume_without_early_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    analysis: dict[str, Any],
) -> None:
    monkeypatch.setattr(MODULE, "WINDOW_BITS", 10)
    monkeypatch.setattr(MODULE, "STREAM_VECTOR_STATES", 2)
    monkeypatch.setattr(MODULE, "THREADS", 1)

    class FakeKernel:
        calls: list[tuple[int, int]] = []

        def filter_masks(
            self,
            _initial: np.ndarray,
            first_vector_pack: int,
            vector_pack_count: int,
            _target: np.ndarray,
            _control: np.ndarray,
            _filter_words: int,
            _threads: int,
        ) -> tuple[np.ndarray, np.ndarray]:
            self.calls.append((first_vector_pack, vector_pack_count))
            factual = np.zeros(vector_pack_count * 4, dtype=np.uint64)
            control = np.zeros(vector_pack_count * 4, dtype=np.uint64)
            if first_vector_pack == 0:
                factual[0] = np.uint64(1 << 5)
            return factual, control

    monkeypatch.setattr(
        MODULE._A178,
        "_independent_confirm",
        lambda _initial, _target, candidate: {
            "candidate_key_word": candidate,
            "complete_block_match": candidate == 5,
        },
    )
    checkpoint = tmp_path / "checkpoint.json"
    MODULE._A178._A177._NATIVE._atomic_json(
        checkpoint,
        {
            **MODULE._checkpoint_fingerprint(analysis["public_challenge"]),
            "next_vector_state": 0,
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
    assert result["logical_candidate_count"] == 1_024
    assert result["vector_state_count"] == 4
    assert result["complete_domain_executed"] is True
    assert result["early_stop_used"] is False
    assert result["factual_filter_matches"] == [5]
    assert result["factual_full_matches"] == [5]
    assert result["control_full_matches"] == []
    assert result["structural_vector_state_reduction_factor_vs_A178"] == 4.0
    assert result["A178_recovered_word_used_to_prune_or_stop_enumeration"] is False
    assert FakeKernel.calls == [(0, 2), (2, 2)]


def test_retained_a179_result_and_equivalence_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A179"
    assert payload["evidence_stage"] == (
        "CHACHA20_FULLROUND_VECTOR256_COMPLETE_DOMAIN_EQUIVALENCE_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A178_result_sha256"] == MODULE.A178_SHA256
    assert payload["anchor_gates"]["A178_causal_sha256"] == MODULE.A178_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]

    execution = payload["execution"]
    assert execution["logical_candidate_count"] == 4_294_967_296
    assert execution["logical_candidates_per_vector_state"] == 256
    assert execution["vector_state_count"] == 16_777_216
    assert execution["A178_uint64_pack_count"] == 67_108_864
    assert execution["stream_batch_count"] == 64
    assert execution["resumed_vector_state_count"] == 0
    assert execution["newly_executed_vector_state_count"] == 16_777_216
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [2_419_963_719]
    assert execution["factual_full_matches"] == [2_419_963_719]
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["structural_vector_state_reduction_factor_vs_A178"] == 4.0
    assert execution["A178_recovered_word_used_to_prune_or_stop_enumeration"] is False
    assert execution["factual_confirmations"][0]["output_bits_checked"] == 512
    assert execution["factual_confirmations"][0]["candidate_block_sha256"] == (
        "0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae"
    )

    execution_digest_input = {
        key: value
        for key, value in execution.items()
        if key not in {"factual_confirmations", "control_confirmations"}
    }
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert MODULE._canonical_sha256(execution_digest_input) == EXECUTION_SHA256
    equivalence = payload["equivalence"]
    assert equivalence == {
        "A178_recovered_key_word": 2_419_963_719,
        "A178_uint64_pack_count": 67_108_864,
        "A179_control_full_matches": [],
        "A179_factual_filter_matches": [2_419_963_719],
        "A179_factual_full_matches": [2_419_963_719],
        "A179_vector_state_count": 16_777_216,
        "complete_domain_executed": True,
        "control_target_rejected": True,
        "early_stop_used": False,
        "exact_A178_recovery_identity": True,
        "exact_vector_state_reduction_factor": 4.0,
    }
    assert payload["equivalence_sha256"] == EQUIVALENCE_SHA256
    assert MODULE._canonical_sha256(equivalence) == EQUIVALENCE_SHA256
    assert payload["parameters"]["volatile_wallclock_excluded_from_canonical_result"] is True
    for volatile_field in ('"wallclock_seconds"', '"elapsed_seconds"', '"duration_seconds"'):
        assert volatile_field not in raw.decode().lower()
    assert CHECKPOINT_PATH.exists() is False


def test_retained_a179_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a178-full-domain-recovery-anchor",
        "chacha20-a179-vector256-protocol-freeze",
        "chacha20-a179-vector256-native-equivalence",
        "chacha20-a179-vector256-complete-domain-replay",
        "chacha20-a179-fullround-vector-packing-advance",
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
