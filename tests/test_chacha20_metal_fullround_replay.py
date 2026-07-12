from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = (
    Path(__file__).parents[1] / "research" / "experiments" / "chacha20_metal_fullround_replay.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_metal_fullround_replay_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "chacha20_metal_fullround_replay_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_metal_fullround_replay_v1.causal"
CHECKPOINT_PATH = RESULTS_DIR / "chacha20_metal_fullround_replay_v1.checkpoint.json"
RESULT_SHA256 = "f58e24cdb76a90ce8cd0ea2a14adce98ffa8f760707f9ea169d5a8d2748bacee"
CAUSAL_SHA256 = "b16a7a2fc0fc78084443ee5ada8fb9a2c6fa9149f5b6333d98764401a07f662e"
CAUSAL_GRAPH_SHA256 = "00e13f58cdb6382c390a978401dc3a6217d98dcc1fa608f96fc6cec37fa5c1a8"
EXECUTION_SHA256 = "9e51013009ae313ee00ea624cd4a81e0e4fe3e8ef319cd4daf2a8e9cd66cf3a6"
EQUIVALENCE_SHA256 = "e02b59ec226de5cf37792b0ca03b3b4e1695c3396ad83eb9a4485eb960577004"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


@pytest.fixture(scope="module")
def metal_host(
    tmp_path_factory: pytest.TempPathFactory,
    analysis: dict[str, Any],
) -> Iterator[tuple[MODULE.MetalChaCha20Host, dict[str, Any]]]:
    if sys.platform != "darwin":
        pytest.skip("native Swift/Metal host requires macOS")
    executable, build = MODULE._compile_native(
        tmp_path_factory.mktemp("chacha-metal"),
        "swiftc",
    )
    host = MODULE.MetalChaCha20Host(
        executable,
        analysis["initial_template"],
        analysis["target"],
        analysis["control_target"],
    )
    try:
        yield host, build
    finally:
        host.close()


def test_protocol_freezes_metal_replay_before_complete_domain_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "9bc042c28256d3da46b9c1f5cf0b7d81b52035d0df67d40d7d32848492eaef2d"
    )
    assert protocol["protocol_state"] == (
        "frozen_after_small_cross_gates_and_throughput_qualification_before_any_A181_complete_domain_execution"
    )
    assert protocol["anchors"]["A179"]["sha256"] == MODULE.A179_SHA256
    assert protocol["anchors"]["A179"]["causal_sha256"] == MODULE.A179_CAUSAL_SHA256
    assert protocol["native_host"]["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    qualification = protocol["pre_freeze_implementation_qualification"]
    assert qualification["exact_scalar_identity"] is True
    assert qualification["complete_domain_execution_performed"] is False
    assert qualification["throughput_is_not_part_of_the_success_rule"] is True
    assert qualification["volatile_median_candidates_per_second"] == pytest.approx(
        1_469_068_029.6250117
    )
    boundary = protocol["information_boundary"]
    assert boundary["A179_recovery_outcome_known_at_A181_freeze"] is True
    assert boundary["A179_recovered_word_used_to_prune_or_stop_GPU_enumeration"] is False
    assert boundary["A179_recovered_word_used_only_after_complete_domain_for_equivalence_gate"]
    assert boundary["A181_complete_domain_outcome_used_before_freeze"] is False
    assert analysis["candidate_execution_started"] is False


def test_public_challenge_and_metal_execution_plan_are_hash_bound(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._canonical_sha256(analysis["public_challenge"]) == (MODULE.PUBLIC_RELATION_SHA256)
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == (
        "49607cf3600a9f59bc41984094a5ee33bea30511817056f1543735ab72737cda"
    )
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 20
    assert plan["logical_candidate_count"] == 4_294_967_296
    assert plan["gpu_logical_thread_count"] == 4_294_967_296
    assert plan["gpu_threads_per_candidate"] == 1
    assert plan["stream_candidate_count"] == 268_435_456
    assert plan["stream_batch_count"] == 16
    assert plan["metal_thread_execution_width"] == 32
    assert plan["threads_per_threadgroup"] == 256
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["runtime_shader_compilation"] is True
    assert plan["replays_A178_public_challenge"] is True


def test_swift_source_warning_gate_and_host_identity_are_exact(
    metal_host: tuple[MODULE.MetalChaCha20Host, dict[str, Any]],
) -> None:
    host, build = metal_host
    source = MODULE_PATH.with_name(MODULE.NATIVE_SOURCE_FILENAME)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == MODULE.NATIVE_SOURCE_SHA256
    assert build["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    assert build["host_language"] == "Swift_6"
    assert build["shader_language"] == "Metal_Shading_Language_runtime_compiled"
    assert build["selected_flags"] == [
        "-O",
        "-whole-module-optimization",
        "-warnings-as-errors",
    ]
    assert build["warnings_as_errors"] is True
    assert host.identity["version"] == MODULE.NATIVE_VERSION
    assert host.identity["metal"]["device"] == "Apple M4"
    assert host.identity["metal"]["filter_execution_width"] == 32
    assert host.identity["metal"]["filter_max_threads_per_group"] >= 256
    assert host.identity["metal"]["shader_runtime_compiled"] is True


def test_metal_256_block_and_three_boundary_gates_are_exact(
    analysis: dict[str, Any],
    metal_host: tuple[MODULE.MetalChaCha20Host, dict[str, Any]],
) -> None:
    host, _build = metal_host
    cross = MODULE._cross_implementation_gate(
        host,
        analysis["protocol"],
        analysis["initial_template"],
    )
    assert cross["first_candidate"] == 123_456_789
    assert cross["states"] == 256
    assert cross["words_checked"] == 4_096
    assert cross["state_bits_checked"] == 131_072
    assert cross["exact_match"] is True
    assert cross["output_sha256"] == (
        "eacb62b978ae444278f0034793ce5ad9c31bfdbed02735053f1b2697d9e8600c"
    )

    boundary = MODULE._boundary_filter_gate(host, analysis["protocol"])
    assert boundary["intervals_checked"] == 3
    assert boundary["logical_candidates_checked"] == 768
    assert boundary["exact_expected_identity"] is True
    assert [row["first_candidate"] for row in boundary["rows"]] == [
        0,
        2_419_963_591,
        4_294_967_040,
    ]
    assert [row["factual_matches"] for row in boundary["rows"]] == [
        [],
        [2_419_963_719],
        [],
    ]
    assert all(row["control_matches"] == [] for row in boundary["rows"])


def test_metal_executor_supports_complete_resume_without_early_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    analysis: dict[str, Any],
) -> None:
    monkeypatch.setattr(MODULE, "WINDOW_BITS", 10)
    monkeypatch.setattr(MODULE, "STREAM_CANDIDATES", 256)

    class FakeHost:
        calls: list[tuple[int, int]] = []

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.calls.append((first, count))
            return {
                "factual": [5] if first == 0 else [],
                "control": [],
            }

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
            "next_candidate": 0,
            "factual_filtered": [],
            "control_filtered": [],
        },
    )
    host = FakeHost()
    result = MODULE._enumerate_key_word(
        host=host,
        initial=analysis["initial_template"],
        target=analysis["target"],
        control=analysis["control_target"],
        challenge=analysis["public_challenge"],
        checkpoint_path=checkpoint,
        resume=True,
    )
    assert result["logical_candidate_count"] == 1_024
    assert result["stream_batch_count"] == 4
    assert result["resumed_candidate_count"] == 0
    assert result["newly_executed_candidate_count"] == 1_024
    assert result["complete_domain_executed"] is True
    assert result["early_stop_used"] is False
    assert result["factual_filter_matches"] == [5]
    assert result["factual_full_matches"] == [5]
    assert result["control_full_matches"] == []
    assert result["A179_recovered_word_used_to_prune_or_stop_GPU_enumeration"] is False
    assert host.calls == [(0, 256), (256, 256), (512, 256), (768, 256)]


def test_retained_a181_result_and_equivalence_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A181"
    assert payload["evidence_stage"] == (
        "CHACHA20_FULLROUND_METAL_COMPLETE_DOMAIN_EQUIVALENCE_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A179_result_sha256"] == MODULE.A179_SHA256
    assert payload["anchor_gates"]["A179_causal_sha256"] == MODULE.A179_CAUSAL_SHA256
    assert payload["anchor_gates"]["Metal_native_source_sha256"] == (MODULE.NATIVE_SOURCE_SHA256)
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["native_build"]["warnings_as_errors"] is True
    assert payload["host_identity"]["metal"]["device"] == "Apple M4"
    assert payload["native_cross_implementation_gate"]["state_bits_checked"] == 131_072
    assert payload["native_boundary_filter_gate"]["intervals_checked"] == 3

    execution = payload["execution"]
    assert execution["logical_candidate_count"] == 4_294_967_296
    assert execution["gpu_logical_thread_count"] == 4_294_967_296
    assert execution["stream_candidate_count"] == 268_435_456
    assert execution["stream_batch_count"] == 16
    assert execution["resumed_candidate_count"] == 0
    assert execution["newly_executed_candidate_count"] == 4_294_967_296
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [2_419_963_719]
    assert execution["factual_full_matches"] == [2_419_963_719]
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["factual_confirmations"][0]["output_bits_checked"] == 512
    assert execution["factual_confirmations"][0]["candidate_block_sha256"] == (
        "0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae"
    )
    assert execution["A179_recovered_word_used_to_prune_or_stop_GPU_enumeration"] is False

    execution_digest_input = {
        key: value
        for key, value in execution.items()
        if key not in {"factual_confirmations", "control_confirmations"}
    }
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert MODULE._canonical_sha256(execution_digest_input) == EXECUTION_SHA256
    equivalence = payload["equivalence"]
    assert equivalence == {
        "A179_recovered_key_word": 2_419_963_719,
        "A181_control_full_matches": [],
        "A181_factual_filter_matches": [2_419_963_719],
        "A181_factual_full_matches": [2_419_963_719],
        "complete_domain_executed": True,
        "control_target_rejected": True,
        "early_stop_used": False,
        "exact_A179_recovery_identity": True,
        "independent_confirmation_bits": 512,
    }
    assert payload["equivalence_sha256"] == EQUIVALENCE_SHA256
    assert MODULE._canonical_sha256(equivalence) == EQUIVALENCE_SHA256
    assert payload["parameters"]["volatile_wallclock_excluded_from_canonical_result"] is True
    for volatile_field in ('"wallclock_seconds"', '"elapsed_seconds"', '"duration_seconds"'):
        assert volatile_field not in raw.decode().lower()
    assert CHECKPOINT_PATH.exists() is False


def test_retained_a181_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a179-complete-domain-anchor",
        "chacha20-a181-metal-protocol-freeze",
        "chacha20-a181-metal-native-equivalence",
        "chacha20-a181-metal-complete-domain-replay",
        "chacha20-a181-fullround-metal-equivalence",
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
