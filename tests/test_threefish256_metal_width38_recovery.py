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
    / "threefish256_metal_width38_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "threefish256_metal_width38_recovery_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESEARCH_ROOT = Path(__file__).parents[1] / "research"
RESULTS_DIR = RESEARCH_ROOT / "results" / "v1"
PROTOCOL_PATH = RESEARCH_ROOT / "configs" / MODULE.PROTOCOL_FILENAME


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(results_dir=RESULTS_DIR)


@pytest.fixture(scope="module")
def metal_host(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[MODULE._QUAL.MetalThreefish256Host]:
    executable, _build = MODULE._QUAL._compile_native(
        tmp_path_factory.mktemp("threefish256-metal-width38"), "swiftc"
    )
    host = MODULE._QUAL.MetalThreefish256Host(executable)
    try:
        yield host
    finally:
        host.close()


def test_protocol_is_hash_bound_secret_free_and_complete(
    analysis: dict[str, Any],
) -> None:
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == (
        MODULE.PROTOCOL_SHA256
    )
    protocol = analysis["protocol"]
    assert protocol["protocol_state"] == "frozen_before_any_A240_candidate_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert analysis["candidate_execution_started"] is False

    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["unknown_assignment_bits"] == 38
    assert challenge["known_master_key_bits"] == 218
    assert challenge["known_key0_upper26"] & ((1 << 38) - 1) == 0
    assert challenge["unknown_assignment_included"] is False
    target = np.array(challenge["target_ciphertext_words"], dtype="<u8")
    control = np.array(challenge["control_ciphertext_words"], dtype="<u8")
    assert np.count_nonzero(target ^ control) == 1
    assert int(target[-1] ^ control[-1]) == 1

    plan = analysis["execution_plan"]
    assert plan["rounds"] == 72
    assert plan["logical_candidate_count"] == 2**38
    assert plan["outer_key0_bits32_37_slice_count"] == 64
    assert plan["stream_candidate_count"] == 2**28
    assert plan["stream_batch_count"] == 1024
    assert plan["filter_output_bits"] == 256
    assert plan["complete_domain_required"] is True
    assert plan["early_stop_used"] is False


def test_real_metal_host_matches_three_outer_slices(
    analysis: dict[str, Any],
    metal_host: MODULE._QUAL.MetalThreefish256Host,
) -> None:
    gate = MODULE._mapping_gate(metal_host, analysis["public_challenge"])
    assert gate["outer_values_checked"] == [0, 32, 63]
    assert gate["logical_candidates_checked"] == 768
    assert gate["complete_output_bits_checked"] == 196_608
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
            "complete_block_match": assignment == 5,
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
    payload = {
        "execution": {
            "factual_full_matches": [5],
            "control_full_matches": [],
        },
        "execution_sha256": "1" * 64,
        "confirmation_sha256": "2" * 64,
    }
    path = tmp_path / "a240.causal"
    result = MODULE._build_causal(path, payload, MODULE.DEFAULT_DOTCAUSAL_SRC)
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["format"] == "authentic_dotcausal_v1_AI_native"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["embedded_rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"] == 1
    assert result["amplified_state_materialized_in_file"] is True
    assert result["integrity_verified_by_authoritative_reader"] is True
