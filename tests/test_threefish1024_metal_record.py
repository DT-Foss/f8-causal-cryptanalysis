from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/threefish1024_metal_record.py"


@pytest.fixture(scope="module")
def tf1024() -> Any:
    spec = importlib.util.spec_from_file_location("test_tf1024_record", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_and_official_zero_kat(tf1024: Any) -> None:
    design = tf1024.load_design()
    gate = tf1024.official_gate()
    assert design["primitive_contract"]["rounds"] == 80
    assert design["primitive_contract"]["block_bits"] == 1024
    assert design["qualification_contract"]["maximum_unknown_bits"] == 43
    assert gate["canonical_match"] is True
    assert gate["independent_match"] is True


def test_uint64_half_roundtrip(tf1024: Any) -> None:
    values = [0, 1, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF]
    assert tf1024.words(tf1024.halves(values)) == values


def test_independent_reference_matches_canonical_on_random_full_states(
    tf1024: Any,
) -> None:
    rng = random.Random(0x1024F8)
    for _ in range(8):
        plaintext = [rng.getrandbits(64) for _ in range(16)]
        key = [rng.getrandbits(64) for _ in range(16)]
        tweak = [rng.getrandbits(64) for _ in range(2)]
        assert tf1024.independent_encrypt(plaintext, key, tweak) == (
            tf1024.threefish1024_encrypt(plaintext, key, tweak, 80)
        )


@pytest.mark.parametrize("assignment", [0, 1, 0xFFFFFFFF, 1 << 32, (1 << 43) - 1])
def test_assignment_mapping_and_independent_reference(
    tf1024: Any, assignment: int
) -> None:
    width = 43
    base_key, tweak, plaintext, _ = tf1024.deterministic_material()
    base_key[0] &= tf1024.MASK64 ^ ((1 << width) - 1)
    key = tf1024.key_for_assignment(base_key, assignment, width)
    outer = assignment >> 32
    configured = tf1024.configured_key(base_key, outer, width)
    assert configured[0] | (assignment & tf1024.MASK32) == key[0]
    canonical = tf1024.threefish1024_encrypt(plaintext, key, tweak, 80)
    independent = tf1024.independent_encrypt(plaintext, key, tweak)
    assert canonical == independent


def test_freeze_hides_secret_and_preserves_public_relation(
    tf1024: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    qualification_path = tmp_path / "qualification.json"
    protocol_path = tmp_path / "protocol.json"
    qualification = {
        "schema": "threefish1024-metal-qualification-v1",
        "official_kat_gate": {"all_passed": True},
        "cross_implementation_gate": {
            "canonical_independent_Metal_exact": True
        },
        "boundary_filter_gate": {"exact": True},
        "information_boundary": {"production_target_exists": False},
        "selection": {"selected_width": 35},
    }
    qualification_path.write_text(json.dumps(qualification))
    qualification_sha = tf1024.file_sha256(qualification_path)
    monkeypatch.setattr(tf1024, "QUALIFICATION", qualification_path)
    monkeypatch.setattr(tf1024, "PROTOCOL", protocol_path)
    monkeypatch.setattr(tf1024, "RESULT", tmp_path / "result.json")
    monkeypatch.setattr(tf1024, "CHECKPOINT", tmp_path / "checkpoint.json")
    monkeypatch.setattr(tf1024, "CAUSAL", tmp_path / "result.causal")
    monkeypatch.setattr(tf1024, "REPORT", tmp_path / "result.md")
    assignment = 0x5A3C7D921
    monkeypatch.setattr(tf1024.secrets, "randbits", lambda width: assignment)
    frozen = tf1024.freeze(expected_qualification_sha256=qualification_sha)
    public = frozen["public_challenge"]
    assert public["unknown_key_bits"] == 35
    assert public["unknown_assignment_included"] is False
    assert public["unknown_assignment_value_included"] is False
    assert public["full_key_included"] is False
    serialized = protocol_path.read_text()
    assert str(assignment) not in serialized
    base_key = [
        public["known_key0_upper_bits"],
        *public["known_key_words_1_through_15"],
    ]
    expected = tf1024.threefish1024_encrypt(
        public["plaintext_words"],
        tf1024.key_for_assignment(base_key, assignment, 35),
        public["known_tweak_words"],
        80,
    )
    assert expected == public["target_ciphertext_words"]
    confirmation = tf1024.confirm(frozen, assignment)
    assert confirmation["complete_1024_bit_match"] is True
    assert confirmation["cross_implementation_output_bits_checked"] == 2048


def test_checkpoint_contract_starts_before_candidate_zero(
    tf1024: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text("{}")
    monkeypatch.setattr(tf1024, "PROTOCOL", protocol_path)
    protocol = {
        "public_challenge_sha256": "ab" * 32,
        "execution": {"logical_candidate_count": 1 << 37},
    }
    checkpoint = tf1024.checkpoint_base(protocol)
    assert checkpoint["next_assignment"] == 0
    assert checkpoint["factual_filtered"] == []
    assert checkpoint["control_filtered"] == []
    assert checkpoint["complete_domain_executed"] is False
    assert checkpoint["early_stop_used"] is False


def test_resume_executes_exact_tail_across_uint32_endpoint(
    tf1024: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text("{}")
    checkpoint_path = tmp_path / "checkpoint.json"
    monkeypatch.setattr(tf1024, "PROTOCOL", protocol_path)
    monkeypatch.setattr(tf1024, "CHECKPOINT", checkpoint_path)
    monkeypatch.setattr(tf1024, "STREAM_CANDIDATES", 4)
    domain = 1 << 32
    target_assignment = domain - 5
    protocol = {
        "public_challenge_sha256": "cd" * 32,
        "public_challenge": {
            "unknown_key_bits": 32,
            "known_key0_upper_bits": 0,
            "known_key_words_1_through_15": [0] * 15,
            "known_tweak_words": [0, 0],
            "plaintext_words": [0] * 16,
            "target_ciphertext_words": [0] * 16,
            "control_ciphertext_words": [1] + [0] * 15,
        },
        "execution": {"logical_candidate_count": domain},
    }
    state = tf1024.checkpoint_base(protocol)
    state["next_assignment"] = domain - 8
    tf1024.atomic_json(checkpoint_path, state)

    class FakeHost:
        def __init__(self) -> None:
            self.configurations: list[dict[str, Any]] = []
            self.intervals: list[tuple[int, int]] = []

        def configure(self, **kwargs: Any) -> None:
            self.configurations.append(kwargs)

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.intervals.append((first, count))
            factual = (
                [target_assignment]
                if first <= target_assignment < first + count
                else []
            )
            return {
                "factual": factual,
                "control": [],
                "gpu_seconds": 0.25,
            }

    host = FakeHost()
    monkeypatch.setattr(
        tf1024,
        "confirm",
        lambda _protocol, assignment: {"assignment": assignment, "confirmed": True},
    )
    result = tf1024.enumerate_domain(host=host, protocol=protocol, resume=True)
    assert host.intervals == [(domain - 8, 4), (domain - 4, 4)]
    assert len(host.configurations) == 1
    assert result["resumed_assignment_count"] == domain - 8
    assert result["newly_executed_assignment_count"] == 8
    assert result["factual_full_matches"] == [target_assignment]
    assert result["control_full_matches"] == []
    assert result["complete_domain_executed"] is True


def test_authentic_causal_artifact_roundtrip(
    tf1024: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    causal_path = tmp_path / "tf1024kr1.causal"
    monkeypatch.setattr(tf1024, "CAUSAL", causal_path)
    payload = {
        "execution_sha256": "11" * 32,
        "confirmation_sha256": "22" * 32,
        "execution": {
            "logical_candidate_count": 1 << 32,
            "factual_filter_matches": [0x12345678],
            "factual_confirmations": [
                {"assignment": 0x12345678, "complete_1024_bit_match": True}
            ],
        },
    }
    graph = tf1024.build_causal(payload)
    assert graph["api_id"] == "tf1024k1"
    assert graph["triplets"] == 6
    assert graph["rules"] == 2
    assert graph["clusters"] == 2
    assert len(graph["gaps"]) == 1
    assert graph["sha256"] == tf1024.file_sha256(causal_path)
