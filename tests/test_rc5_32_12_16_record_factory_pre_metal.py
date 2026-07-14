from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(filename: str, name: str) -> Any:
    path = Path(__file__).parents[1] / "research" / "experiments" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


QUALIFICATION = _load(
    "rc5_32_12_16_metal_qualification.py", "rc5_a247_qualification_tested"
)
FACTORY = _load(
    "rc5_32_12_16_metal_protocol_factory.py", "rc5_a248_factory_tested"
)
RECOVERY = _load("rc5_32_12_16_metal_recovery.py", "rc5_a248_recovery_tested")
ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research" / "experiments"


def test_nonzero_native_kat_and_scalar_provenance_gates() -> None:
    assert QUALIFICATION.OFFICIAL_KAT_MASTER_KEY == [
        0x19465F91,
        0x51B241BE,
        0x01A55563,
        0x91CEA910,
    ]
    expected = QUALIFICATION._scalar_outputs(
        *QUALIFICATION.OFFICIAL_KAT_MASTER_KEY
    )
    assert expected[:2].tolist() == [0xAC13C0F7, 0x52892B5B]
    assert len(QUALIFICATION.verify_rivest_kats()) == 5
    assert all(row["pass"] for row in QUALIFICATION.verify_rivest_kats())
    assert QUALIFICATION.verify_rfc2040_derived_r12()["pass"] is True


def test_single_native_request_cannot_encode_two_to_the_32_candidates() -> None:
    class UnusedHost:
        pass

    with pytest.raises(ValueError, match=r"1\.\.\.2\^32-1"):
        QUALIFICATION._benchmark(
            UnusedHost(), candidate_count=2**32, repeats=1
        )


@pytest.mark.parametrize(
    ("width", "outer_bits", "mask"),
    [
        (32, 0, 0xFFFFFFFF),
        (33, 1, 0xFFFFFFFE),
        (43, 11, 0xFFFFF800),
        (64, 32, 0x00000000),
    ],
)
def test_dynamic_width_mapping(width: int, outer_bits: int, mask: int) -> None:
    params = FACTORY._width_parameters(width)
    assert params["outer_bits"] == outer_bits
    assert params["key1_known_mask"] == mask
    assert params["outer_slices"] == 2**outer_bits
    assert params["logical_candidates"] == 2**width
    assignment = min(params["logical_candidates"] - 1, (7 << 32) | 0x89ABCDEF)
    key1, key2, key3, plaintext, _label, _digest = FACTORY._known_material(width)
    output = FACTORY._target_words(
        assignment,
        width=width,
        key1_known=key1,
        key2=key2,
        key3=key3,
        plaintext_words=plaintext,
    )
    assert output == RECOVERY._scalar_outputs(
        {
            "known_key1": key1,
            "known_key2": key2,
            "known_key3": key3,
            "plaintext_words_ab_order": plaintext,
        },
        {
            "logical_candidates": params["logical_candidates"],
        },
        assignment,
    ).tolist()


def test_protocol_factory_import_does_not_freeze_a_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        FACTORY.secrets,
        "randbits",
        lambda _width: (_ for _ in ()).throw(AssertionError("challenge generated")),
    )
    reloaded = _load(
        "rc5_32_12_16_metal_protocol_factory.py", "rc5_a248_factory_reimported"
    )
    assert reloaded.ATTEMPT_ID == "A248"


def test_static_native_shape_and_strict_json_uint32_gate() -> None:
    source = (EXPERIMENTS / "rc5_32_12_16_metal_native.swift").read_text()
    assert "constant uint RC5_INITIAL_SUBKEYS[26]" in source
    assert "for (uint mix = 0u; mix < 78u; ++mix)" in source
    assert "for (uint round = 1u; round <= 12u; ++round)" in source
    assert "uint plaintext[4];" in source
    assert "uint target[4];" in source
    assert "uint control[4];" in source
    assert "CFBooleanGetTypeID" in source
    assert "exact.rounded(.towardZero) == exact" in source
    assert "subkeys[26]" in source


def test_hard_clone_residue_gate() -> None:
    files = [
        "rc5_32_12_16_metal_native.swift",
        "rc5_32_12_16_metal_qualification.py",
        "rc5_32_12_16_metal_protocol_factory.py",
        "rc5_32_12_16_metal_recovery.py",
    ]
    forbidden = [
        "SIMON",
        "_simon",
        "z3",
        "A245",
        "A246",
        "44-round",
        "302e5cf20598ff32",
        "c7ab55dbc35ffbfc",
        "e868d0d19dc39628",
    ]
    for filename in files:
        source = (EXPERIMENTS / filename).read_text()
        assert not [token for token in forbidden if token in source], filename


def test_checkpoint_executor_covers_toy_domain_without_early_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = {
        "width": 8,
        "outer_bits": 0,
        "known_key_bits": 120,
        "outer_slices": 1,
        "inner_candidates": 16,
        "logical_candidates": 16,
        "stream_candidates": 4,
        "key1_known_mask": 0xFFFFFFFF,
    }
    challenge = {
        "plaintext_words_ab_order": [1, 2, 3, 4],
        "target_ciphertext_words_ab_order": [5, 6, 7, 8],
        "control_ciphertext_words_ab_order": [5, 6, 7, 9],
        "target_ciphertext_little_u32_sha256": "a" * 64,
        "control_ciphertext_little_u32_sha256": "b" * 64,
        "known_key1": 0,
        "known_key2": 0,
        "known_key3": 0,
    }
    anchors = {
        "protocol_sha256": "1" * 64,
        "public_challenge_sha256": "2" * 64,
        "qualification_sha256": "3" * 64,
        "native_source_sha256": "4" * 64,
    }

    class FakeHost:
        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

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
        RECOVERY,
        "_confirm",
        lambda _challenge, _context, _target, assignment: {
            "combined_assignment": assignment,
            "complete_two_block_match": assignment == 5,
        },
    )
    checkpoint = tmp_path / "checkpoint.json"
    host = FakeHost()
    execution = RECOVERY._enumerate_domain(
        host=host,
        challenge=challenge,
        context=context,
        anchors=anchors,
        checkpoint_path=checkpoint,
        resume=False,
    )
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_full_matches"] == [5]
    assert execution["control_full_matches"] == []
    assert host.calls == [(0, 4), (4, 4), (8, 4), (12, 4)]
    durable = json.loads(checkpoint.read_text())
    assert durable["next_assignment"] == 16
    resumed_host = FakeHost()
    resumed = RECOVERY._enumerate_domain(
        host=resumed_host,
        challenge=challenge,
        context=context,
        anchors=anchors,
        checkpoint_path=checkpoint,
        resume=True,
    )
    assert resumed["resumed_assignment_count"] == 16
    assert resumed["newly_executed_assignment_count"] == 0
    assert resumed_host.calls == []


def test_authentic_causal_is_materialized_and_reader_verified(tmp_path: Path) -> None:
    execution = {
        "unknown_key_bits": 43,
        "logical_candidate_count": 2**43,
        "complete_domain_executed": True,
        "factual_filter_matches": [5],
        "factual_confirmations": [
            {"combined_assignment": 5, "complete_two_block_match": True}
        ],
        "control_filter_matches": [],
        "control_confirmations": [],
    }
    payload = {
        "anchor_gates": {"qualification_sha256": "0" * 64},
        "mapping_gate": {"exact_scalar_filter_and_mapping_identity": True},
        "execution": execution,
        "execution_sha256": "1" * 64,
        "confirmation_sha256": "2" * 64,
    }
    path = tmp_path / "a248.causal"
    result = RECOVERY._build_authentic_causal(
        path=path,
        payload=payload,
        dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["api_id"] == "a248"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["integrity_verified_by_authoritative_reader"] is True


def test_full_domain_runner_requires_explicit_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="explicit execute_full_domain=True"):
        RECOVERY.run(
            protocol_path=tmp_path / "missing-protocol.json",
            expected_protocol_sha256="0" * 64,
            results_dir=tmp_path,
            output=tmp_path / "result.json",
            causal_output=tmp_path / "result.causal",
            report_output=tmp_path / "report.md",
            checkpoint_path=tmp_path / "checkpoint.json",
            build_dir=tmp_path / "build",
            swiftc="swiftc",
            dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
            resume=False,
            execute_full_domain=False,
        )
