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
    "present128_metal_qualification.py", "present128_p128q1_qualification_tested"
)
FACTORY = _load(
    "present128_metal_protocol_factory.py", "present128_p128r1_factory_tested"
)
RECOVERY = _load("present128_metal_recovery.py", "present128_p128r1_recovery_tested")
ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research" / "experiments"
DOTCAUSAL = ROOT / "provenance/vendor/dotcausal/src"


def _synthetic_qualification(width: int) -> dict[str, Any]:
    native = EXPERIMENTS / "present128_metal_native.swift"
    return {
        "schema": QUALIFICATION.SCHEMA,
        "attempt_id": "P128Q1",
        "evidence_stage": "PRESENT128_METAL_PRE_TARGET_QUALIFICATION",
        "cipher": {
            "rounds": 31,
            "master_key_bits": 128,
            "final_whitening_key": "K32",
        },
        "native_build": {"source_sha256": FACTORY._file_sha256(native)},
        "provenance_kat_gate": {
            "official_zero_scalar_vector": QUALIFICATION.verify_official_zero_kat(),
            "reference_scalar_vectors": QUALIFICATION.verify_reference_kats(),
            "local_round_key_sentinel": (
                QUALIFICATION.verify_round_key_sentinel()
            ),
            "nonpalindromic_orientation_sentinels": (
                QUALIFICATION.verify_orientation_sentinels()
            ),
            "two_block_scalar_identity": True,
        },
        "cross_implementation_gate": {"exact_scalar_identity": True},
        "boundary_filter_gate": {"exact_boundary_identity": True},
        "information_boundary": {"production_target_selected": False},
        "launch_gate": {
            "selected_width": width,
            "selected_width_under_two_hours": True,
            "full_domain_launch_authorized": True,
            "projected_selected_width_seconds_at_observed_minimum": 100.0,
            "maximum_complete_domain_seconds": 7200.0,
        },
    }


def test_specification_native_scalar_anchor_and_local_schedule_trace() -> None:
    assert QUALIFICATION.REFERENCE_KAT_KEY_PARTS == (
        0x0C0D0E0F,
        0x08090A0B,
        0x04050607,
        0x00010203,
    )
    expected = QUALIFICATION._scalar_outputs(*QUALIFICATION.REFERENCE_KAT_KEY_PARTS)
    assert expected[:2].tolist() == [0x0E3DCAFF, 0x311F1809]
    assert QUALIFICATION.verify_official_zero_kat()["pass"] is True
    assert len(QUALIFICATION.verify_reference_kats()) == 4
    assert all(row["pass"] for row in QUALIFICATION.verify_reference_kats())
    assert QUALIFICATION.verify_round_key_sentinel()["pass"] is True
    assert all(row["pass"] for row in QUALIFICATION.verify_orientation_sentinels())


def test_single_native_request_rejects_two_to_the_32_candidates() -> None:
    class UnusedHost:
        pass

    with pytest.raises(ValueError, match=r"1\.\.\.2\^32-1"):
        QUALIFICATION._benchmark(UnusedHost(), candidate_count=2**32, repeats=1)


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
    assert params["mid_low_known_mask"] == mask
    assert params["outer_slices"] == 2**outer_bits
    assert params["logical_candidates"] == 2**width
    assignment = min(params["logical_candidates"] - 1, (7 << 32) | 0x89ABCDEF)
    mid_low32, high64, plaintext, _label, _digest, _guard = FACTORY._known_material(
        width
    )
    expected = FACTORY._target_words(
        assignment,
        width=width,
        mid_low32_known=mid_low32,
        high64=high64,
        plaintext_words=plaintext,
    )
    observed = RECOVERY._scalar_outputs(
        {
            "known_mid_low32": mid_low32,
            "known_high64": high64,
            "plaintext_words_big_endian": plaintext,
        },
        {"logical_candidates": params["logical_candidates"]},
        assignment,
    )
    assert observed.tolist() == expected
    confirmation = RECOVERY._confirm(
        {
            "known_mid_low32": mid_low32,
            "known_high64": high64,
            "plaintext_words_big_endian": plaintext,
        },
        {"logical_candidates": params["logical_candidates"]},
        observed,
        assignment,
    )
    full_key = (
        (high64 << 64)
        | ((mid_low32 | (assignment >> 32)) << 32)
        | (assignment & 0xFFFFFFFF)
    )
    assert confirmation["full_master_key_hex"] == f"{full_key:032x}"


def test_protocol_factory_import_is_side_effect_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        FACTORY.secrets,
        "randbits",
        lambda _width: (_ for _ in ()).throw(AssertionError("challenge generated")),
    )
    reloaded = _load(
        "present128_metal_protocol_factory.py", "present128_p128r1_factory_reimported"
    )
    assert reloaded.ATTEMPT_ID == "P128R1"


def test_synthetic_protocol_freeze_and_hash_gated_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    width = 43
    assignment = (3 << 32) | 0x12345678
    qualification = tmp_path / FACTORY.QUALIFICATION_FILENAME
    qualification.write_text(json.dumps(_synthetic_qualification(width)))
    native = EXPERIMENTS / "present128_metal_native.swift"
    reference = ROOT / "src/arx_carry_leak/present128_reference.py"
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda bits: assignment)
    protocol = FACTORY.build_protocol(
        qualification=qualification,
        native_source=native,
        reference_source=reference,
    )
    assert protocol["protocol_state"] == "frozen_before_any_P128R1_candidate_execution"
    assert protocol["public_challenge"]["unknown_assignment_included"] is False
    assert protocol["execution_plan"]["logical_candidate_count"] == 2**width
    assert protocol["execution_plan"]["filter_output_bits"] == 128
    assert protocol["public_challenge"]["target_ciphertext_words_big_endian"] == (
        FACTORY._target_words(
            assignment,
            width=width,
            mid_low32_known=protocol["public_challenge"]["known_mid_low32"],
            high64=protocol["public_challenge"]["known_high64"],
            plaintext_words=protocol["public_challenge"][
                "plaintext_words_big_endian"
            ],
        )
    )
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol, sort_keys=True))
    analysis = RECOVERY.analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=RECOVERY._file_sha256(protocol_path),
        results_dir=tmp_path,
    )
    assert analysis["candidate_execution_started"] is False
    assert analysis["context"]["width"] == width
    assert analysis["anchor_gates"]["reference_source_sha256"] == (
        FACTORY._file_sha256(reference)
    )


def test_analysis_rejects_qualification_native_hash_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    width = 43
    qualification_payload = _synthetic_qualification(width)
    qualification = tmp_path / FACTORY.QUALIFICATION_FILENAME
    qualification.write_text(json.dumps(qualification_payload))
    native = EXPERIMENTS / "present128_metal_native.swift"
    reference = ROOT / "src/arx_carry_leak/present128_reference.py"
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda _bits: 5)
    protocol = FACTORY.build_protocol(
        qualification=qualification,
        native_source=native,
        reference_source=reference,
    )
    qualification_payload["native_build"]["source_sha256"] = "0" * 64
    qualification.write_text(json.dumps(qualification_payload))
    protocol["anchors"]["qualification"]["sha256"] = RECOVERY._file_sha256(
        qualification
    )
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol, sort_keys=True))
    with pytest.raises(RuntimeError, match="qualification and PRESENT-128 native hashes"):
        RECOVERY.analyze(
            protocol_path=protocol_path,
            expected_protocol_sha256=RECOVERY._file_sha256(protocol_path),
            results_dir=tmp_path,
        )


def test_static_native_round_key_abi_and_strict_json_gate() -> None:
    source = (EXPERIMENTS / "present128_metal_native.swift").read_text()
    assert "uint plaintext[4];" in source
    assert "uint target[4];" in source
    assert "uint control[4];" in source
    assert "uint key_high32;" in source
    assert "uint key_mid_high32;" in source
    assert "uint key_mid_low32;" in source
    assert "for (uint round_index = 1u; round_index <= 31u; ++round_index)" in source
    assert "states.x ^= key_high64;" in source
    assert "states.y ^= key_high64;" in source
    assert "no S-box or permutation follows it" in source
    assert "(high64 << 61u) | (low64 >> 3u)" in source
    assert "(low64 << 61u) | (high64 >> 3u)" in source
    assert "PRESENT_SBOX[second_nibble]" in source
    assert "next_low64 ^= ulong(round_index & 0x3u) << 62u;" in source
    assert "next_high64 ^= ulong(round_index >> 2u);" in source
    assert "(ulong(params.key_high32) << 32u)" in source
    assert "ulong(params.key_mid_high32)" in source
    assert "(ulong(params.key_mid_low32) << 32u)" in source
    assert "ulong(candidate);" in source
    assert "CFBooleanGetTypeID" in source
    assert "exact.rounded(.towardZero) == exact" in source
    assert "config.keyHigh32" in source
    assert "config.keyMidHigh32" in source
    assert "config.keyMidLow32" in source


def test_hard_clone_residue_gate() -> None:
    files = [
        "present128_metal_native.swift",
        "present128_metal_qualification.py",
        "present128_metal_protocol_factory.py",
        "present128_metal_recovery.py",
    ]
    forbidden = [
        "RC5",
        "rc5_",
        "SIMON",
        "simon_",
        "P32",
        "Q32",
        "A245",
        "A246",
        "A247",
        "A248",
        "44-round",
        "12-round",
        "present80",
        "PRESENT-80",
        "a253",
    ]
    for filename in files:
        source = (EXPERIMENTS / filename).read_text()
        assert not [token for token in forbidden if token in source], filename


def test_checkpoint_executor_covers_toy_domain_and_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = {
        "width": 4,
        "outer_bits": 1,
        "known_key_bits": 124,
        "outer_slices": 2,
        "inner_candidates": 8,
        "logical_candidates": 16,
        "stream_candidates": 4,
        "mid_low_known_mask": 0xFFFFFFFE,
    }
    challenge = {
        "plaintext_words_big_endian": [1, 2, 3, 4],
        "target_ciphertext_words_big_endian": [5, 6, 7, 8],
        "control_ciphertext_words_big_endian": [5, 6, 7, 9],
        "target_ciphertext_big_u32_sha256": "a" * 64,
        "control_ciphertext_big_u32_sha256": "b" * 64,
        "known_mid_low32": 0,
        "known_high64": 0,
    }
    anchors = {
        "protocol_sha256": "1" * 64,
        "public_challenge_sha256": "2" * 64,
        "qualification_sha256": "3" * 64,
        "native_source_sha256": "4" * 64,
        "reference_source_sha256": "5" * 64,
    }

    class FakeHost:
        def __init__(self) -> None:
            self.outer = -1
            self.calls: list[tuple[int, int, int]] = []

        def configure(self, **kwargs: Any) -> None:
            self.outer = int(kwargs["key_mid_low32"])

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.calls.append((self.outer, first, count))
            match = self.outer == 1 and first <= 5 < first + count
            return {
                "factual": [5] if match else [],
                "control": [],
                "gpu_seconds": 0.25,
            }

    monkeypatch.setattr(
        RECOVERY,
        "_confirm",
        lambda _challenge, _context, _target, assignment: {
            "combined_assignment": assignment,
            "complete_two_block_match": assignment == 13,
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
    assert execution["factual_full_matches"] == [13]
    assert execution["control_full_matches"] == []
    assert host.calls == [(0, 0, 4), (0, 4, 4), (1, 0, 4), (1, 4, 4)]
    assert json.loads(checkpoint.read_text())["next_assignment"] == 16
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
    path = tmp_path / "p128r1.causal"
    result = RECOVERY._build_authentic_causal(
        path=path,
        payload=payload,
        dotcausal_src=DOTCAUSAL,
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["api_id"] == "p128r1"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["integrity_verified_by_authoritative_reader"] is True
    assert result["reader_source"]["version"] == "0.3.1"
    _writer, Reader, _source = RECOVERY._load_dotcausal(None)
    reader = Reader(str(path), verify_integrity=True)
    stored = RECOVERY._stored_causal_triplets(reader)
    assert [row["is_inferred"] for row in stored] == [False] * 5 + [True] * 2
    assert [row["inference_chain"] for row in stored[-2:]] == [[1, 2], [3, 4]]


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
            dotcausal_src=DOTCAUSAL,
            resume=False,
            execute_full_domain=False,
        )


def test_reproduction_wrapper_default_path_is_pre_metal_only() -> None:
    source = (ROOT / "scripts/reproduce_present128_metal.sh").read_text()
    default_branch = source.split("  --qualify)", maxsplit=1)[0]
    assert '"$PYTHON_BIN" -m pytest' in default_branch
    assert '"$PYTHON_BIN" -m py_compile' in default_branch
    assert "swiftc -typecheck" in default_branch
    assert '"$PYTHON_BIN" "$QUALIFICATION"' not in default_branch
    assert '"$PYTHON_BIN" "$FACTORY"' not in default_branch
    assert "--execute-full-domain" not in default_branch
