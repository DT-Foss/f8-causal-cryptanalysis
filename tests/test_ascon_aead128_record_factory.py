from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from arx_carry_leak.ascon_aead128_reference import (
    OFFICIAL_KAT_COMMIT,
    OFFICIAL_KAT_FILE_SHA256,
    OFFICIAL_KATS,
    SP800_232_PDF_SHA256,
    decrypt,
    encrypt,
    encrypt_combined,
    verify_official_kats,
    verify_orientation_sentinel,
)


def _load(filename: str, name: str) -> Any:
    path = Path(__file__).parents[1] / "research" / "experiments" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


QUALIFICATION = _load(
    "ascon_aead128_metal_qualification.py", "ascon_a255_qualification_tested"
)
FACTORY = _load(
    "ascon_aead128_metal_protocol_factory.py", "ascon_a256_factory_tested"
)
RECOVERY = _load(
    "ascon_aead128_metal_recovery.py", "ascon_a256_recovery_tested"
)
ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research" / "experiments"
REFERENCE = ROOT / "src" / "arx_carry_leak" / "ascon_aead128_reference.py"
NATIVE = EXPERIMENTS / "ascon_aead128_metal_native.swift"
QUALIFICATION_SOURCE = EXPERIMENTS / "ascon_aead128_metal_qualification.py"
RECOVERY_SOURCE = EXPERIMENTS / "ascon_aead128_metal_recovery.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _qualification_payload(width: int = 36, stream: int = 1 << 16) -> dict[str, Any]:
    return {
        "schema": QUALIFICATION.SCHEMA,
        "attempt_id": "A255",
        "evidence_stage": "ASCON_AEAD128_SP800_232_METAL_PRE_TARGET_QUALIFICATION",
        "algorithm": {
            "byte_semantics": "SP800-232_little_endian",
            "legacy_submission_endian_semantics": False,
        },
        "content_anchors": {
            "qualification_source": {"sha256": _sha256(QUALIFICATION_SOURCE)},
            "native_source": {"sha256": _sha256(NATIVE)},
            "cpu_reference": {"sha256": _sha256(REFERENCE)},
            "official_kat": {
                "sha256": OFFICIAL_KAT_FILE_SHA256,
                "commit": OFFICIAL_KAT_COMMIT,
            },
            "nist_standard": {"pdf_sha256": SP800_232_PDF_SHA256},
        },
        "official_kat_gate": {
            "scalar_vectors": [{"pass": True} for _ in range(4)],
            "metal_vectors": [
                {"exact_cpu_metal_identity": True} for _ in range(4)
            ],
            "nonpalindromic_orientation_sentinel": {"pass": True},
            "all_official_kat_gates_passed": True,
        },
        "cross_implementation_gate": {"exact_cpu_metal_identity": True},
        "boundary_mapping_gate": {"exact_boundary_identity": True},
        "qualification_resource_cap": {"cannot_occupy_gpu_for_two_minutes": True},
        "information_boundary": {"production_protocol_frozen": False},
        "launch_gate": {
            "selected_width": width,
            "selected_stream_candidate_count": stream,
            "parameters_safe_for_post_review_freeze": True,
            "selected_width_under_two_hours": True,
            "full_domain_launch_authorized": False,
            "projected_selected_width_seconds_at_observed_minimum": 1000.0,
            "maximum_complete_domain_seconds": 7200,
        },
    }


def test_official_standardized_kats_and_nonpalindromic_orientation() -> None:
    rows = verify_official_kats()
    assert [row["count"] for row in rows] == [1, 35, 563, 1074]
    assert all(row["pass"] is True for row in rows)
    sentinel = verify_orientation_sentinel()
    assert sentinel["official_kat_count"] == 1074
    assert sentinel["little_endian_key_words_hex"] == [
        "0706050403020100",
        "0f0e0d0c0b0a0908",
    ]
    assert sentinel["legacy_big_endian_interpretation_hex"] == [
        "0001020304050607",
        "08090a0b0c0d0e0f",
    ]
    assert sentinel["word_reversed_key_rejected"] is True
    assert sentinel["pass"] is True


@pytest.mark.parametrize("vector", OFFICIAL_KATS)
def test_reference_roundtrip_and_tag_rejection(vector: Any) -> None:
    ciphertext, tag = encrypt(
        vector.key, vector.nonce, vector.associated_data, vector.plaintext
    )
    assert ciphertext + tag == vector.combined_ciphertext_tag
    assert (
        decrypt(vector.key, vector.nonce, vector.associated_data, ciphertext, tag)
        == vector.plaintext
    )
    bad_tag = tag[:-1] + bytes([tag[-1] ^ 1])
    with pytest.raises(ValueError, match="invalid Ascon-AEAD128"):
        decrypt(
            vector.key,
            vector.nonce,
            vector.associated_data,
            ciphertext,
            bad_tag,
        )


@pytest.mark.parametrize(
    ("width", "outer_bits", "word1_mask"),
    [
        (32, 0, 0xFFFFFFFF),
        (33, 1, 0xFFFFFFFE),
        (39, 7, 0xFFFFFF80),
        (64, 32, 0x00000000),
    ],
)
def test_residual_mapping(width: int, outer_bits: int, word1_mask: int) -> None:
    context = FACTORY._width_context(width, 1 << 16)
    assert context["outer_bits"] == outer_bits
    assert context["key_word1_known_mask"] == word1_mask
    assert context["logical_candidates"] == 2**width
    known_key, nonce, associated_data, message, _label, _digest = (
        FACTORY._known_material(width, 1 << 16)
    )
    assignment = min((2**width) - 1, (7 << 32) | 0x89ABCDEF)
    expected = FACTORY._target_for_assignment(
        assignment,
        width=width,
        stream_candidates=1 << 16,
        known_key=known_key,
        nonce=nonce,
        associated_data=associated_data,
        message=message,
    )
    challenge = {
        "known_key_zeroed_residual_hex": known_key.hex(),
        "message_hex": message.hex(),
        "associated_data_hex": associated_data.hex(),
        "nonce_hex": nonce.hex(),
        "target_ciphertext_and_tag_hex": expected.hex(),
        "control_ciphertext_and_tag_hex": expected.hex(),
    }
    assert RECOVERY._scalar_output(challenge, context, assignment) == expected


def test_qualification_work_cap_is_immutable() -> None:
    with pytest.raises(ValueError, match="benchmark candidate count"):
        QUALIFICATION._validate_benchmark_budget(QUALIFICATION.MAX_BENCHMARK_CANDIDATES + 1, 1)
    with pytest.raises(ValueError, match="benchmark repeats"):
        QUALIFICATION._validate_benchmark_budget(1, QUALIFICATION.MAX_BENCHMARK_REPEATS + 1)
    assert QUALIFICATION.QUALIFICATION_GPU_WALL_CAP_SECONDS < 120


def test_protocol_factory_import_does_not_freeze_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        FACTORY.secrets,
        "randbits",
        lambda _width: (_ for _ in ()).throw(AssertionError("challenge generated")),
    )
    reloaded = _load(
        "ascon_aead128_metal_protocol_factory.py",
        "ascon_a256_factory_reimported",
    )
    assert reloaded.ATTEMPT_ID == "A256"


def test_protocol_builder_discards_secret_and_analyzes_public_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    width = 36
    assignment = 0xA89ABCDEF
    qualification_path = tmp_path / FACTORY.QUALIFICATION_FILENAME
    qualification_path.write_text(json.dumps(_qualification_payload(width)) + "\n")
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda bits: assignment)
    with pytest.raises(RuntimeError, match="root review acknowledgement"):
        FACTORY.build_protocol(
            qualification=qualification_path,
            qualification_source=QUALIFICATION_SOURCE,
            native_source=NATIVE,
            reference_source=REFERENCE,
            recovery_source=RECOVERY_SOURCE,
            root_review_acknowledged=False,
        )
    protocol = FACTORY.build_protocol(
        qualification=qualification_path,
        qualification_source=QUALIFICATION_SOURCE,
        native_source=NATIVE,
        reference_source=REFERENCE,
        recovery_source=RECOVERY_SOURCE,
        root_review_acknowledged=True,
    )
    challenge = protocol["public_challenge"]
    assert challenge["unknown_assignment_included"] is False
    assert not {
        "hidden_assignment",
        "secret_assignment",
        "unknown_assignment_value",
    } & set(challenge)
    known_key = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    actual = encrypt_combined(
        (int.from_bytes(known_key, "little") | assignment).to_bytes(16, "little"),
        bytes.fromhex(challenge["nonce_hex"]),
        bytes.fromhex(challenge["associated_data_hex"]),
        bytes.fromhex(challenge["message_hex"]),
    )
    target = bytes.fromhex(challenge["target_ciphertext_and_tag_hex"])
    control = bytes.fromhex(challenge["control_ciphertext_and_tag_hex"])
    assert target == actual
    assert control[:-1] == target[:-1]
    assert control[-1] == target[-1] ^ 1
    assert protocol["information_boundary"]["runner_imported_or_constructed_by_builder"] is False
    assert protocol["execution_plan"]["authentic_dotcausal_v1_required"] is True
    assert (
        protocol["execution_plan"]["authentic_CausalReader_reopen_required"]
        is True
    )
    assert (
        protocol["required_validation_gates"][
            "final_manifest_must_bind_causal_artifact"
        ]
        is True
    )

    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    analysis = RECOVERY.analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=_sha256(protocol_path),
        results_dir=tmp_path,
    )
    assert analysis["candidate_execution_started"] is False
    assert analysis["context"]["width"] == width


def test_native_source_has_complete_standardized_relation_and_strict_json_gate() -> None:
    source = NATIVE.read_text()
    assert "0x00001000808c0001ul" in source
    assert "state[4] ^= 0x8000000000000000ul" in source
    assert "ascon_p12(state);" in source
    assert "ascon_p8(state);" in source
    assert "for (uint index = 0u; index < params.output_length; ++index)" in source
    assert "output[index] == packed_byte(params.target_words, index)" in source
    assert "output[index] == packed_byte(params.control_words, index)" in source
    assert "CFBooleanGetTypeID" in source
    assert "exact.rounded(.towardZero) == exact" in source
    assert "sp800_232_little_endian_semantics" in source


def test_checkpoint_executor_covers_toy_domain_without_early_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = {
        "width": 4,
        "outer_bits": 0,
        "known_key_bits": 124,
        "outer_slices": 1,
        "inner_candidates": 16,
        "logical_candidates": 16,
        "stream_candidates": 4,
        "key_word1_known_mask": 0xFFFFFFFF,
    }
    target = bytes(range(48))
    control = target[:-1] + bytes([target[-1] ^ 1])
    challenge = {
        "message_hex": bytes(32).hex(),
        "associated_data_hex": bytes(17).hex(),
        "nonce_hex": bytes(16).hex(),
        "known_key_zeroed_residual_hex": bytes(16).hex(),
        "known_key_words_little_endian": [0, 0, 0, 0],
        "target_ciphertext_and_tag_hex": target.hex(),
        "control_ciphertext_and_tag_hex": control.hex(),
        "target_ciphertext_and_tag_sha256": hashlib.sha256(target).hexdigest(),
        "control_ciphertext_and_tag_sha256": hashlib.sha256(control).hexdigest(),
    }
    anchors = {
        "protocol_sha256": "1" * 64,
        "public_challenge_sha256": "2" * 64,
        "qualification_sha256": "3" * 64,
        "native_source_sha256": "4" * 64,
        "cpu_reference_sha256": "5" * 64,
        "protocol_factory_sha256": "6" * 64,
        "recovery_source_sha256": "7" * 64,
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
        lambda _challenge, _context, _expected, assignment, relation: {
            "combined_assignment": assignment,
            "relation": relation,
            "complete_ciphertext_and_tag_match": assignment == 5,
        },
    )
    checkpoint = tmp_path / "checkpoint.json"
    host = FakeHost()
    result = RECOVERY._enumerate_domain(
        host=host,
        challenge=challenge,
        context=context,
        anchors=anchors,
        checkpoint_path=checkpoint,
        resume=False,
    )
    assert result["complete_domain_executed"] is True
    assert result["early_stop_used"] is False
    assert result["factual_full_matches"] == [5]
    assert result["control_full_matches"] == []
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


def test_authentic_causal_artifact_is_materialized_and_reader_verified(
    tmp_path: Path,
) -> None:
    execution = {
        "unknown_key_bits": 40,
        "logical_candidate_count": 1 << 40,
        "complete_domain_executed": True,
        "factual_filter_matches": [5],
        "factual_confirmations": [
            {"combined_assignment": 5, "complete_ciphertext_and_tag_match": True}
        ],
        "control_filter_matches": [],
        "control_confirmations": [],
    }
    payload = {
        "anchor_gates": {"qualification_sha256": "1" * 64},
        "mapping_gate": {"exact_scalar_filter_and_mapping_identity": True},
        "execution": execution,
        "execution_content_sha256": "2" * 64,
        "confirmation_content_sha256": "3" * 64,
    }
    path = tmp_path / "a256.causal"
    result = RECOVERY._build_authentic_causal(
        path=path,
        payload=payload,
        dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["format"] == "authentic_dotcausal_v1_AI_native"
    assert result["api_id"] == "a256"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["embedded_rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"] == 1
    assert result["inference_recomputed_on_reader_open"] is False
    assert result["amplified_state_materialized_in_file"] is True
    assert result["integrity_verified_by_authoritative_reader"] is True


def test_final_artifacts_bind_authentic_causal_without_gpu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text("{}\n")
    content_paths: dict[str, str] = {}
    for name in (
        "qualification",
        "qualification_source",
        "native_source",
        "cpu_reference",
        "protocol_factory",
        "recovery_source",
    ):
        path = tmp_path / name
        path.write_text(f"{name}\n")
        content_paths[name] = str(path)
    anchor_gates = {
        "protocol_sha256": _sha256(protocol_path),
        "public_challenge_sha256": "1" * 64,
        "qualification_sha256": "2" * 64,
        "qualification_source_sha256": "3" * 64,
        "native_source_sha256": "4" * 64,
        "cpu_reference_sha256": "5" * 64,
        "protocol_factory_sha256": "6" * 64,
        "recovery_source_sha256": "7" * 64,
    }
    analysis = {
        "context": {"width": 4},
        "protocol": {
            "protocol_state": "frozen_test_protocol",
            "information_boundary": {},
        },
        "public_challenge": {},
        "execution_plan": {},
        "anchor_gates": anchor_gates,
        "content_paths": content_paths,
    }
    execution = {
        "unknown_key_bits": 4,
        "known_key_bits": 124,
        "logical_candidate_count": 16,
        "executed_assignment_count": 16,
        "complete_domain_executed": True,
        "unique_exact_assignment": True,
        "control_target_rejected": True,
        "early_stop_used": False,
        "independent_full_ciphertext_and_tag_confirmation_after_completion": True,
        "factual_filter_matches": [5],
        "control_filter_matches": [],
        "factual_confirmations": [
            {"combined_assignment": 5, "complete_ciphertext_and_tag_match": True}
        ],
        "control_confirmations": [],
        "factual_full_matches": [5],
        "control_full_matches": [],
        "gpu_seconds": 1.0,
        "volatile_wall_seconds": 2.0,
        "volatile_candidates_per_gpu_second": 16.0,
    }

    class FakeHost:
        identity = {"device": "test"}

        def close(self) -> None:
            return None

    monkeypatch.setattr(RECOVERY, "analyze", lambda **_kwargs: analysis)
    monkeypatch.setattr(
        RECOVERY._QUAL,
        "_compile_native",
        lambda _build_dir, _swiftc: (tmp_path / "host", {"test_build": True}),
    )
    monkeypatch.setattr(
        RECOVERY._QUAL, "MetalAsconAEAD128Host", lambda _executable: FakeHost()
    )
    monkeypatch.setattr(
        RECOVERY,
        "_mapping_gate",
        lambda _host, _challenge, _context: {
            "exact_scalar_filter_and_mapping_identity": True
        },
    )
    monkeypatch.setattr(
        RECOVERY, "_enumerate_domain", lambda **_kwargs: execution
    )
    output = tmp_path / "result.json"
    causal = tmp_path / "result.causal"
    manifest = tmp_path / "manifest.json"
    report = tmp_path / "report.md"
    result = RECOVERY.run(
        protocol_path=protocol_path,
        expected_protocol_sha256=anchor_gates["protocol_sha256"],
        results_dir=tmp_path,
        output=output,
        causal_output=causal,
        manifest_output=manifest,
        report_output=report,
        checkpoint_path=tmp_path / "checkpoint.json",
        build_dir=tmp_path / "build",
        swiftc="swiftc",
        dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
        resume=False,
        execute_full_domain=True,
    )
    payload = json.loads(output.read_text())
    final_manifest = json.loads(manifest.read_text())
    assert result["authentic_causal_reader_verified"] is True
    assert payload["causal"]["file_sha256"] == _sha256(causal)
    assert final_manifest["files"]["causal"]["sha256"] == _sha256(causal)
    assert final_manifest["files"]["result"]["sha256"] == _sha256(output)
    assert final_manifest["causal_artifact_bound_to_result"] is True


def test_full_domain_runner_requires_explicit_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="explicit execute_full_domain=True"):
        RECOVERY.run(
            protocol_path=tmp_path / "missing-protocol.json",
            expected_protocol_sha256="0" * 64,
            results_dir=tmp_path,
            output=tmp_path / "result.json",
            causal_output=tmp_path / "result.causal",
            manifest_output=tmp_path / "manifest.json",
            report_output=tmp_path / "report.md",
            checkpoint_path=tmp_path / "checkpoint.json",
            build_dir=tmp_path / "build",
            swiftc="swiftc",
            dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
            resume=False,
            execute_full_domain=False,
        )


def test_no_clone_residue_from_neighbor_factories() -> None:
    files = [
        "ascon_aead128_metal_native.swift",
        "ascon_aead128_metal_qualification.py",
        "ascon_aead128_metal_protocol_factory.py",
        "ascon_aead128_metal_recovery.py",
    ]
    forbidden = ["A243", "A244", "A245", "A246", "A247", "A248", "RC5", "PRESENT", "SIMON", "SPECK"]
    for filename in files:
        source = (EXPERIMENTS / filename).read_text()
        assert not [token for token in forbidden if token in source], filename


def test_retained_factory_content_manifest_hashes() -> None:
    manifest_path = (
        ROOT
        / "research"
        / "provenance"
        / "ascon_aead128_a255_record_factory_manifest_v1.json"
    )
    manifest = json.loads(manifest_path.read_text())
    assert manifest["attempt_id"] == "A255"
    assert manifest["qualification_outcome"]["production_challenge_frozen"] is False
    assert manifest["qualification_outcome"]["full_domain_launched"] is False
    for name, record in manifest["files"].items():
        path = ROOT / record["path"]
        if name == "compiled_qualification_host":
            # The publication tree deliberately excludes generated native binaries.
            assert not path.exists()
            continue
        assert path.is_file()
        assert _sha256(path) == record["sha256"]
    assert manifest["official_sources"]["ascon_c_commit"] == OFFICIAL_KAT_COMMIT
    assert manifest["official_sources"]["kat_sha256"] == OFFICIAL_KAT_FILE_SHA256
    assert (
        manifest["official_sources"]["nist_sp800_232_pdf_sha256"]
        == SP800_232_PDF_SHA256
    )
