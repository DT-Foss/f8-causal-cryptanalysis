from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from arx_carry_leak.aes256_reference import (
    FIPS197_KATS,
    LOCAL_ORIENTATION_KAT,
    RCON,
    SBOX,
    apply_low_residual_bits,
    decrypt_block,
    decrypt_blocks,
    encrypt_block,
    encrypt_blocks,
    expand_key,
    key_words_big_endian,
    verify_fips197_kats,
    verify_orientation_and_schedule_sentinels,
    zero_low_residual_bits,
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
    "aes256_metal_qualification.py", "aes256_qualification_tested"
)
FACTORY = _load("aes256_metal_protocol_factory.py", "aes256_factory_tested")
RECOVERY = _load("aes256_metal_recovery.py", "aes256_recovery_tested")
ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research" / "experiments"
DOTCAUSAL = ROOT / "provenance/vendor/dotcausal/src"
REFERENCE = ROOT / "src" / "arx_carry_leak" / "aes256_reference.py"
NATIVE = EXPERIMENTS / "aes256_metal_native.swift"
QUALIFICATION_SOURCE = EXPERIMENTS / "aes256_metal_qualification.py"
RECOVERY_SOURCE = EXPERIMENTS / "aes256_metal_recovery.py"
INDEPENDENT_SOURCE = ROOT / "src/arx_carry_leak/aes256_independent.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cpu_payload_with_synthetic_metal_fields() -> dict[str, Any]:
    """Reproduce the old CPU-plus-booleans bypass without an evidence ledger."""

    width = 36
    stream = 1 << 16
    payload = QUALIFICATION.run_cpu_qualification()
    payload.update(
        {
            "evidence_stage": FACTORY.QUALIFICATION_STAGE,
            "metal_kat_cross_gate": {
                "fips197_vectors": [
                    {"exact_cpu_metal_identity": True},
                    {"exact_cpu_metal_identity": True},
                ],
                "exact_cpu_metal_identity": True,
            },
            "metal_boundary_mapping_gate": {"exact_boundary_identity": True},
            "qualification_resource_cap": {
                "cannot_occupy_gpu_for_two_minutes": True
            },
            "information_boundary": {
                "production_target_selected": False,
                "production_unknown_assignment_generated": False,
                "production_protocol_frozen": False,
                "complete_residual_key_domain_executed": False,
                "benchmark_used_only_for_prospective_width_and_stream_selection": True,
            },
            "launch_gate": {
                "selected_width": width,
                "selected_stream_candidate_count": stream,
                "selectable_widths": list(range(32, width + 1)),
                "parameters_safe_for_later_review": True,
                "full_domain_launch_authorized": False,
                "projected_selected_width_seconds_at_observed_minimum": 1000.0,
                "maximum_complete_domain_seconds": 7200,
            },
            "metal_executed": True,
        }
    )
    return payload


def _structurally_authentic_metal_qualification() -> dict[str, Any]:
    """Build a no-GPU fixture matching the semantic Metal ledger contract."""

    payload = QUALIFICATION.run_cpu_qualification()
    candidate_count = 1 << 16
    repeats = 2
    target_candidate = candidate_count // 2
    sample_times = ((0.0030, 0.00625), (0.0029, 0.0060))
    samples = [
        {
            "candidate_count": candidate_count,
            "gpu_seconds": gpu_seconds,
            "end_to_end_wall_seconds": wall_seconds,
            "gpu_candidates_per_second": candidate_count / gpu_seconds,
            "end_to_end_candidates_per_second": candidate_count / wall_seconds,
            "factual_matches": [target_candidate],
            "control_matches": [],
        }
        for gpu_seconds, wall_seconds in sample_times
    ]
    throughputs = [row["end_to_end_candidates_per_second"] for row in samples]
    minimum = min(throughputs)
    stream = QUALIFICATION._recommended_stream_count(minimum)
    benchmark = {
        "candidate_count_per_repeat": candidate_count,
        "repeats": repeats,
        "warmup_candidate_count": candidate_count,
        "maximum_candidate_invocations_permitted": (
            QUALIFICATION._validate_benchmark_budget(candidate_count, repeats)
        ),
        "warmup_factual_matches": [target_candidate],
        "samples": samples,
        "minimum_candidates_per_second": minimum,
        "median_candidates_per_second": QUALIFICATION.statistics.median(throughputs),
        "recommended_stream_candidate_count": stream,
        "recommended_stream_seconds_at_minimum": stream / minimum,
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum
            for width in range(
                QUALIFICATION.MIN_RESIDUAL_WIDTH,
                QUALIFICATION.MAX_RESIDUAL_WIDTH + 1,
            )
        },
        "timed_relation_bits": QUALIFICATION.FILTER_BITS,
        "volatile_performance_only_not_recovery_evidence": True,
    }
    launch_gate = QUALIFICATION._launch_gate(benchmark)
    assert launch_gate["selected_width"] == 36
    resource_cap = {
        "wall_deadline_seconds": QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "host_lifetime_started_monotonic": 1000.0,
        "absolute_deadline_monotonic": (
            1000.0 + QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS
        ),
        "host_lifetime_finished_monotonic": 1001.0,
        "actual_wall_seconds_host_lifetime": 1.0,
        "reported_total_gpu_seconds": 1.0,
        "maximum_benchmark_candidates_per_repeat": (
            QUALIFICATION.MAX_BENCHMARK_CANDIDATES
        ),
        "maximum_benchmark_repeats": QUALIFICATION.MAX_BENCHMARK_REPEATS,
        "subprocess_killed_on_deadline": True,
        "deadline_covers_ready_wait": True,
        "constructor_cleanup_on_startup_failure": True,
        "cannot_occupy_gpu_for_two_minutes": True,
    }
    native_build = {
        "source_filename": NATIVE.name,
        "source_sha256": payload["content_anchors"]["native_source"]["sha256"],
        "executable_sha256": "a" * 64,
        "compiler_version": "structural-fixture",
        "selected_flags": ["-O", "-whole-module-optimization", "-warnings-as-errors"],
        "warnings_as_errors": True,
    }
    host_identity = {
        "op": "ready",
        "version": QUALIFICATION.NATIVE_VERSION,
        "metal": {
            "device": "Apple structural fixture",
            "filter_execution_width": 32,
            "shader_runtime_compiled": True,
            "fips197_external_byte_order": True,
            "candidate_maps_to_key_bytes_28_through_31_big_endian": True,
            "aes256_nk8_subword_i_mod_8_eq_4": True,
        },
    }
    cross = QUALIFICATION._expected_metal_cross_evidence()
    mapping = QUALIFICATION._expected_metal_mapping_evidence()
    ledger = QUALIFICATION._build_metal_evidence_ledger(
        cpu_content_anchors_sha256=payload["content_anchors_sha256"],
        native_build=native_build,
        host_identity=host_identity,
        cross=cross,
        mapping=mapping,
        benchmark=benchmark,
        launch_gate=launch_gate,
        resource_cap=resource_cap,
    )
    payload.update(
        {
            "evidence_stage": FACTORY.QUALIFICATION_STAGE,
            "native_build": native_build,
            "host_identity": host_identity,
            "metal_kat_cross_gate": cross,
            "metal_boundary_mapping_gate": mapping,
            "benchmark": benchmark,
            "launch_gate": launch_gate,
            "qualification_resource_cap": resource_cap,
            "metal_evidence_ledger": ledger,
            "metal_evidence_ledger_sha256": QUALIFICATION._canonical_sha256(ledger),
            "information_boundary": {
                "production_target_selected": False,
                "production_unknown_assignment_generated": False,
                "production_protocol_frozen": False,
                "complete_residual_key_domain_executed": False,
                "benchmark_used_only_for_prospective_width_and_stream_selection": True,
            },
            "metal_executed": True,
        }
    )
    return payload


def test_fips197_fullround_known_answers_and_round_key() -> None:
    rows = verify_fips197_kats()
    assert len(rows) == 2
    assert all(row["pass"] is True for row in rows)
    vector = FIPS197_KATS[1]
    assert encrypt_block(vector.key, vector.plaintext) == vector.ciphertext
    assert decrypt_block(vector.key, vector.ciphertext) == vector.plaintext
    assert expand_key(vector.key)[-16:].hex() == "fe4890d1e6188d0b046df344706c631e"
    sentinels = verify_orientation_and_schedule_sentinels()
    assert sentinels["orientation_pass"] is True
    assert sentinels["decrypt_roundtrip_pass"] is True
    assert all(
        row["pass"] is True
        for row in sentinels["round_key_word_sentinels"].values()
    )


def test_independent_numpy_reference_confirms_scalar_on_nonpalindromic_blocks() -> None:
    assert QUALIFICATION.independent_numpy_source_path() == INDEPENDENT_SOURCE.resolve()
    key = LOCAL_ORIENTATION_KAT.key
    plaintext = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    scalar = encrypt_blocks(key, plaintext)
    independent = QUALIFICATION.independent_numpy_encrypt(key, plaintext)
    assert scalar == independent
    assert scalar[:16] == LOCAL_ORIENTATION_KAT.ciphertext
    assert decrypt_blocks(key, scalar) == plaintext


@pytest.mark.parametrize(
    ("width", "assignment", "expected_word6", "expected_word7"),
    [
        (32, 0x89ABCDEF, 0x00000000, 0x89ABCDEF),
        (33, 0x189ABCDEF, 0x00000001, 0x89ABCDEF),
        (40, 0xA589ABCDEF, 0x000000A5, 0x89ABCDEF),
        (64, 0xFEDCBA9876543210, 0xFEDCBA98, 0x76543210),
    ],
)
def test_contiguous_low_residual_mapping_is_endian_explicit(
    width: int, assignment: int, expected_word6: int, expected_word7: int
) -> None:
    seed = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768700000000ccddeeff"
    )
    known = zero_low_residual_bits(seed, width)
    key = apply_low_residual_bits(known, assignment, width)
    words = key_words_big_endian(key)
    assert words[6] == expected_word6
    assert words[7] == expected_word7
    assert int.from_bytes(key, "big") & ((1 << width) - 1) == assignment
    assert key[28:] == expected_word7.to_bytes(4, "big")


def test_cpu_only_qualification_never_invokes_metal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        QUALIFICATION,
        "_compile_native",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Metal invoked")),
    )
    payload = QUALIFICATION.run_cpu_qualification()
    assert payload["cpu_kat_gate"]["all_cpu_kats_passed"] is True
    assert payload["cpu_boundary_mapping_gate"]["exact_boundary_identity"] is True
    assert payload["metal_executed"] is False
    assert payload["production_challenge_frozen"] is False
    assert payload["full_domain_launched"] is False
    assert "metal_evidence_ledger" not in payload
    assert "metal_evidence_ledger_sha256" not in payload


def test_qualification_resource_cap_is_immutable() -> None:
    assert QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS < 120
    with pytest.raises(ValueError, match="benchmark candidate count"):
        QUALIFICATION._validate_benchmark_budget(
            QUALIFICATION.MAX_BENCHMARK_CANDIDATES + 1, 1
        )
    with pytest.raises(ValueError, match="benchmark repeats"):
        QUALIFICATION._validate_benchmark_budget(
            1, QUALIFICATION.MAX_BENCHMARK_REPEATS + 1
        )


def test_protocol_factory_import_does_not_freeze_a_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        FACTORY.secrets,
        "randbits",
        lambda _width: (_ for _ in ()).throw(AssertionError("challenge generated")),
    )
    reloaded = _load(
        "aes256_metal_protocol_factory.py", "aes256_factory_reimported"
    )
    assert reloaded.QUALIFICATION_SCHEMA == QUALIFICATION.SCHEMA


def test_protocol_builder_requires_ack_and_omits_hidden_assignment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assignment = 0xA89ABCDEF
    qualification = _structurally_authentic_metal_qualification()
    width = qualification["launch_gate"]["selected_width"]
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_text(json.dumps(qualification) + "\n")
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda bits: assignment)
    with pytest.raises(RuntimeError, match="review acknowledgement"):
        FACTORY.build_protocol(
            qualification=qualification_path,
            qualification_source=QUALIFICATION_SOURCE,
            native_source=NATIVE,
            reference_source=REFERENCE,
            independent_source=INDEPENDENT_SOURCE,
            recovery_source=RECOVERY_SOURCE,
            freeze_acknowledged=False,
        )
    protocol = FACTORY.build_protocol(
        qualification=qualification_path,
        qualification_source=QUALIFICATION_SOURCE,
        native_source=NATIVE,
        reference_source=REFERENCE,
        independent_source=INDEPENDENT_SOURCE,
        recovery_source=RECOVERY_SOURCE,
        freeze_acknowledged=True,
    )
    challenge = protocol["public_challenge"]
    assert protocol["attempt_id"] == "AES256R1"
    assert protocol["qualification_attempt_id"] == "AES256Q1"
    assert challenge["unknown_assignment_included"] is False
    assert challenge["hidden_assignment_included"] is False
    assert not {
        "unknown_assignment_value",
        "hidden_assignment",
        "secret_assignment",
    } & set(challenge)
    known = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    expected = encrypt_blocks(
        apply_low_residual_bits(known, assignment, width),
        bytes.fromhex(challenge["plaintext_hex"]),
    )
    target = bytes.fromhex(challenge["target_ciphertext_hex"])
    control = bytes.fromhex(challenge["control_ciphertext_hex"])
    assert target == expected
    assert control[:-1] == target[:-1]
    assert control[-1] == target[-1] ^ 1
    assert protocol["execution_plan"]["complete_domain_required"] is True
    assert protocol["execution_plan"]["authentic_dotcausal_v1_required"] is True
    assert protocol["content_manifest"]["independent_numpy_reference"]["sha256"] == (
        _sha256(INDEPENDENT_SOURCE)
    )
    assert protocol["metal_evidence_ledger_anchor"]["sha256"] == (
        qualification["metal_evidence_ledger_sha256"]
    )
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol, sort_keys=True))
    analysis = RECOVERY.analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=_sha256(protocol_path),
        results_dir=tmp_path,
    )
    assert analysis["candidate_execution_started"] is False
    assert analysis["anchor_gates"]["independent_numpy_reference_sha256"] == (
        _sha256(INDEPENDENT_SOURCE)
    )
    assert analysis["anchor_gates"]["metal_evidence_ledger_sha256"] == (
        qualification["metal_evidence_ledger_sha256"]
    )
    altered_protocol = json.loads(json.dumps(protocol))
    altered_protocol["metal_evidence_ledger_anchor"]["sha256"] = "0" * 64
    altered_protocol_path = tmp_path / "protocol-altered-ledger-anchor.json"
    altered_protocol_path.write_text(json.dumps(altered_protocol, sort_keys=True))
    with pytest.raises(RuntimeError, match="ledger protocol anchor differs"):
        RECOVERY.analyze(
            protocol_path=altered_protocol_path,
            expected_protocol_sha256=_sha256(altered_protocol_path),
            results_dir=tmp_path,
        )


def test_factory_rejects_cpu_payload_with_synthetic_metal_fields() -> None:
    payload = _cpu_payload_with_synthetic_metal_fields()
    with pytest.raises(RuntimeError, match="evidence ledger"):
        FACTORY._qualification_gate(payload)


def test_structurally_authentic_metal_ledger_is_accepted() -> None:
    payload = _structurally_authentic_metal_qualification()
    width = payload["launch_gate"]["selected_width"]
    stream = payload["launch_gate"]["selected_stream_candidate_count"]
    assert QUALIFICATION.validate_metal_evidence_ledger(payload) == (
        payload["metal_evidence_ledger_sha256"]
    )
    assert FACTORY._qualification_gate(payload) == (width, stream)
    for field in (
        "production_target_selected",
        "production_unknown_assignment_generated",
        "production_protocol_frozen",
        "complete_residual_key_domain_executed",
    ):
        payload["information_boundary"][field] = True
        with pytest.raises(RuntimeError, match="semantic gate"):
            FACTORY._qualification_gate(payload)
        payload["information_boundary"][field] = False


def test_factory_rejects_round_key_sentinel_drift() -> None:
    payload = _structurally_authentic_metal_qualification()
    sentinels = payload["cpu_kat_gate"][
        "nonpalindromic_orientation_and_round_key_sentinels"
    ]
    sentinels["round_key_word_sentinels"]["12"]["pass"] = False
    with pytest.raises(RuntimeError, match="semantic gate"):
        FACTORY._qualification_gate(payload)


def test_metal_ledger_host_lifetime_covers_recorded_work() -> None:
    for actual_wall, reported_gpu in ((0.01, 0.0059), (0.02, 0.03)):
        payload = _structurally_authentic_metal_qualification()
        resource_cap = payload["qualification_resource_cap"]
        started = resource_cap["host_lifetime_started_monotonic"]
        resource_cap["host_lifetime_finished_monotonic"] = started + actual_wall
        resource_cap["actual_wall_seconds_host_lifetime"] = actual_wall
        resource_cap["reported_total_gpu_seconds"] = reported_gpu
        payload["metal_evidence_ledger_sha256"] = QUALIFICATION._canonical_sha256(
            payload["metal_evidence_ledger"]
        )
        with pytest.raises(RuntimeError, match="consistency gate"):
            QUALIFICATION.validate_metal_evidence_ledger(payload)

    payload = _structurally_authentic_metal_qualification()
    sample = payload["benchmark"]["samples"][0]
    sample["gpu_seconds"] = sample["end_to_end_wall_seconds"] * 2
    sample["gpu_candidates_per_second"] = (
        sample["candidate_count"] / sample["gpu_seconds"]
    )
    payload["metal_evidence_ledger_sha256"] = QUALIFICATION._canonical_sha256(
        payload["metal_evidence_ledger"]
    )
    with pytest.raises(RuntimeError, match="consistency gate"):
        QUALIFICATION.validate_metal_evidence_ledger(payload)


def test_independent_numpy_source_is_hash_bound_before_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    qualification = _structurally_authentic_metal_qualification()
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_text(json.dumps(qualification))
    drifted = tmp_path / "ciphers.py"
    drifted.write_bytes(INDEPENDENT_SOURCE.read_bytes() + b"\n# audit drift\n")
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda bits: 1)
    with pytest.raises(RuntimeError, match="content hashes differ"):
        FACTORY.build_protocol(
            qualification=qualification_path,
            qualification_source=QUALIFICATION_SOURCE,
            native_source=NATIVE,
            reference_source=REFERENCE,
            independent_source=drifted,
            recovery_source=RECOVERY_SOURCE,
            freeze_acknowledged=True,
        )


def test_static_native_source_has_all_rounds_and_exact_mapping() -> None:
    source = NATIVE.read_text()
    assert "constant uchar AES_SBOX[256]" in source
    assert "constant uchar AES_RCON[10]" in source
    assert "for (uint round = 1u; round <= 14u; ++round)" in source
    assert "if (round < 14u)" in source
    assert "thread uint words[60]" in source
    assert "else if ((index & 7u) == 4u)" in source
    assert "schedule = aes_sub_word(schedule);" in source
    assert "uint plaintext[32];" in source
    assert "uint target[32];" in source
    assert "uint control[32];" in source
    assert "fips197_external_byte_order" in source
    assert "candidate_maps_to_key_bytes_28_through_31_big_endian" in source
    assert "candidate_key_word\": 7" in source
    assert "CFBooleanGetTypeID" in source
    assert "exact.rounded(.towardZero) == exact" in source


def test_static_metal_tables_are_byte_exact_fips_tables() -> None:
    source = NATIVE.read_text()
    sbox_match = re.search(
        r"constant uchar AES_SBOX\[256\] = \{(.*?)\};", source, re.DOTALL
    )
    rcon_match = re.search(
        r"constant uchar AES_RCON\[10\] = \{(.*?)\};", source, re.DOTALL
    )
    assert sbox_match is not None
    assert rcon_match is not None
    metal_sbox = tuple(
        int(token, 16) for token in re.findall(r"0x[0-9a-fA-F]+", sbox_match.group(1))
    )
    metal_rcon = tuple(
        int(token, 16) for token in re.findall(r"0x[0-9a-fA-F]+", rcon_match.group(1))
    )
    assert metal_sbox == SBOX
    assert metal_rcon == RCON


def test_checkpoint_executor_covers_toy_domain_without_early_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = {
        "width": 4,
        "outer_bits": 0,
        "known_key_bits": 252,
        "outer_slices": 1,
        "inner_candidates": 16,
        "logical_candidates": 16,
        "stream_candidates": 4,
        "key_word6_known_mask": 0xFFFFFFFF,
    }
    target = bytes(range(32))
    control = target[:-1] + bytes([target[-1] ^ 1])
    challenge = {
        "plaintext_hex": bytes(32).hex(),
        "known_key_zeroed_residual_hex": bytes(32).hex(),
        "known_key_words_big_endian": [0, 0, 0, 0, 0, 0, 0, 0],
        "target_ciphertext_hex": target.hex(),
        "control_ciphertext_hex": control.hex(),
    }
    anchors = {
        "protocol_sha256": "1" * 64,
        "public_challenge_sha256": "2" * 64,
        "qualification_sha256": "3" * 64,
        "native_source_sha256": "4" * 64,
        "independent_numpy_reference_sha256": _sha256(INDEPENDENT_SOURCE),
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
        lambda _challenge, _context, _expected, assignment, relation, _source_hash: {
            "combined_assignment": assignment,
            "relation": relation,
            "complete_two_block_match": assignment == 5,
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


def test_final_confirmation_rejects_independent_source_hash_drift() -> None:
    challenge = {
        "known_key_zeroed_residual_hex": bytes(32).hex(),
        "plaintext_hex": bytes(32).hex(),
    }
    context = {"width": 32}
    with pytest.raises(RuntimeError, match="hash changed before confirmation"):
        RECOVERY._confirm(
            challenge,
            context,
            bytes(32),
            0,
            "factual",
            "0" * 64,
        )


def test_final_confirmation_checks_both_full_blocks_with_two_implementations() -> None:
    assignment = 0x89ABCDEF
    known = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacb00000000"
    )
    plaintext = bytes(range(32))
    expected = encrypt_blocks(
        apply_low_residual_bits(known, assignment, 32), plaintext
    )
    row = RECOVERY._confirm(
        {
            "known_key_zeroed_residual_hex": known.hex(),
            "plaintext_hex": plaintext.hex(),
        },
        {"width": 32},
        expected,
        assignment,
        "factual",
        _sha256(INDEPENDENT_SOURCE),
    )
    assert row["scalar_independent_identity"] is True
    assert row["complete_two_block_match"] is True
    assert row["output_bits_checked"] == 256


def test_absolute_deadline_covers_ready_wait_and_kills_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()

    class FakeProcess:
        def __init__(self) -> None:
            self.stdin = io.StringIO()
            self.stdout = os.fdopen(read_fd)
            self.stderr = io.StringIO()
            self.returncode: int | None = None
            self.killed = False

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9
            os.close(write_fd)

        def wait(self, timeout: float) -> int:
            assert timeout == 5
            assert self.returncode is not None
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(QUALIFICATION.subprocess, "Popen", lambda *_a, **_k: process)
    with pytest.raises(TimeoutError, match="wall cap"):
        QUALIFICATION.MetalAES256Host(
            Path("unused"), deadline_monotonic=time.monotonic() + 0.01
        )
    assert process.killed is True


def test_authentic_dotcausal_v1_is_materialized_and_reader_verified(
    tmp_path: Path,
) -> None:
    execution = {
        "unknown_key_bits": 36,
        "logical_candidate_count": 1 << 36,
        "complete_domain_executed": True,
        "factual_filter_matches": [5],
        "factual_confirmations": [
            {"combined_assignment": 5, "complete_two_block_match": True}
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
    path = tmp_path / "aes256.causal"
    result = RECOVERY._build_authentic_causal(
        path=path,
        payload=payload,
        dotcausal_src=DOTCAUSAL,
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["format"] == "authentic_dotcausal_v1_AI_native"
    assert result["api_id"] == "aes256v1"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["embedded_rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"] == 1
    assert result["integrity_verified_by_authoritative_reader"] is True


def test_full_domain_runner_requires_explicit_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="explicit execute_full_domain=True"):
        RECOVERY.run(
            protocol_path=tmp_path / "missing-protocol.json",
            expected_protocol_sha256="0" * 64,
            results_dir=tmp_path,
            output=tmp_path / "result.json",
            causal_output=tmp_path / "result.causal",
            manifest_output=tmp_path / "manifest.json",
            checkpoint_path=tmp_path / "checkpoint.json",
            build_dir=tmp_path / "build",
            swiftc="swiftc",
            dotcausal_src=DOTCAUSAL,
            resume=False,
            execute_full_domain=False,
        )


def test_no_neighbor_factory_clone_residue() -> None:
    files = [
        "aes256_metal_native.swift",
        "aes256_metal_qualification.py",
        "aes256_metal_protocol_factory.py",
        "aes256_metal_recovery.py",
    ]
    forbidden = ["Ascon", "RC5", "SIMON", "SPECK", "PRESENT", "A247", "A248", "A255", "A256"]
    for filename in files:
        source = (EXPERIMENTS / filename).read_text()
        assert not [token for token in forbidden if token in source], filename
