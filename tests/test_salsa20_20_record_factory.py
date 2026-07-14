from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from arx_carry_leak.salsa20_reference import (
    BERNSTEIN_REFERENCE_SHA256,
    SPEC_256_EXPANSION_KAT,
    SPECIFICATION_PDF_SHA256,
    block,
    crypt,
    verify_specification_kats,
)


def _load(filename: str, name: str) -> Any:
    path = Path(__file__).parents[1] / "research" / "experiments" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


QUALIFICATION = _load("salsa20_20_metal_qualification.py", "salsa20_a263_qualification_tested")
FACTORY = _load("salsa20_20_metal_protocol_factory.py", "salsa20_a264_factory_tested")
RECOVERY = _load("salsa20_20_metal_recovery.py", "salsa20_a264_recovery_tested")
ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "research" / "experiments"
REFERENCE = ROOT / "src" / "arx_carry_leak" / "salsa20_reference.py"
NATIVE = EXPERIMENTS / "salsa20_20_metal_native.swift"
QUALIFICATION_SOURCE = EXPERIMENTS / "salsa20_20_metal_qualification.py"
PROTOCOL_FACTORY = EXPERIMENTS / "salsa20_20_metal_protocol_factory.py"
RECOVERY_SOURCE = EXPERIMENTS / "salsa20_20_metal_recovery.py"
PREFLIGHT_MANIFEST = (
    ROOT / "research" / "provenance" / "salsa20_20_a263_a264_record_factory_manifest_v1.json"
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _synthetic_qualification_payload(width: int = 36, stream: int = 1 << 16) -> dict[str, Any]:
    return {
        "schema": QUALIFICATION.SCHEMA,
        "attempt_id": "A263",
        "recovery_attempt_id": "A264",
        "evidence_stage": "SALSA20_20_METAL_PRE_TARGET_QUALIFICATION",
        "algorithm": {
            "rounds": 20,
            "key_bits": 256,
            "byte_semantics": "Bernstein_little_endian",
        },
        "content_anchors": {
            "qualification_source": {"sha256": _digest(QUALIFICATION_SOURCE)},
            "native_source": {"sha256": _digest(NATIVE)},
            "cpu_reference": {"sha256": _digest(REFERENCE)},
            "protocol_factory": {"sha256": _digest(PROTOCOL_FACTORY)},
            "recovery_source": {"sha256": _digest(RECOVERY_SOURCE)},
            "primary_specification": {"pdf_sha256": SPECIFICATION_PDF_SHA256},
            "bernstein_reference": {"sha256": BERNSTEIN_REFERENCE_SHA256},
        },
        "specification_kat_gate": {
            "scalar_vectors": [{"pass": True}, {"pass": True}],
            "metal_256_bit_expansion_vector": {"exact_cpu_metal_identity": True},
        },
        "cross_implementation_gate": {"exact_cpu_metal_identity": True},
        "boundary_mapping_gate": {"exact_boundary_identity": True},
        "qualification_resource_cap": {"cannot_occupy_gpu_for_two_minutes": True},
        "information_boundary": {
            "production_target_selected": False,
            "production_protocol_frozen": False,
        },
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


def _structurally_authentic_metal_qualification() -> dict[str, Any]:
    content_anchors = {
        "qualification_source": {
            "path": str(QUALIFICATION_SOURCE),
            "sha256": _digest(QUALIFICATION_SOURCE),
        },
        "native_source": {"path": str(NATIVE), "sha256": _digest(NATIVE)},
        "cpu_reference": {"path": str(REFERENCE), "sha256": _digest(REFERENCE)},
        "protocol_factory": {
            "path": str(PROTOCOL_FACTORY),
            "sha256": _digest(PROTOCOL_FACTORY),
        },
        "recovery_source": {
            "path": str(RECOVERY_SOURCE),
            "sha256": _digest(RECOVERY_SOURCE),
        },
        "primary_specification": {
            "url": QUALIFICATION.SPECIFICATION_URL,
            "pdf_sha256": SPECIFICATION_PDF_SHA256,
        },
        "bernstein_reference": {
            "url": QUALIFICATION.BERNSTEIN_REFERENCE_URL,
            "sha256": BERNSTEIN_REFERENCE_SHA256,
        },
    }
    candidate_count = 1 << 16
    wall_rates = [12_000_000.0, 13_000_000.0]
    rows = []
    for wall_rate in wall_rates:
        wall_seconds = candidate_count / wall_rate
        gpu_seconds = wall_seconds * 0.8
        rows.append(
            {
                "candidate_count": candidate_count,
                "gpu_seconds": gpu_seconds,
                "end_to_end_wall_seconds": wall_seconds,
                "gpu_candidates_per_second": candidate_count / gpu_seconds,
                "end_to_end_candidates_per_second": wall_rate,
                "factual_matches": [],
                "control_matches": [],
            }
        )
    minimum = min(wall_rates)
    stream = QUALIFICATION._recommended_stream_count(minimum)
    benchmark = {
        "rows": rows,
        "candidate_count_per_repeat": candidate_count,
        "repeat_count": len(rows),
        "minimum_end_to_end_candidates_per_second": minimum,
        "median_end_to_end_candidates_per_second": QUALIFICATION.statistics.median(wall_rates),
        "minimum_gpu_candidates_per_second": min(row["gpu_candidates_per_second"] for row in rows),
        "median_gpu_candidates_per_second": QUALIFICATION.statistics.median(
            [row["gpu_candidates_per_second"] for row in rows]
        ),
        "recommended_stream_candidate_count": stream,
        "recommended_stream_seconds_at_minimum": stream / minimum,
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum
            for width in range(
                QUALIFICATION.MIN_RESIDUAL_WIDTH,
                QUALIFICATION.MAX_RESIDUAL_WIDTH + 1,
            )
        },
        "maximum_candidate_evaluations": (
            QUALIFICATION.MAX_BENCHMARK_CANDIDATES * QUALIFICATION.MAX_BENCHMARK_REPEATS
        ),
        "timed_relation_bits": 512,
        "volatile_performance_only_not_recovery_evidence": True,
    }
    launch = QUALIFICATION._launch_gate(benchmark)
    assert launch["selected_width"] == 36
    expected_words = QUALIFICATION._bytes_to_words(bytes.fromhex(SPEC_256_EXPANSION_KAT.output_hex))
    kat = {
        "primary_specification_url": QUALIFICATION.SPECIFICATION_URL,
        "primary_specification_pdf_sha256": SPECIFICATION_PDF_SHA256,
        "bernstein_reference_url": QUALIFICATION.BERNSTEIN_REFERENCE_URL,
        "bernstein_reference_sha256": BERNSTEIN_REFERENCE_SHA256,
        "scalar_vectors": verify_specification_kats(),
        "metal_256_bit_expansion_vector": {
            "expected_words": expected_words,
            "actual_words": expected_words,
            "exact_cpu_metal_identity": True,
            "gpu_seconds": 0.001,
        },
        "all_specification_kat_gates_passed": True,
    }
    cross = {**QUALIFICATION._expected_cross_static(), "gpu_seconds": 0.001}
    boundary = {
        "boundary_candidates": [
            {**row, "gpu_seconds": 0.001} for row in QUALIFICATION._expected_boundary_static()
        ],
        "exact_boundary_identity": True,
        "candidate_word_mapping": "candidate_is_key_word_0_little_endian",
        "outer_slice_mapping": "outer_slice_ors_into_low_bits_of_key_word_1",
    }
    recorded_gpu = (
        0.001
        + 0.001
        + 0.001 * len(boundary["boundary_candidates"])
        + sum(float(row["gpu_seconds"]) for row in rows)
    )
    resource = {
        "wall_deadline_seconds": QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "gpu_wall_cap_seconds": QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "host_lifetime_started_monotonic": 1000.0,
        "absolute_deadline_monotonic": (
            1000.0 + QUALIFICATION.QUALIFICATION_METAL_WALL_CAP_SECONDS
        ),
        "host_lifetime_finished_monotonic": 1001.0,
        "actual_wall_seconds_host_lifetime": 1.0,
        "reported_total_gpu_seconds": recorded_gpu,
        "maximum_benchmark_candidates_per_repeat": (QUALIFICATION.MAX_BENCHMARK_CANDIDATES),
        "maximum_benchmark_repeats": QUALIFICATION.MAX_BENCHMARK_REPEATS,
        "max_candidates_per_repeat": QUALIFICATION.MAX_BENCHMARK_CANDIDATES,
        "max_repeats": QUALIFICATION.MAX_BENCHMARK_REPEATS,
        "subprocess_killed_on_deadline": True,
        "deadline_covers_ready_wait": True,
        "deadline_covers_every_response_wait": True,
        "constructor_cleanup_on_startup_failure": True,
        "cannot_occupy_gpu_for_two_minutes": True,
    }
    host_ready = {
        "op": "ready",
        "version": QUALIFICATION.NATIVE_VERSION,
        "metal": {
            "device": "Apple structural fixture",
            "filter_execution_width": 32,
            "shader_runtime_compiled": True,
            "salsa20_rounds": 20,
            "complete_block_words": 16,
        },
    }
    native_build = {
        "source": str(NATIVE),
        "source_sha256": _digest(NATIVE),
        "executable": "structural-fixture",
        "executable_sha256": "ab" * 32,
        "compiler": "/usr/bin/swiftc",
        "compiler_version": "Swift structural fixture",
        "selected_flags": [
            "-O",
            "-whole-module-optimization",
            "-warnings-as-errors",
        ],
        "warnings_as_errors": True,
        "compile_command": ["swiftc"],
    }
    payload = {
        "schema": QUALIFICATION.SCHEMA,
        "attempt_id": QUALIFICATION.ATTEMPT_ID,
        "recovery_attempt_id": QUALIFICATION.RECOVERY_ATTEMPT_ID,
        "evidence_stage": QUALIFICATION.STAGE,
        "algorithm": {
            "name": "Salsa20/20",
            "rounds": 20,
            "key_bits": 256,
            "nonce_bits": 64,
            "counter_bits": 64,
            "output_block_bits": 512,
            "byte_semantics": "Bernstein_little_endian",
        },
        "content_anchors": content_anchors,
        "content_anchors_sha256": QUALIFICATION._canonical_sha256(content_anchors),
        "specification_kat_gate": kat,
        "cross_implementation_gate": cross,
        "boundary_mapping_gate": boundary,
        "benchmark": benchmark,
        "qualification_resource_cap": resource,
        "launch_gate": launch,
        "native_build": native_build,
        "host_ready_record": host_ready,
        "host_identity": host_ready["metal"],
        "host_platform": "structural fixture",
        "information_boundary": {
            "production_target_selected": False,
            "production_secret_generated": False,
            "production_protocol_frozen": False,
            "full_domain_launched": False,
            "benchmark_independent_of_future_production_target": True,
        },
        "metal_executed": True,
        "full_domain_launched": False,
    }
    ledger = QUALIFICATION._build_metal_evidence_ledger(
        content_anchors_sha256=payload["content_anchors_sha256"],
        native_build=native_build,
        host_ready=host_ready,
        kat_gate=kat,
        cross_gate=cross,
        boundary_gate=boundary,
        benchmark=benchmark,
        launch_gate=launch,
        resource_cap=resource,
    )
    payload["metal_evidence_ledger"] = ledger
    payload["metal_evidence_ledger_sha256"] = QUALIFICATION._canonical_sha256(ledger)
    return payload


def _rebind_ledger(payload: dict[str, Any]) -> None:
    payload["metal_evidence_ledger"] = QUALIFICATION._build_metal_evidence_ledger(
        content_anchors_sha256=payload["content_anchors_sha256"],
        native_build=payload["native_build"],
        host_ready=payload["host_ready_record"],
        kat_gate=payload["specification_kat_gate"],
        cross_gate=payload["cross_implementation_gate"],
        boundary_gate=payload["boundary_mapping_gate"],
        benchmark=payload["benchmark"],
        launch_gate=payload["launch_gate"],
        resource_cap=payload["qualification_resource_cap"],
    )
    payload["metal_evidence_ledger_sha256"] = QUALIFICATION._canonical_sha256(
        payload["metal_evidence_ledger"]
    )


def test_primary_specification_kats_and_fullround_reference() -> None:
    rows = verify_specification_kats()
    assert len(rows) == 2
    assert all(row["pass"] is True for row in rows)
    vector = SPEC_256_EXPANSION_KAT
    key = bytes.fromhex(vector.key_hex)
    input16 = bytes.fromhex(vector.input_hex)
    actual = block(key, input16[:8], int.from_bytes(input16[8:], "little"))
    assert actual.hex() == vector.output_hex


def test_stream_cipher_roundtrip_and_counter_separation() -> None:
    key = bytes(range(32))
    nonce = bytes(range(8))
    message = bytes(range(256))
    ciphertext = crypt(message, key, nonce, counter=7)
    assert ciphertext != message
    assert crypt(ciphertext, key, nonce, counter=7) == message
    assert block(key, nonce, 7) != block(key, nonce, 8)


def test_independent_direct_schedule_matches_reference() -> None:
    vectors = [
        (bytes(32), bytes(8), 0),
        (bytes(range(32)), bytes.fromhex("0011223344556677"), 0xFFEEDDCCBBAA9988),
        (bytes(reversed(range(32))), bytes.fromhex("fedcba9876543210"), 2**64 - 1),
    ]
    for key, nonce, counter in vectors:
        assert RECOVERY._independent_block(key, nonce, counter) == block(key, nonce, counter)


@pytest.mark.parametrize(
    ("width", "outer_bits", "mask"),
    [
        (32, 0, 0xFFFFFFFF),
        (33, 1, 0xFFFFFFFE),
        (43, 11, 0xFFFFF800),
        (64, 32, 0x00000000),
    ],
)
def test_residual_mapping(width: int, outer_bits: int, mask: int) -> None:
    context = FACTORY._width_context(width, 1 << 16)
    assert context["outer_bits"] == outer_bits
    assert context["key_word1_known_mask"] == mask
    known, nonce, counter, _label, _sha = FACTORY._known_material(width, 1 << 16)
    assignment = min((1 << width) - 1, (7 << 32) | 0x89ABCDEF)
    expected = FACTORY._target_for_assignment(
        assignment,
        width=width,
        stream_candidates=1 << 16,
        known_key=known,
        nonce=nonce,
        counter=counter,
    )
    challenge = {
        "known_key_zeroed_residual_hex": known.hex(),
        "nonce_hex": nonce.hex(),
        "counter": counter,
    }
    assert RECOVERY._scalar_block(challenge, context, assignment) == expected


def test_protocol_factory_import_never_selects_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        FACTORY.secrets,
        "randbits",
        lambda _width: (_ for _ in ()).throw(AssertionError("secret selected")),
    )
    reloaded = _load("salsa20_20_metal_protocol_factory.py", "salsa20_a264_factory_reimported")
    assert reloaded.ATTEMPT_ID == "A264"


def test_protocol_builder_discards_secret_and_requires_root_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    width = 36
    assignment = 0xA89ABCDEF
    qualification = tmp_path / FACTORY.QUALIFICATION_FILENAME
    payload = _structurally_authentic_metal_qualification()
    assert payload["launch_gate"]["selected_width"] == width
    qualification.write_text(json.dumps(payload) + "\n")
    monkeypatch.setattr(FACTORY.secrets, "randbits", lambda bits: assignment)
    kwargs = {
        "qualification": qualification,
        "qualification_source": QUALIFICATION_SOURCE,
        "native_source": NATIVE,
        "reference_source": REFERENCE,
        "recovery_source": RECOVERY_SOURCE,
    }
    with pytest.raises(RuntimeError, match="root review acknowledgement"):
        FACTORY.build_protocol(**kwargs, root_review_acknowledged=False)
    protocol = FACTORY.build_protocol(**kwargs, root_review_acknowledged=True)
    challenge = protocol["public_challenge"]
    serialized = json.dumps(protocol, sort_keys=True)
    assert challenge["unknown_assignment_included"] is False
    assert str(assignment) not in serialized
    assert not {
        "hidden_assignment",
        "secret_assignment",
        "unknown_assignment_value",
    } & set(challenge)
    known = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    key = (int.from_bytes(known, "little") | assignment).to_bytes(32, "little")
    target = block(key, bytes.fromhex(challenge["nonce_hex"]), int(challenge["counter"]))
    assert target.hex() == challenge["target_block_hex"]
    control = bytes.fromhex(challenge["control_block_hex"])
    assert control[:-1] == target[:-1]
    assert control[-1] == target[-1] ^ 1
    protocol_path = tmp_path / "frozen_protocol.json"
    protocol_path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    analysis = RECOVERY.analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=_digest(protocol_path),
        results_dir=tmp_path,
    )
    assert analysis["candidate_execution_started"] is False
    assert analysis["context"]["width"] == width
    assert analysis["information_boundary"]["unknown_assignment_present"] is False
    assert (
        protocol["metal_evidence_ledger_anchor"]["sha256"]
        == payload["metal_evidence_ledger_sha256"]
    )
    assert (
        analysis["anchor_gates"]["metal_evidence_ledger_sha256"]
        == payload["metal_evidence_ledger_sha256"]
    )


def test_native_source_encodes_complete_relation_and_strict_json_gate() -> None:
    source = NATIVE.read_text()
    assert "for (uint double_round = 0u; double_round < 10u; ++double_round)" in source
    assert "salsa20_quarterround(output, 15u, 12u, 13u, 14u);" in source
    assert "output[index] += input[index];" in source
    assert "uint target[16];" in source
    assert "uint control[16];" in source
    assert "for (uint index = 0u; index < 16u; ++index)" in source
    assert "CFBooleanGetTypeID" in source
    assert "exact.rounded(.towardZero) == exact" in source
    assert '"Bernstein_little_endian"' in source


def test_qualification_resource_cap_is_immutable() -> None:
    with pytest.raises(ValueError, match="benchmark candidate count"):
        QUALIFICATION._validate_benchmark_budget(QUALIFICATION.MAX_BENCHMARK_CANDIDATES + 1, 1)
    with pytest.raises(ValueError, match="benchmark repeats"):
        QUALIFICATION._validate_benchmark_budget(1, QUALIFICATION.MAX_BENCHMARK_REPEATS + 1)
    assert QUALIFICATION.QUALIFICATION_GPU_WALL_CAP_SECONDS < 120


def test_synthetic_boolean_only_qualification_is_rejected() -> None:
    with pytest.raises(RuntimeError):
        FACTORY._qualification_gate(_synthetic_qualification_payload())


def test_structurally_authentic_metal_evidence_ledger_is_recomputed() -> None:
    payload = _structurally_authentic_metal_qualification()
    claimed = payload["metal_evidence_ledger_sha256"]
    assert QUALIFICATION.validate_metal_evidence_ledger(payload) == claimed
    assert FACTORY._qualification_gate(payload) == (36, 1 << 22)


def test_metal_ledger_rejects_tampering_even_after_attacker_rehashes() -> None:
    payload = _structurally_authentic_metal_qualification()
    payload["metal_evidence_ledger"]["semantic_bindings"]["official_rounds"] = 8
    payload["metal_evidence_ledger_sha256"] = QUALIFICATION._canonical_sha256(
        payload["metal_evidence_ledger"]
    )
    with pytest.raises(RuntimeError, match="evidence ledger consistency"):
        QUALIFICATION.validate_metal_evidence_ledger(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("metal_executed", False),
        ("full_domain_launched", True),
    ],
)
def test_metal_ledger_rejects_false_execution_provenance(field: str, value: bool) -> None:
    payload = _structurally_authentic_metal_qualification()
    payload[field] = value
    with pytest.raises(RuntimeError, match="evidence ledger consistency"):
        QUALIFICATION.validate_metal_evidence_ledger(payload)


def test_metal_ledger_rejects_gpu_rate_selected_width_after_full_rebind() -> None:
    payload = _structurally_authentic_metal_qualification()
    benchmark = payload["benchmark"]
    benchmark["minimum_end_to_end_candidates_per_second"] = benchmark[
        "minimum_gpu_candidates_per_second"
    ]
    payload["launch_gate"] = QUALIFICATION._launch_gate(benchmark)
    _rebind_ledger(payload)
    with pytest.raises(RuntimeError, match="evidence ledger consistency"):
        QUALIFICATION.validate_metal_evidence_ledger(payload)


def test_metal_ledger_rejects_missing_deadline_coverage_after_full_rebind() -> None:
    payload = _structurally_authentic_metal_qualification()
    payload["qualification_resource_cap"]["deadline_covers_ready_wait"] = False
    _rebind_ledger(payload)
    with pytest.raises(RuntimeError, match="evidence ledger consistency"):
        QUALIFICATION.validate_metal_evidence_ledger(payload)


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
        QUALIFICATION.MetalSalsa2020Host(Path("unused"), deadline_monotonic=time.monotonic() + 0.01)
    assert process.killed is True
    process.stdout.close()


def test_absolute_deadline_covers_post_startup_response_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    ready = {
        "op": "ready",
        "version": QUALIFICATION.NATIVE_VERSION,
        "metal": {
            "device": "Apple test fixture",
            "filter_execution_width": 32,
            "shader_runtime_compiled": True,
            "salsa20_rounds": 20,
            "complete_block_words": 16,
        },
    }
    os.write(write_fd, (json.dumps(ready) + "\n").encode())

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
    host = QUALIFICATION.MetalSalsa2020Host(
        Path("unused"), deadline_monotonic=time.monotonic() + 0.02
    )
    os.write(write_fd, b'{"op":')
    with pytest.raises(TimeoutError, match="wall cap"):
        host.blocks(0, 1)
    assert process.killed is True
    process.stdout.close()


def test_recovery_manifest_binds_result_causal_report_and_evidence(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    causal = tmp_path / "result.causal"
    report = tmp_path / "report.md"
    output.write_bytes(b"result\n")
    causal.write_bytes(b"causal\n")
    report.write_bytes(b"report\n")
    anchors = {
        "protocol_sha256": "1" * 64,
        "qualification_sha256": "2" * 64,
        "metal_evidence_ledger_sha256": "3" * 64,
    }
    manifest = RECOVERY._artifact_manifest(
        output=output,
        causal_output=causal,
        report_output=report,
        anchor_gates=anchors,
    )
    assert manifest["metal_evidence_ledger_sha256"] == "3" * 64
    assert manifest["files"]["result"]["sha256"] == _digest(output)
    assert manifest["files"]["causal"]["sha256"] == _digest(causal)
    assert manifest["files"]["report"]["sha256"] == _digest(report)
    assert manifest["authentic_dotcausal_v1_reader_verified"] is True


def test_preflight_manifest_hashes_and_state_are_exact() -> None:
    manifest = json.loads(PREFLIGHT_MANIFEST.read_text())
    for record in manifest["files"].values():
        assert _digest(ROOT / record["path"]) == record["sha256"]
    state = manifest["factory_state"]
    assert state["offline_factory_tests_passed"] == 26
    assert state["current_swift_source_typechecked"] is True
    assert state["current_swift_host_compiled"] is False
    assert state["throughput_qualification_executed"] is False
    assert state["metal_evidence_ledger_materialized"] is False
    assert state["production_challenge_frozen"] is False
    assert state["production_domain_executed"] is False


def test_checkpoint_covers_toy_domain_and_resume_is_exact(
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
        "key_word1_known_mask": 0xFFFFFFFF,
        "key_known_mask_256": ((1 << 256) - 1) ^ 15,
    }
    target = bytes(range(64))
    control = target[:-1] + bytes([target[-1] ^ 1])
    challenge = {
        "known_key_zeroed_residual_hex": bytes(32).hex(),
        "known_key_words_little_endian": [0] * 8,
        "nonce_hex": bytes(8).hex(),
        "counter": 0,
        "counter_words_little_endian": [0, 0],
        "target_block_hex": target.hex(),
        "control_block_hex": control.hex(),
        "target_block_sha256": hashlib.sha256(target).hexdigest(),
        "control_block_sha256": hashlib.sha256(control).hexdigest(),
    }
    anchors = {
        "protocol_sha256": "1" * 64,
        "public_challenge_sha256": "2" * 64,
        "native_source_sha256": "3" * 64,
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
            "complete_512_bit_block_match": assignment == 5,
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


def test_authentic_causal_is_retained_and_reader_verified(tmp_path: Path) -> None:
    execution = {
        "unknown_key_bits": 40,
        "logical_candidate_count": 1 << 40,
        "complete_domain_executed": True,
        "factual_filter_matches": [5],
        "factual_confirmations": [{"combined_assignment": 5, "complete_512_bit_block_match": True}],
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
    path = tmp_path / "a264.causal"
    result = RECOVERY._build_authentic_causal(
        path=path, payload=payload, dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC
    )
    assert path.read_bytes()[:8] in {b"CAUSAL01", b"CAUSAL\x00\x01"}
    assert result["api_id"] == "a264"
    assert result["explicit_triplets"] == 5
    assert result["materialized_inferred_triplets"] == 2
    assert result["total_triplets"] == 7
    assert result["integrity_verified_by_authoritative_reader"] is True


def test_full_domain_runner_requires_explicit_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="explicit execute_full_domain=True"):
        RECOVERY.run(
            protocol_path=tmp_path / "missing.json",
            expected_protocol_sha256="0" * 64,
            results_dir=tmp_path,
            output=tmp_path / "result.json",
            causal_output=tmp_path / "result.causal",
            report_output=tmp_path / "report.md",
            manifest_output=tmp_path / "manifest.json",
            checkpoint_path=tmp_path / "checkpoint.json",
            build_dir=tmp_path / "build",
            swiftc="swiftc",
            dotcausal_src=RECOVERY.DEFAULT_DOTCAUSAL_SRC,
            resume=False,
            execute_full_domain=False,
        )


def test_no_neighbor_factory_clone_residue() -> None:
    files = [
        "salsa20_20_metal_native.swift",
        "salsa20_20_metal_qualification.py",
        "salsa20_20_metal_protocol_factory.py",
        "salsa20_20_metal_recovery.py",
    ]
    forbidden = ["RC5", "SIMON", "SPECK", "PRESENT", "ASCON", "A247", "A248"]
    for filename in files:
        source = (EXPERIMENTS / filename).read_text()
        assert not [token for token in forbidden if token in source], filename
