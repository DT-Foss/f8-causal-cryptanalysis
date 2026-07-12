#!/usr/bin/env python3
"""Complete-domain ChaCha20 replay on the native Apple Metal GPU."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A179 = _import_sibling(
    "chacha20_vector256_fullround_replay.py",
    "chacha20_metal_a179_anchor",
)
_A178 = _A179._A178
_A119 = _A179._A119

ATTEMPT_ID = "A181"
SCHEMA = "chacha20-metal-fullround-replay-v1"
PROTOCOL_SCHEMA = "chacha20-metal-fullround-replay-protocol-v1"
PROTOCOL_FILENAME = "chacha20_metal_fullround_replay_v1.json"
PROTOCOL_SHA256 = "9bc042c28256d3da46b9c1f5cf0b7d81b52035d0df67d40d7d32848492eaef2d"
A179_FILENAME = _A179.RESULT_FILENAME
A179_SHA256 = "73874897bf3747a0c640e00e5325f9c0502d2db7b77f6fe01590c87494f7fb93"
A179_CAUSAL_FILENAME = _A179.CAUSAL_FILENAME
A179_CAUSAL_SHA256 = "ab627294751d40647d3b1c9d5f20d852195d64fa449dea761b8cad15b24291a1"
NATIVE_SOURCE_FILENAME = "chacha20_metal_native.swift"
NATIVE_SOURCE_SHA256 = "ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816"
NATIVE_VERSION = "chacha20-metal-native-v1"
PUBLIC_RELATION_SHA256 = _A179.PUBLIC_RELATION_SHA256
EXPECTED_KEY_WORD = _A179.EXPECTED_KEY_WORD
UNKNOWN_KEY_WORD_INDEX = _A179.UNKNOWN_KEY_WORD_INDEX
UNKNOWN_INITIAL_LANE = _A179.UNKNOWN_INITIAL_LANE
WINDOW_BITS = 32
STREAM_CANDIDATES = 1 << 28
RESULT_CAPACITY = 64
FILTER_WORDS = 2
RESULT_FILENAME = "chacha20_metal_fullround_replay_v1.json"
CAUSAL_FILENAME = "chacha20_metal_fullround_replay_v1.causal"
CHECKPOINT_FILENAME = "chacha20_metal_fullround_replay_v1.checkpoint.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A179._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A179._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A181 frozen protocol hash differs")
    protocol = json.loads(raw)
    qualification = protocol.get("pre_freeze_implementation_qualification", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_small_cross_gates_and_throughput_qualification_before_any_A181_complete_domain_execution"
        or protocol.get("anchors", {}).get("A179", {}).get("sha256") != A179_SHA256
        or protocol.get("anchors", {}).get("A179", {}).get("causal_sha256") != A179_CAUSAL_SHA256
        or protocol.get("native_host", {}).get("source_sha256") != NATIVE_SOURCE_SHA256
        or qualification.get("exact_scalar_identity") is not True
        or qualification.get("complete_domain_execution_performed") is not False
        or qualification.get("throughput_is_not_part_of_the_success_rule") is not True
        or boundary.get("A179_recovered_word_used_to_prune_or_stop_GPU_enumeration") is not False
        or boundary.get("A181_complete_domain_outcome_used_before_freeze") is not False
        or protocol.get("execution_plan", {}).get("complete_domain_required") is not True
    ):
        raise RuntimeError("A181 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    result_path = results_dir / A179_FILENAME
    causal_path = results_dir / A179_CAUSAL_FILENAME
    native_path = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    observed = {
        "A179_result_sha256": _file_sha256(result_path),
        "A179_causal_sha256": _file_sha256(causal_path),
        "Metal_native_source_sha256": _file_sha256(native_path),
    }
    expected = {
        "A179_result_sha256": A179_SHA256,
        "A179_causal_sha256": A179_CAUSAL_SHA256,
        "Metal_native_source_sha256": NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A181 A179/Metal-source anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    if (
        result.get("schema") != _A179.SCHEMA
        or result.get("evidence_stage")
        != "CHACHA20_FULLROUND_VECTOR256_COMPLETE_DOMAIN_EQUIVALENCE_RETAINED"
        or result.get("execution", {}).get("complete_domain_executed") is not True
        or result.get("execution", {}).get("factual_full_matches") != [EXPECTED_KEY_WORD]
        or result.get("execution", {}).get("control_full_matches") != []
        or result.get("public_challenge_sha256") != PUBLIC_RELATION_SHA256
    ):
        raise RuntimeError("A181 retained A179 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A179_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
        or len(reader.triplets(include_inferred=False)) != 5
    ):
        raise RuntimeError("A181 retained A179 Causal gate failed")
    return result, {
        **observed,
        "A179_causal_graph_sha256": reader.graph_sha256,
        "A179_causal_provenance_verified": True,
        "A179_recovered_key_word": EXPECTED_KEY_WORD,
        "A179_complete_domain_executed": True,
    }


def _execution_plan() -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": 20,
        "unknown_key_word_bits": WINDOW_BITS,
        "known_key_bits": 224,
        "counter_bits_known": 32,
        "nonce_bits_known": 96,
        "logical_candidate_count": candidate_count,
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": candidate_count,
        "metal_thread_execution_width": 32,
        "threads_per_threadgroup": 256,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": candidate_count // STREAM_CANDIDATES,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "maximum_result_memory_bytes": 520,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "runtime_shader_compilation": True,
        "full_confirmation": "independent_NumPy_ChaCha20_all_512_output_bits",
        "control_target_required": True,
        "replays_A178_public_challenge": True,
        "wallclock_excluded_from_canonical_result": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a179, anchors = _load_anchor_gates(results_dir)
    challenge = a179["public_challenge"]
    _A178._validate_public_challenge(challenge)
    plan = _execution_plan()
    if protocol["execution_plan"] != plan or protocol["execution_plan_sha256"] != _canonical_sha256(
        plan
    ):
        raise RuntimeError("A181 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "initial_template": _A178._initial_from_challenge(challenge),
        "target": np.array(challenge["target_words"], dtype=np.uint32),
        "control_target": np.array(challenge["control_target_words"], dtype=np.uint32),
        "execution_plan": plan,
        "candidate_execution_started": False,
    }


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    if source_sha != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A181 Metal native source differs")
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"chacha20_metal_{source_sha[:16]}"
    temporary = output.with_name(f".{output.name}.tmp")
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    temporary.unlink(missing_ok=True)
    result = subprocess.run(
        [compiler, *flags, str(source), "-o", str(temporary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("A181 Swift/Metal host compilation failed: " + result.stderr.strip())
    temporary.replace(output)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("A181 Swift/Metal host build produced no executable")
    version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    return output, {
        "source_sha256": source_sha,
        "executable_sha256": _file_sha256(output),
        "host_language": "Swift_6",
        "shader_language": "Metal_Shading_Language_runtime_compiled",
        "compiler_version": version,
        "selected_flags": flags,
        "warnings_as_errors": True,
    }


class MetalChaCha20Host:
    def __init__(
        self,
        executable: Path,
        initial: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
    ):
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready = self._read()
        metal = ready.get("metal", {})
        if (
            ready.get("op") != "ready"
            or ready.get("version") != NATIVE_VERSION
            or metal.get("device") != "Apple M4"
            or metal.get("filter_execution_width") != 32
            or metal.get("filter_max_threads_per_group", 0) < 256
        ):
            self.close(force=True)
            raise RuntimeError("A181 Metal host identity gate failed")
        self.identity = ready
        configured = self._request(
            {
                "op": "configure",
                "initial": [int(value) for value in initial],
                "target": [int(value) for value in target[:FILTER_WORDS]],
                "control": [int(value) for value in control[:FILTER_WORDS]],
            }
        )
        if configured.get("op") != "configured":
            self.close(force=True)
            raise RuntimeError("A181 Metal host configuration gate failed")

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError("A181 Metal host closed unexpectedly: " + diagnostics)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("A181 Metal host returned a non-object")
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("A181 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        return self._read()

    def blocks(self, first: int, count: int) -> np.ndarray:
        response = self._request({"op": "blocks", "first": first, "count": count})
        words = np.array(response.get("words", []), dtype=np.uint32)
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or words.size != count * 16
        ):
            raise RuntimeError("A181 Metal block response gate failed")
        return words.reshape(count, 16)

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self._request(
            {
                "op": "filter",
                "first": first,
                "count": count,
                "capacity": RESULT_CAPACITY,
            }
        )
        if (
            response.get("op") != "filter"
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(response.get("factual"), list)
            or not isinstance(response.get("control"), list)
        ):
            raise RuntimeError("A181 Metal filter response gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if not force:
            response = self._request({"op": "quit"})
            if response.get("op") != "quit":
                force = True
        if force:
            self.process.kill()
        else:
            assert self.process.stdin is not None
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=5)
        if not force and code != 0:
            assert self.process.stderr is not None
            raise RuntimeError("A181 Metal host exit failed: " + self.process.stderr.read())


def _cross_implementation_gate(
    host: MetalChaCha20Host,
    protocol: dict[str, Any],
    initial_template: np.ndarray,
) -> dict[str, Any]:
    qualification = protocol["pre_freeze_implementation_qualification"]
    first = int(qualification["cross_gate_first_candidate"])
    count = int(qualification["cross_gate_candidate_count"])
    observed = host.blocks(first, count)
    scalar = np.repeat(initial_template.reshape(1, 16), count, axis=0)
    scalar[:, UNKNOWN_INITIAL_LANE] = np.arange(first, first + count, dtype=np.uint32)
    expected = (_A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
    output_sha = _sha256(observed.astype("<u4", copy=False).tobytes())
    if (
        not np.array_equal(observed, expected)
        or output_sha != qualification["cross_gate_output_sha256"]
        or observed.size * 32 != qualification["cross_gate_output_bits_checked"]
    ):
        raise RuntimeError("A181 Metal/scalar cross-implementation gate failed")
    return {
        "first_candidate": first,
        "states": count,
        "words_checked": int(observed.size),
        "state_bits_checked": int(observed.size * 32),
        "exact_match": True,
        "output_sha256": output_sha,
    }


def _boundary_filter_gate(
    host: MetalChaCha20Host,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    qualification = protocol["pre_freeze_implementation_qualification"]
    intervals = [
        tuple(int(value) for value in row) for row in qualification["boundary_filter_intervals"]
    ]
    expected_factual = qualification["boundary_expected_factual_matches"]
    expected_control = qualification["boundary_expected_control_matches"]
    rows = []
    for index, (first, count) in enumerate(intervals):
        response = host.filter(first, count)
        factual = [int(value) for value in response["factual"]]
        control = [int(value) for value in response["control"]]
        if factual != expected_factual[index] or control != expected_control[index]:
            raise RuntimeError("A181 Metal boundary-filter gate failed")
        rows.append(
            {
                "first_candidate": first,
                "candidate_count": count,
                "factual_matches": factual,
                "control_matches": control,
                "exact_expected_identity": True,
            }
        )
    return {
        "intervals_checked": len(rows),
        "logical_candidates_checked": sum(row[1] for row in intervals),
        "rows": rows,
        "exact_expected_identity": True,
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "chacha20-metal-checkpoint-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "target_block_sha256": challenge["target_block_sha256"],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
        "window_bits": WINDOW_BITS,
        "stream_candidates": STREAM_CANDIDATES,
        "result_capacity": RESULT_CAPACITY,
    }


def _enumerate_key_word(
    *,
    host: MetalChaCha20Host,
    initial: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
    challenge: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    candidate_count = 1 << WINDOW_BITS
    next_candidate = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = _checkpoint_fingerprint(challenge)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A181 checkpoint fingerprint differs")
        next_candidate = int(checkpoint["next_candidate"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        if (
            next_candidate < 0
            or next_candidate > candidate_count
            or next_candidate % STREAM_CANDIDATES != 0
            or any(value < 0 or value >= next_candidate for value in factual_filtered)
            or any(value < 0 or value >= next_candidate for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A181 checkpoint progress is invalid")
    resumed_candidate_count = next_candidate
    while next_candidate < candidate_count:
        batch_count = min(STREAM_CANDIDATES, candidate_count - next_candidate)
        response = host.filter(next_candidate, batch_count)
        factual_filtered.extend(int(value) for value in response["factual"])
        control_filtered.extend(int(value) for value in response["control"])
        next_candidate += batch_count
        _A178._A177._NATIVE._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_candidate": next_candidate,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
            },
        )
        print(f"A181 Metal candidates={next_candidate}/{candidate_count}", flush=True)
    factual_confirmations = [
        _A178._independent_confirm(initial, target, candidate) for candidate in factual_filtered
    ]
    control_confirmations = [
        _A178._independent_confirm(initial, control, candidate) for candidate in control_filtered
    ]
    factual_full = [
        row["candidate_key_word"] for row in factual_confirmations if row["complete_block_match"]
    ]
    control_full = [
        row["candidate_key_word"] for row in control_confirmations if row["complete_block_match"]
    ]
    return {
        "unknown_key_word_index": UNKNOWN_KEY_WORD_INDEX,
        "unknown_initial_lane": UNKNOWN_INITIAL_LANE,
        "logical_candidate_count": candidate_count,
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": candidate_count,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": candidate_count // STREAM_CANDIDATES,
        "resumed_candidate_count": resumed_candidate_count,
        "newly_executed_candidate_count": candidate_count - resumed_candidate_count,
        "complete_domain_executed": next_candidate == candidate_count,
        "early_stop_used": False,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_key_word": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "A179_recovered_word_used_to_prune_or_stop_GPU_enumeration": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_metal_fullround_replay",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 20,
            "unknown_key_word_bits": WINDOW_BITS,
            "logical_candidates": 1 << WINDOW_BITS,
            "execution_backend": "Apple_M4_Metal_GPU",
        },
    )
    ids = [
        "chacha20-a179-complete-domain-anchor",
        "chacha20-a181-metal-protocol-freeze",
        "chacha20-a181-metal-native-equivalence",
        "chacha20-a181-metal-complete-domain-replay",
        "chacha20-a181-fullround-metal-equivalence",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A179:retained_fullround_vector256_complete_domain_equivalence",
        mechanism="anchor_the_exact_2^32_ChaCha20_domain_and_recovered_word",
        outcome="A181:Metal_complete_domain_execution_question",
        confidence=1.0,
        evidence_kind="retained_A179_complete_domain_anchor",
        source=A179_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A181:Metal_complete_domain_execution_question",
        mechanism="freeze_the_persistent_Metal_execution_plan_before_any_complete_domain_GPU_run",
        outcome="A181:frozen_Metal_fullround_replay_protocol",
        confidence=1.0,
        evidence_kind="pre_complete_domain_Metal_protocol_freeze",
        source=PROTOCOL_SHA256,
        provenance=[ids[0]],
        attrs={"protocol_gate": payload["protocol_gate"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A181:frozen_Metal_fullround_replay_protocol",
        mechanism="cross_validate_256_complete_blocks_and_three_boundary_filter_intervals",
        outcome="A181:verified_Metal_ChaCha20_reader",
        confidence=1.0,
        evidence_kind="Metal_scalar_full_block_and_filter_equivalence",
        source=NATIVE_SOURCE_SHA256,
        provenance=[ids[1]],
        attrs={
            "native_build": payload["native_build"],
            "host_identity": payload["host_identity"],
            "cross_gate": payload["native_cross_implementation_gate"],
            "boundary_gate": payload["native_boundary_filter_gate"],
        },
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A181:verified_Metal_ChaCha20_reader",
        mechanism="dispatch_all_2^32_key_word_assignments_without_early_stop",
        outcome="A181:complete_Metal_fullround_replay",
        confidence=1.0,
        evidence_kind="complete_Metal_candidate_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A181:complete_Metal_fullround_replay",
        mechanism="independently_confirm_the_exact_A179_word_over_all_512_bits_and_reject_the_control",
        outcome="A181:fullround_Metal_complete_domain_equivalence",
        confidence=1.0,
        evidence_kind="independent_complete_block_Metal_equivalence",
        source=payload["equivalence_sha256"],
        provenance=[ids[3]],
        attrs={"equivalence": payload["equivalence"]},
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A181 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    build_dir: Path,
    checkpoint_path: Path,
    swiftc: str,
    resume: bool,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    executable, native_build = _compile_native(build_dir, swiftc)
    host = MetalChaCha20Host(
        executable,
        analysis["initial_template"],
        analysis["target"],
        analysis["control_target"],
    )
    try:
        cross_gate = _cross_implementation_gate(
            host,
            analysis["protocol"],
            analysis["initial_template"],
        )
        boundary_gate = _boundary_filter_gate(host, analysis["protocol"])
        execution = _enumerate_key_word(
            host=host,
            initial=analysis["initial_template"],
            target=analysis["target"],
            control=analysis["control_target"],
            challenge=analysis["public_challenge"],
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        host_identity = host.identity
    finally:
        host.close()
    equivalence = {
        "complete_domain_executed": execution["complete_domain_executed"],
        "A179_recovered_key_word": EXPECTED_KEY_WORD,
        "A181_factual_filter_matches": execution["factual_filter_matches"],
        "A181_factual_full_matches": execution["factual_full_matches"],
        "A181_control_full_matches": execution["control_full_matches"],
        "exact_A179_recovery_identity": execution["factual_full_matches"] == [EXPECTED_KEY_WORD],
        "control_target_rejected": execution["control_full_matches"] == [],
        "independent_confirmation_bits": 512,
        "early_stop_used": execution["early_stop_used"],
    }
    if (
        equivalence["complete_domain_executed"] is not True
        or equivalence["exact_A179_recovery_identity"] is not True
        or equivalence["control_target_rejected"] is not True
        or equivalence["early_stop_used"] is not False
    ):
        raise RuntimeError("A181 complete-domain equivalence gate failed")
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CHACHA20_FULLROUND_METAL_COMPLETE_DOMAIN_EQUIVALENCE_RETAINED",
        "result": (
            "The native Apple M4 Metal Causal Reader executes the complete 2^32 "
            "ChaCha20 key-word domain, reproduces the exact A179 full-block match, "
            "and rejects the bit-flipped control."
        ),
        "scope": (
            "Standard 20-round ChaCha20 block-function replay of the frozen A178 "
            "32-bit partial-key challenge on the Apple M4 Metal GPU."
        ),
        "parameters": {
            "rounds": 20,
            "unknown_key_word_bits": WINDOW_BITS,
            "logical_candidate_count": 1 << WINDOW_BITS,
            "execution_backend": "Apple_M4_Metal_GPU",
            "stream_candidate_count": STREAM_CANDIDATES,
            "volatile_wallclock_excluded_from_canonical_result": True,
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "pre_freeze_implementation_qualification": analysis["protocol"][
                "pre_freeze_implementation_qualification"
            ],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "kat": _A119._kat(),
        "native_build": native_build,
        "host_identity": host_identity,
        "native_cross_implementation_gate": cross_gate,
        "native_boundary_filter_gate": boundary_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key not in {"factual_confirmations", "control_confirmations"}
            }
        ),
        "equivalence": equivalence,
        "equivalence_sha256": _canonical_sha256(equivalence),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    checkpoint_path.unlink(missing_ok=True)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A181 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_key_words": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=research_root / "results" / "v1" / CHECKPOINT_FILENAME,
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "chacha-metal",
    )
    parser.add_argument("--swiftc", default=os.environ.get("SWIFTC", "swiftc"))
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "anchor_gates": analysis["anchor_gates"],
                    "public_challenge_sha256": PUBLIC_RELATION_SHA256,
                    "execution_plan": analysis["execution_plan"],
                    "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
                    "candidate_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                build_dir=args.build_dir.resolve(),
                checkpoint_path=args.checkpoint.resolve(),
                swiftc=args.swiftc,
                resume=args.resume,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
