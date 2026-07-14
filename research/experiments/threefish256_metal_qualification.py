#!/usr/bin/env python3
"""Qualify and benchmark a native full-round Threefish-256 Metal enumerator."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import statistics
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import threefish256_encrypt

ATTEMPT_ID = "A238"
SCHEMA = "threefish256-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "threefish256_metal_native.swift"
NATIVE_VERSION = "threefish256-metal-native-v1"
FILTER_WORDS32 = 8
RESULT_CAPACITY = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 22
DEFAULT_REPEATS = 5
MASK64 = (1 << 64) - 1
ZERO_KAT_OUTPUT = [
    0x94EEEA8B1F2ADA84,
    0xADF103313EAE6670,
    0x952419A1F4B16D53,
    0xD83F13E63C9F6B11,
]
NONZERO_KAT_PLAINTEXT = [
    0xF8F9FAFBFCFDFEFF,
    0xF0F1F2F3F4F5F6F7,
    0xE8E9EAEBECEDEEEF,
    0xE0E1E2E3E4E5E6E7,
]
NONZERO_KAT_KEY = [
    0x1716151413121110,
    0x1F1E1D1C1B1A1918,
    0x2726252423222120,
    0x2F2E2D2C2B2A2928,
]
NONZERO_KAT_TWEAK = [0x0706050403020100, 0x0F0E0D0C0B0A0908]
NONZERO_KAT_OUTPUT = [
    0xDF8FEA0EFF91D0E0,
    0xD50AD82EE69281C9,
    0x76F48D58085D869D,
    0xDF975E95B5567065,
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _halves(words: Sequence[int]) -> np.ndarray:
    output = np.empty(2 * len(words), dtype=np.uint32)
    for index, word in enumerate(words):
        word = int(word)
        if word < 0 or word > MASK64:
            raise ValueError("Threefish word must fit in uint64")
        output[2 * index] = word & 0xFFFFFFFF
        output[2 * index + 1] = word >> 32
    return output


def _words(halves: Sequence[int]) -> list[int]:
    if len(halves) % 2:
        raise ValueError("uint32 half array must have even length")
    return [
        int(halves[index]) | (int(halves[index + 1]) << 32)
        for index in range(0, len(halves), 2)
    ]


def _candidate_key(candidate: int, key_words: np.ndarray) -> list[int]:
    if candidate < 0 or candidate > 0xFFFFFFFF:
        raise ValueError("candidate must fit in uint32")
    if key_words.shape != (8,):
        raise ValueError("key_words must contain eight uint32 halves")
    words = _words(key_words)
    words[0] = candidate | (int(key_words[1]) << 32)
    return words


def _scalar_output(
    candidate: int,
    plaintext: np.ndarray,
    key_words: np.ndarray,
    tweak_words: np.ndarray,
) -> np.ndarray:
    output = threefish256_encrypt(
        _words(plaintext),
        _candidate_key(candidate, key_words),
        _words(tweak_words),
        72,
    )
    return _halves(output)


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"threefish256_metal_{source_sha[:16]}"
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
        raise RuntimeError(
            "Threefish-256 Swift/Metal host compilation failed: "
            + result.stderr.strip()
        )
    temporary.replace(output)
    version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
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


class MetalThreefish256Host:
    def __init__(self, executable: Path):
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
            or not str(metal.get("device", "")).startswith("Apple")
            or int(metal.get("filter_execution_width", 0)) <= 0
            or int(metal.get("filter_max_threads_per_group", 0)) < 256
            or metal.get("shader_runtime_compiled") is not True
            or metal.get("native_64_bit_integer_arithmetic") is not True
        ):
            self.close(force=True)
            raise RuntimeError("Threefish-256 Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError("Threefish-256 Metal host closed unexpectedly: " + diagnostics)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Threefish-256 Metal host returned a non-object")
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("Threefish-256 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        plaintext: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
        key_words: np.ndarray,
        tweak_words: np.ndarray,
    ) -> None:
        response = self._request(
            {
                "op": "configure",
                "plaintext": [int(value) for value in plaintext],
                "target": [int(value) for value in target],
                "control": [int(value) for value in control],
                "key_words": [int(value) for value in key_words],
                "tweak_words": [int(value) for value in tweak_words],
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("plaintext_blocks") != 1
            or response.get("filter_words") != FILTER_WORDS32
        ):
            raise RuntimeError("Threefish-256 Metal configuration gate failed")

    def blocks(self, first: int, count: int) -> np.ndarray:
        response = self._request({"op": "blocks", "first": first, "count": count})
        words = np.array(response.get("words", []), dtype=np.uint32)
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or words.size != count * FILTER_WORDS32
        ):
            raise RuntimeError("Threefish-256 Metal block response gate failed")
        return words.reshape(count, FILTER_WORDS32)

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
            or float(response.get("gpu_seconds", -1.0)) < 0.0
        ):
            raise RuntimeError("Threefish-256 Metal filter response gate failed")
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
            raise RuntimeError(
                "Threefish-256 Metal host exit failed: " + self.process.stderr.read()
            )


def _configure_case(
    host: MetalThreefish256Host,
    *,
    plaintext64: Sequence[int],
    key64: Sequence[int],
    tweak64: Sequence[int],
    target64: Sequence[int],
) -> tuple[int, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    candidate = int(key64[0]) & 0xFFFFFFFF
    plaintext = _halves(plaintext64)
    key_words = _halves(key64)
    key_words[0] = 0
    tweak = _halves(tweak64)
    target = _halves(target64)
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key_words=key_words,
        tweak_words=tweak,
    )
    return candidate, plaintext, key_words, tweak, target


def _kat_gate(host: MetalThreefish256Host) -> dict[str, Any]:
    cases = [
        {
            "name": "official_zero",
            "plaintext": [0, 0, 0, 0],
            "key": [0, 0, 0, 0],
            "tweak": [0, 0],
            "expected": ZERO_KAT_OUTPUT,
        },
        {
            "name": "official_nonzero",
            "plaintext": NONZERO_KAT_PLAINTEXT,
            "key": NONZERO_KAT_KEY,
            "tweak": NONZERO_KAT_TWEAK,
            "expected": NONZERO_KAT_OUTPUT,
        },
    ]
    rows = []
    for case in cases:
        candidate, plaintext, key_words, tweak, expected = _configure_case(
            host,
            plaintext64=case["plaintext"],
            key64=case["key"],
            tweak64=case["tweak"],
            target64=case["expected"],
        )
        scalar = _scalar_output(candidate, plaintext, key_words, tweak)
        observed = host.blocks(candidate, 1)[0]
        filtered = host.filter(candidate, 1)
        if (
            not np.array_equal(scalar, expected)
            or not np.array_equal(observed, expected)
            or filtered["factual"] != [candidate]
            or filtered["control"] != []
        ):
            raise RuntimeError(f"Threefish-256 {case['name']} KAT gate failed")
        rows.append(
            {
                "name": case["name"],
                "candidate": candidate,
                "expected_words_hex": [f"{word:016x}" for word in case["expected"]],
                "actual_words_hex": [f"{word:016x}" for word in _words(observed)],
                "exact_scalar_and_Metal_identity": True,
            }
        )
    return {
        "source": "Skein 1.3 specification and official submission KATs",
        "cases": rows,
        "all_passed": True,
    }


def _cross_gate(host: MetalThreefish256Host) -> dict[str, Any]:
    first = 123_456_789
    count = 256
    offset = 73
    plaintext = _halves([0x0123456789ABCDEF, 0x0, 0xFEDCBA9876543210, 0x55AA])
    key_words = _halves(
        [0xA5A5A5A500000000, 0x1337, 0xCAFEBABEDEADBEEF, 0x0102030405060708]
    )
    tweak = _halves([0x1122334455667788, 0x99AABBCCDDEEFF00])
    expected = np.stack(
        [
            _scalar_output(candidate, plaintext, key_words, tweak)
            for candidate in range(first, first + count)
        ]
    )
    target = expected[offset].copy()
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key_words=key_words,
        tweak_words=tweak,
    )
    observed = host.blocks(first, count)
    filtered = host.filter(first, count)
    if (
        not np.array_equal(observed, expected)
        or filtered["factual"] != [first + offset]
        or filtered["control"] != []
    ):
        raise RuntimeError("Threefish-256 Metal/scalar cross gate failed")
    return {
        "first_candidate": first,
        "candidate_count": count,
        "target_candidate": first + offset,
        "complete_output_bits_checked": int(observed.size * 32),
        "output_sha256": _sha256(observed.astype("<u4", copy=False).tobytes()),
        "exact_scalar_identity": True,
        "exact_filter_identity": True,
    }


def _boundary_gate(host: MetalThreefish256Host) -> dict[str, Any]:
    target_candidate = 0x90210FED
    plaintext = _halves([1, 2, 3, 4])
    key_words = _halves([0xBEEFCAFE00000000, 5, 6, 7])
    tweak = _halves([8, 9])
    target = _scalar_output(target_candidate, plaintext, key_words, tweak)
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key_words=key_words,
        tweak_words=tweak,
    )
    intervals = [(0, 256), (target_candidate - 128, 256), (2**32 - 256, 256)]
    rows = []
    for first, count in intervals:
        response = host.filter(first, count)
        expected = [target_candidate] if first <= target_candidate < first + count else []
        if response["factual"] != expected or response["control"] != []:
            raise RuntimeError("Threefish-256 Metal boundary gate failed")
        rows.append(
            {
                "first_candidate": first,
                "candidate_count": count,
                "factual_matches": response["factual"],
                "control_matches": response["control"],
            }
        )
    return {"target_candidate": target_candidate, "intervals": rows, "exact": True}


def _benchmark(
    host: MetalThreefish256Host, *, candidate_count: int, repeats: int
) -> dict[str, Any]:
    if candidate_count < 1 or candidate_count > 2**32 or repeats < 1:
        raise ValueError("invalid Threefish-256 benchmark dimensions")
    plaintext = _halves([0x1234, 0x5678, 0x9ABC, 0xDEF0])
    key_words = _halves([0xA5A5A5A500000000, 1, 2, 3])
    tweak = _halves([4, 5])
    target = _scalar_output(0x2468ACE0, plaintext, key_words, tweak)
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key_words=key_words,
        tweak_words=tweak,
    )
    host.filter(0, min(candidate_count, 1 << 18))
    samples = []
    for _ in range(repeats):
        response = host.filter(0, candidate_count)
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0.0:
            raise RuntimeError("Threefish-256 Metal benchmark returned zero GPU time")
        samples.append(
            {
                "candidate_count": candidate_count,
                "gpu_seconds": gpu_seconds,
                "candidates_per_second": candidate_count / gpu_seconds,
                "factual_matches": response["factual"],
                "control_matches": response["control"],
            }
        )
    throughputs = [row["candidates_per_second"] for row in samples]
    median = statistics.median(throughputs)
    return {
        "candidate_count_per_repeat": candidate_count,
        "repeats": repeats,
        "samples": samples,
        "median_candidates_per_second": median,
        "minimum_candidates_per_second": min(throughputs),
        "maximum_candidates_per_second": max(throughputs),
        "projected_complete_domain_seconds": {
            str(width): (2**width) / median for width in range(32, 43)
        },
        "volatile_performance_only_not_a_success_rule": True,
    }


def run(
    *,
    output: Path,
    build_dir: Path,
    swiftc: str,
    benchmark_candidates: int,
    repeats: int,
) -> dict[str, Any]:
    executable, build = _compile_native(build_dir, swiftc)
    host = MetalThreefish256Host(executable)
    try:
        kats = _kat_gate(host)
        cross = _cross_gate(host)
        boundary = _boundary_gate(host)
        benchmark = _benchmark(
            host, candidate_count=benchmark_candidates, repeats=repeats
        )
        identity = host.identity
    finally:
        host.close()
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "THREEFISH256_METAL_PRE_TARGET_QUALIFICATION",
        "scope": (
            "Full 72-round Threefish-256 implementation qualification and volatile "
            "throughput measurement; no production recovery target was selected or run."
        ),
        "cipher": {
            "variant": "Threefish-256",
            "block_bits": 256,
            "master_key_bits": 256,
            "tweak_bits": 128,
            "rounds": 72,
            "candidate_encoding": "uint32 candidate replaces low32 of key word 0",
            "known_plaintext_blocks_per_candidate": 1,
            "filter_output_bits": 256,
        },
        "native_build": build,
        "host_identity": identity,
        "official_kat_gates": kats,
        "cross_implementation_gate": cross,
        "boundary_filter_gate": boundary,
        "benchmark": benchmark,
        "information_boundary": {
            "production_target_selected": False,
            "production_unknown_assignment_generated": False,
            "complete_residual_key_domain_executed": False,
            "benchmark_outcome_may_select_future_width": True,
        },
    }
    _atomic_json(output, payload)
    if json.loads(output.read_text()) != payload:
        raise RuntimeError("Threefish-256 qualification artifact reopen gate failed")
    return {
        "output": str(output),
        "sha256": _file_sha256(output),
        "device": identity["metal"]["device"],
        "median_candidates_per_second": benchmark["median_candidates_per_second"],
        "projected_complete_domain_seconds": benchmark[
            "projected_complete_domain_seconds"
        ],
        "all_qualification_gates_passed": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / "threefish256_metal_qualification_v1.json",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=research_root / "build" / "threefish256_metal",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument(
        "--benchmark-candidates", type=int, default=DEFAULT_BENCHMARK_CANDIDATES
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            run(
                output=args.output,
                build_dir=args.build_dir,
                swiftc=args.swiftc,
                benchmark_candidates=args.benchmark_candidates,
                repeats=args.repeats,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
