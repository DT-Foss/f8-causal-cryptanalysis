#!/usr/bin/env python3
"""Qualify and benchmark the full-round Speck32/64 Metal key enumerator.

This module is deliberately separate from any frozen recovery challenge.  It
validates the native implementation and measures throughput without observing
or selecting a production target assignment.
"""

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

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_encrypt_block,
    speck_round_keys,
)

ATTEMPT_ID = "A236"
SCHEMA = "speck32-64-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "speck32_64_metal_native.swift"
NATIVE_VERSION = "speck32-64-metal-native-v1"
PLAINTEXT_BLOCKS = 3
WORDS_PER_BLOCK = 2
FILTER_WORDS = PLAINTEXT_BLOCKS * WORDS_PER_BLOCK
RESULT_CAPACITY = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 26
DEFAULT_REPEATS = 5
VARIANT = SPECK_VARIANTS["speck32_64"]
OFFICIAL_KAT_MASTER_KEY = [0x0100, 0x0908, 0x1110, 0x1918]
OFFICIAL_KAT_PLAINTEXT = (0x6574, 0x694C)
OFFICIAL_KAT_CIPHERTEXT = (0xA868, 0x42F2)
QUALIFICATION_PLAINTEXT = np.array(
    [0x6574, 0x694C, 0x0000, 0x0000, 0xFFFF, 0xFFFF], dtype=np.uint32
)


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


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"speck32_64_metal_{source_sha[:16]}"
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
            "Speck32/64 Swift/Metal host compilation failed: " + result.stderr.strip()
        )
    temporary.replace(output)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("Speck32/64 Swift/Metal host build produced no executable")
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


def _candidate_words(candidate: int, key2: int, key3: int) -> list[int]:
    if candidate < 0 or candidate > 0xFFFFFFFF:
        raise ValueError("candidate must fit in uint32")
    if key2 < 0 or key2 > 0xFFFF or key3 < 0 or key3 > 0xFFFF:
        raise ValueError("key2 and key3 must fit in uint16")
    return [candidate & 0xFFFF, (candidate >> 16) & 0xFFFF, key2, key3]


def _scalar_outputs(
    candidate: int,
    key2: int,
    key3: int,
    plaintext: np.ndarray = QUALIFICATION_PLAINTEXT,
) -> np.ndarray:
    if plaintext.shape != (FILTER_WORDS,) or np.any(plaintext > 0xFFFF):
        raise ValueError("plaintext must contain six uint16 words")
    round_keys = speck_round_keys(
        VARIANT, _candidate_words(candidate, key2, key3), VARIANT.full_rounds
    )
    output = np.empty(FILTER_WORDS, dtype=np.uint32)
    for offset in range(0, FILTER_WORDS, WORDS_PER_BLOCK):
        x, y = speck_encrypt_block(
            int(plaintext[offset]), int(plaintext[offset + 1]), round_keys, VARIANT
        )
        output[offset] = x
        output[offset + 1] = y
    return output


class MetalSpeck3264Host:
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
        ):
            self.close(force=True)
            raise RuntimeError("Speck32/64 Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError("Speck32/64 Metal host closed unexpectedly: " + diagnostics)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Speck32/64 Metal host returned a non-object")
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("Speck32/64 Metal host is not running")
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
        key2: int,
        key3: int,
    ) -> None:
        response = self._request(
            {
                "op": "configure",
                "plaintext": [int(value) for value in plaintext],
                "target": [int(value) for value in target],
                "control": [int(value) for value in control],
                "key2": key2,
                "key3": key3,
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("plaintext_blocks") != PLAINTEXT_BLOCKS
            or response.get("filter_words") != FILTER_WORDS
        ):
            raise RuntimeError("Speck32/64 Metal configuration gate failed")

    def blocks(self, first: int, count: int) -> np.ndarray:
        response = self._request({"op": "blocks", "first": first, "count": count})
        words = np.array(response.get("words", []), dtype=np.uint32)
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or words.size != count * FILTER_WORDS
        ):
            raise RuntimeError("Speck32/64 Metal block response gate failed")
        return words.reshape(count, FILTER_WORDS)

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
            raise RuntimeError("Speck32/64 Metal filter response gate failed")
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
                "Speck32/64 Metal host exit failed: " + self.process.stderr.read()
            )


def _kat_gate(host: MetalSpeck3264Host) -> dict[str, Any]:
    candidate = OFFICIAL_KAT_MASTER_KEY[0] | (OFFICIAL_KAT_MASTER_KEY[1] << 16)
    key2, key3 = OFFICIAL_KAT_MASTER_KEY[2:]
    expected = _scalar_outputs(candidate, key2, key3)
    control = expected.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=expected,
        control=control,
        key2=key2,
        key3=key3,
    )
    observed = host.blocks(candidate, 1)[0]
    filtered = host.filter(candidate, 1)
    if (
        tuple(int(value) for value in observed[:2]) != OFFICIAL_KAT_CIPHERTEXT
        or not np.array_equal(observed, expected)
        or filtered["factual"] != [candidate]
        or filtered["control"] != []
    ):
        raise RuntimeError("Speck32/64 official KAT/Metal equivalence gate failed")
    return {
        "master_key_words_paper_order": OFFICIAL_KAT_MASTER_KEY,
        "plaintext_words": list(OFFICIAL_KAT_PLAINTEXT),
        "expected_ciphertext_words": list(OFFICIAL_KAT_CIPHERTEXT),
        "actual_ciphertext_words": [int(value) for value in observed[:2]],
        "three_block_scalar_identity": True,
        "candidate_encoding": candidate,
    }


def _cross_gate(host: MetalSpeck3264Host) -> dict[str, Any]:
    first = 123_456_789
    count = 256
    offset = 73
    key2 = 0xBEEF
    key3 = 0x1337
    expected = np.stack(
        [_scalar_outputs(candidate, key2, key3) for candidate in range(first, first + count)]
    )
    target = expected[offset].copy()
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key2=key2,
        key3=key3,
    )
    observed = host.blocks(first, count)
    filtered = host.filter(first, count)
    if (
        not np.array_equal(observed, expected)
        or filtered["factual"] != [first + offset]
        or filtered["control"] != []
    ):
        raise RuntimeError("Speck32/64 Metal/scalar cross gate failed")
    return {
        "first_candidate": first,
        "candidate_count": count,
        "complete_output_bits_checked": int(observed.size * 16),
        "target_candidate": first + offset,
        "output_sha256": _sha256(observed.astype("<u4", copy=False).tobytes()),
        "exact_scalar_identity": True,
        "exact_filter_identity": True,
    }


def _boundary_gate(host: MetalSpeck3264Host) -> dict[str, Any]:
    target_candidate = 0x90210FED
    key2 = 0xCAFE
    key3 = 0xD00D
    target = _scalar_outputs(target_candidate, key2, key3)
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key2=key2,
        key3=key3,
    )
    intervals = [(0, 256), (target_candidate - 128, 256), (2**32 - 256, 256)]
    rows = []
    for first, count in intervals:
        result = host.filter(first, count)
        expected = [target_candidate] if first <= target_candidate < first + count else []
        if result["factual"] != expected or result["control"] != []:
            raise RuntimeError("Speck32/64 Metal boundary filter gate failed")
        rows.append(
            {
                "first_candidate": first,
                "candidate_count": count,
                "factual_matches": result["factual"],
                "control_matches": result["control"],
            }
        )
    return {
        "target_candidate": target_candidate,
        "intervals": rows,
        "exact_boundary_identity": True,
    }


def _benchmark(
    host: MetalSpeck3264Host,
    *,
    candidate_count: int,
    repeats: int,
) -> dict[str, Any]:
    if candidate_count < 1 or candidate_count > 2**32:
        raise ValueError("benchmark candidate count must be in 1...2^32")
    if repeats < 1:
        raise ValueError("benchmark repeats must be positive")
    key2 = 0x6EED
    key3 = 0x5EED
    target = _scalar_outputs(0x2468ACE0, key2, key3)
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key2=key2,
        key3=key3,
    )
    # Compile and allocate once before collecting timed samples.
    host.filter(0, min(candidate_count, 1 << 20))
    samples = []
    for _ in range(repeats):
        response = host.filter(0, candidate_count)
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0.0:
            raise RuntimeError("Speck32/64 Metal benchmark returned zero GPU time")
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
            str(width): (2**width) / median for width in range(40, 49)
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
    host = MetalSpeck3264Host(executable)
    try:
        kat = _kat_gate(host)
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
        "evidence_stage": "SPECK32_64_METAL_PRE_TARGET_QUALIFICATION",
        "scope": (
            "Full 22-round Speck32/64 implementation qualification and volatile "
            "throughput measurement; no production recovery target was selected or run."
        ),
        "cipher": {
            "variant": "Speck32/64",
            "block_bits": 32,
            "master_key_bits": 64,
            "rounds": 22,
            "candidate_encoding": "low16=k0, high16=l0, configured_key2=l1, key3=l2",
            "known_plaintext_blocks_per_candidate": PLAINTEXT_BLOCKS,
            "filter_output_bits": FILTER_WORDS * 16,
        },
        "native_build": build,
        "host_identity": identity,
        "official_kat_gate": kat,
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
    reopened = json.loads(output.read_text())
    if reopened != payload:
        raise RuntimeError("Speck32/64 qualification artifact reopen gate failed")
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
        default=research_root / "results" / "v1" / "speck32_64_metal_qualification_v1.json",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=research_root / "build" / "speck32_64_metal",
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
