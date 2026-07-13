"""Symbolic-output R20 CNF template with target-independent topology."""

from __future__ import annotations

import hashlib
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Sequence

import numpy as np


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def symbolic_formula(r20: Any, public_challenge: dict[str, Any]) -> str:
    formula = r20._source_formula(public_challenge)
    initial = r20.P1._initial_expressions(public_challenge)
    declarations = "\n".join(
        f"(declare-fun t{lane} () (_ BitVec 32))" for lane in range(16)
    )
    formula = formula.replace(
        "(declare-fun k0 () (_ BitVec 32))",
        "(declare-fun k0 () (_ BitVec 32))\n" + declarations,
        1,
    )
    for lane, (expected, initial_word) in enumerate(
        zip(public_challenge["target_words"][0], initial, strict=True)
    ):
        original = f"(bvsub #x{expected:08x} {initial_word})"
        replacement = f"(bvsub t{lane} {initial_word})"
        if formula.count(original) < 1:
            raise RuntimeError(f"symbolic R20 target replacement missing at lane {lane}")
        formula = formula.replace(original, replacement)
    return formula


def _export(
    *, formula: str, output: Path, arguments: Sequence[str], bitwuzla: str
) -> dict[str, Any]:
    result = subprocess.run(
        [bitwuzla, *arguments, f"--write-cnf={output}"],
        input=formula,
        text=True,
        capture_output=True,
        timeout=12,
        check=False,
    )
    if result.returncode != 0 or not output.exists():
        raise RuntimeError(
            f"symbolic R20 CNF export failed: {result.returncode} {result.stderr}"
        )
    return {
        "returncode": result.returncode,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "status": next(
            (line for line in result.stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
            "invalid",
        ),
    }


def _pattern(width: int, dimension: int) -> int:
    if dimension == -1:
        return 0
    return sum(1 << bit for bit in range(width) if (bit >> dimension) & 1)


def _decode_mapping(
    rows: Sequence[tuple[int, list[int]]], *, width: int
) -> list[int]:
    by_dimension = {
        dimension: {abs(value): 1 if value > 0 else -1 for value in units}
        for dimension, units in rows
    }
    baseline_units = next(units for dimension, units in rows if dimension == -1)
    baseline = {abs(value): value for value in baseline_units}
    if any(set(mapping) != set(baseline) for mapping in by_dimension.values()):
        raise RuntimeError("symbolic template coordinate probes use different variables")
    result: list[int | None] = [None] * width
    for variable, baseline_literal in baseline.items():
        coordinate = 0
        baseline_sign = 1 if baseline_literal > 0 else -1
        for dimension in range(5):
            if by_dimension[dimension][variable] != baseline_sign:
                coordinate |= 1 << dimension
        if coordinate >= width or result[coordinate] is not None:
            raise RuntimeError("symbolic template binary coordinate decoding is not bijective")
        result[coordinate] = -baseline_literal
    if any(value is None for value in result):
        raise RuntimeError("symbolic template coordinate mapping is incomplete")
    return [int(value) for value in result]


def compile_template(
    *,
    r20: Any,
    public_challenge: dict[str, Any],
    protocol: dict[str, Any],
    directory: Path,
) -> tuple[bytes, list[int], list[list[int]], dict[str, Any]]:
    config = protocol["symbolic_R20_template"]
    formula = symbolic_formula(r20, public_challenge)
    if (
        len(formula.encode()) != config["formula_bytes"]
        or _sha256(formula.encode()) != config["formula_sha256"]
    ):
        raise RuntimeError("symbolic R20 formula differs from v2 freeze")
    base_path = directory / "a214b_symbolic_base.cnf"
    base_export = _export(
        formula=formula,
        output=base_path,
        arguments=config["arguments"],
        bitwuzla=config["Bitwuzla_path"],
    )
    base_raw = base_path.read_bytes()
    lines = base_raw.splitlines(keepends=True)
    header = lines[0].decode().strip()
    fields = lines[0].split()
    variable_count, clause_count = int(fields[2]), int(fields[3])
    body = b"".join(lines[1:])
    if (
        header != config["base_header"]
        or len(base_raw) != config["base_bytes"]
        or _sha256(base_raw) != config["base_sha256"]
        or _sha256(body) != config["base_body_sha256"]
        or base_export["status"] not in {"sat", "unknown"}
    ):
        raise RuntimeError("symbolic R20 base CNF differs from v2 freeze")

    def probe(item: tuple[str, int, int, int]) -> tuple[str, int, int, list[int]]:
        kind, index, dimension, width = item
        pattern = _pattern(width, dimension)
        if kind == "key":
            assertion = f"(assert (= ((_ extract 19 0) k0) #x{pattern:05x}))"
            unit_count = 20
        else:
            assertion = f"(assert (= t{index} #x{pattern:08x}))"
            unit_count = 32
        probe_formula = formula.replace(
            "(check-sat)", assertion + "\n(check-sat)", 1
        )
        output = directory / f"a214b_{kind}_{index}_{dimension}.cnf"
        exported = _export(
            formula=probe_formula,
            output=output,
            arguments=config["arguments"],
            bitwuzla=config["Bitwuzla_path"],
        )
        raw = output.read_bytes()
        probe_lines = raw.splitlines(keepends=True)
        probe_header = probe_lines[0].split()
        units = [int(line.split()[0]) for line in probe_lines[-unit_count:]]
        exact = (
            exported["status"] in {"sat", "unknown"}
            and int(probe_header[2]) == variable_count
            and int(probe_header[3]) == clause_count + unit_count
            and b"".join(probe_lines[1:-unit_count]) == body
            and all(len(line.split()) == 2 and line.split()[1] == b"0" for line in probe_lines[-unit_count:])
        )
        output.unlink()
        if not exact:
            raise RuntimeError(
                "symbolic R20 mapping probe is not an exact unit delta: "
                f"{kind}/{index}/{dimension}, status={exported['status']}, "
                f"header={probe_lines[0].decode().strip()}, "
                f"body_equal={b''.join(probe_lines[1:-unit_count]) == body}, "
                f"unit_count={unit_count}"
            )
        return kind, index, dimension, units

    items = [("key", 0, dimension, 20) for dimension in (-1, 0, 1, 2, 3, 4)]
    items.extend(
        ("output", lane, dimension, 32)
        for lane in range(16)
        for dimension in (-1, 0, 1, 2, 3, 4)
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        rows = list(executor.map(probe, items))
    if len(rows) != config["mapping_export_count"]:
        raise RuntimeError("symbolic R20 mapping probe count differs")
    key_mapping = _decode_mapping(
        [(dimension, units) for kind, _, dimension, units in rows if kind == "key"],
        width=20,
    )
    output_mapping = [
        _decode_mapping(
            [
                (dimension, units)
                for kind, index, dimension, units in rows
                if kind == "output" and index == lane
            ],
            width=32,
        )
        for lane in range(16)
    ]
    output_mapping_sha256 = _sha256(
        json.dumps(output_mapping, separators=(",", ":")).encode()
    )
    if (
        key_mapping != config["key_one_literals_bit0_through_bit19"]
        or output_mapping_sha256 != config["output_one_literal_matrix_sha256"]
    ):
        raise RuntimeError("symbolic R20 decoded mapping differs from v2 freeze")
    return base_raw, key_mapping, output_mapping, {
        "formula_sha256": _sha256(formula.encode()),
        "base_cnf_sha256": _sha256(base_raw),
        "base_body_sha256": _sha256(body),
        "mapping_probe_count": len(rows),
        "key_mapping_sha256": _sha256(
            np.asarray(key_mapping, dtype="<i4").tobytes()
        ),
        "output_mapping_sha256": output_mapping_sha256,
        "all_mapping_probes_exact_unit_deltas": True,
    }


def instantiate_output(
    base_raw: bytes,
    output_mapping: Sequence[Sequence[int]],
    target_words: Sequence[int],
) -> tuple[bytes, list[int], dict[str, Any]]:
    if len(output_mapping) != 16 or any(len(row) != 32 for row in output_mapping):
        raise ValueError("symbolic output mapping must be 16 by 32")
    if len(target_words) != 16:
        raise ValueError("ChaCha20 target must contain sixteen words")
    lines = base_raw.splitlines(keepends=True)
    fields = lines[0].split()
    units = [
        int(output_mapping[lane][bit])
        if (int(target_words[lane]) >> bit) & 1
        else -int(output_mapping[lane][bit])
        for lane in range(16)
        for bit in range(32)
    ]
    raw = (
        f"p cnf {int(fields[2])} {int(fields[3]) + len(units)}\n".encode()
        + b"".join(lines[1:])
        + b"".join(f"{literal} 0\n".encode() for literal in units)
    )
    return raw, units, {
        "header": raw.splitlines()[0].decode(),
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "unit_count": len(units),
        "unit_int32le_sha256": _sha256(
            np.asarray(units, dtype="<i4").tobytes()
        ),
    }
