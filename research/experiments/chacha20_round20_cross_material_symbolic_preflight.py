#!/usr/bin/env python3
"""Freeze the target-independent symbolic CNF manifest for A278 public material."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A280T"
DEFAULT_MASTER = (
    ROOT / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_cross_material_symbolic_template_v1.json"
)
MASTER_SHA256 = "256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6"
RUNNER = Path(__file__)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _path(value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A280T dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _clause_length_counts(raw: bytes) -> dict[str, int]:
    counts: Counter[int] = Counter()
    for line in raw.splitlines()[1:]:
        fields = line.split()
        if not fields or fields[-1] != b"0":
            raise RuntimeError("A280T base CNF contains a malformed clause")
        counts[len(fields) - 1] += 1
    return {str(length): counts[length] for length in sorted(counts)}


def _derive_mappings(
    *,
    template: Any,
    formula: str,
    base_raw: bytes,
    config: dict[str, Any],
    directory: Path,
) -> tuple[list[int], list[list[int]], dict[str, Any]]:
    lines = base_raw.splitlines(keepends=True)
    fields = lines[0].split()
    variable_count, clause_count = int(fields[2]), int(fields[3])
    body = b"".join(lines[1:])

    def probe(item: tuple[str, int, int, int]) -> tuple[str, int, int, list[int], str]:
        kind, index, dimension, width = item
        pattern = template._pattern(width, dimension)
        if kind == "key":
            assertion = f"(assert (= ((_ extract 19 0) k0) #x{pattern:05x}))"
            unit_count = 20
        else:
            assertion = f"(assert (= t{index} #x{pattern:08x}))"
            unit_count = 32
        probe_formula = formula.replace(
            "(check-sat)", assertion + "\n(check-sat)", 1
        )
        output = directory / f"a280t_{kind}_{index}_{dimension}.cnf"
        exported = template._export(
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
            and all(
                len(line.split()) == 2 and line.split()[1] == b"0"
                for line in probe_lines[-unit_count:]
            )
        )
        output.unlink()
        if not exact:
            raise RuntimeError(
                f"A280T mapping probe is not an exact unit delta: {kind}/{index}/{dimension}"
            )
        return kind, index, dimension, units, exported["status"]

    items = [("key", 0, dimension, 20) for dimension in (-1, 0, 1, 2, 3, 4)]
    items.extend(
        ("output", lane, dimension, 32)
        for lane in range(16)
        for dimension in (-1, 0, 1, 2, 3, 4)
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        rows = list(executor.map(probe, items))
    key_mapping = template._decode_mapping(
        [(dimension, units) for kind, _, dimension, units, _ in rows if kind == "key"],
        width=20,
    )
    output_mapping = [
        template._decode_mapping(
            [
                (dimension, units)
                for kind, index, dimension, units, _ in rows
                if kind == "output" and index == lane
            ],
            width=32,
        )
        for lane in range(16)
    ]
    output_mapping_sha256 = _sha256(
        json.dumps(output_mapping, separators=(",", ":")).encode()
    )
    status_counts = Counter(status for *_, status in rows)
    return key_mapping, output_mapping, {
        "mapping_probe_count": len(rows),
        "mapping_probe_status_counts": {
            status: status_counts.get(status, 0)
            for status in ("sat", "unknown", "unsat")
        },
        "key_mapping_sha256": _sha256(
            np.asarray(key_mapping, dtype="<i4").tobytes()
        ),
        "output_mapping_sha256": output_mapping_sha256,
        "all_mapping_probes_exact_unit_deltas": True,
    }


def build_protocol(
    *,
    master_path: Path,
    expected_master_sha256: str,
    root_review_acknowledged: bool,
) -> dict[str, Any]:
    if root_review_acknowledged is not True:
        raise RuntimeError("A280T freeze requires explicit root review acknowledgement")
    if _file_sha256(master_path) != expected_master_sha256:
        raise RuntimeError("A280T master protocol hash differs")
    master = json.loads(master_path.read_bytes())
    schedule = master.get("frozen_schedule", {})
    boundary = master.get("information_boundary", {})
    if (
        master.get("schema")
        != "chacha20-round20-cross-material-composite-master-v1"
        or master.get("attempt_id") != "A278"
        or master.get("protocol_state")
        != "frozen_before_cross_material_target_generation_measurement_order_or_solve"
        or schedule.get("measurement", {}).get("candidate_order")
        != "numeric_0_through_255"
        or schedule.get("measurement", {}).get("conflict_horizons") != [1, 2, 4, 8]
        or schedule.get("measurement", {}).get("watchdog_seconds_per_stage") != 2.0
        or boundary.get("new_public_material_frozen_before_target_generation") is not True
        or boundary.get("reader_and_all_solver_budgets_frozen_before_target_generation")
        is not True
    ):
        raise RuntimeError("A280T master semantic gate failed")

    anchors = master["anchors"]
    for name, anchor in anchors.items():
        path = _path(anchor["path"])
        if _file_sha256(path) != anchor["sha256"]:
            raise RuntimeError(f"A280T retained anchor differs: {name}")
    public_path = _path(anchors["public_core"]["path"])
    template_path = _path(anchors["symbolic_template"]["path"])
    public = _import_path(public_path, "a280t_public")
    template = _import_path(template_path, "a280t_template")

    a276_protocol = json.loads(_path(anchors["A276_protocol"]["path"]).read_bytes())
    old_symbolic_path = _path(a276_protocol["anchors"]["symbolic_template_protocol_path"])
    old_symbolic_sha256 = a276_protocol["anchors"]["symbolic_template_protocol_sha256"]
    if _file_sha256(old_symbolic_path) != old_symbolic_sha256:
        raise RuntimeError("A280T inherited symbolic protocol hash differs")
    old_symbolic = json.loads(old_symbolic_path.read_bytes())
    inherited = copy.deepcopy(old_symbolic["symbolic_R20_template"])
    bitwuzla_path = Path(inherited["Bitwuzla_path"])
    if _file_sha256(bitwuzla_path) != inherited["Bitwuzla_sha256"]:
        raise RuntimeError("A280T Bitwuzla executable hash differs")

    public_template = public.validate_public_template(
        master["cross_material_public_template"]
    )
    if _canonical_sha256(public_template) != master["cross_material_public_template_sha256"]:
        raise RuntimeError("A280T public template hash differs")
    # This synthetic known challenge supplies removable target constants only.
    # symbolic_formula replaces all of them by t0..t15, so its result is
    # independent of this dummy label and of the later A279 target.
    dummy = public.build_known_challenge(public_template, low20=0)
    formula = template.symbolic_formula(public, dummy)

    with tempfile.TemporaryDirectory(prefix="a280t_symbolic_preflight_") as temporary:
        directory = Path(temporary)
        preliminary_path = directory / "cross_material_symbolic_base.preflight.cnf"
        export = template._export(
            formula=formula,
            output=preliminary_path,
            arguments=inherited["arguments"],
            bitwuzla=inherited["Bitwuzla_path"],
        )
        base_raw = preliminary_path.read_bytes()
        lines = base_raw.splitlines(keepends=True)
        body = b"".join(lines[1:])
        symbolic_config = copy.deepcopy(inherited)
        symbolic_config.update(
            {
                "formula_bytes": len(formula.encode()),
                "formula_sha256": _sha256(formula.encode()),
                "base_header": lines[0].decode().strip(),
                "base_bytes": len(base_raw),
                "base_sha256": _sha256(base_raw),
                "base_body_sha256": _sha256(body),
                "base_clause_length_counts": _clause_length_counts(base_raw),
            }
        )
        for key in list(symbolic_config):
            if key.startswith("instantiated_") or key.startswith("all_25_instantiated"):
                symbolic_config.pop(key)
        mapping_directory = directory / "mapping_gate"
        mapping_directory.mkdir()
        key_mapping, output_mapping, mapping_manifest = _derive_mappings(
            template=template,
            formula=formula,
            base_raw=base_raw,
            config=symbolic_config,
            directory=mapping_directory,
        )
        symbolic_config["key_one_literals_bit0_through_bit19"] = key_mapping
        symbolic_config["output_one_literal_matrix_sha256"] = mapping_manifest[
            "output_mapping_sha256"
        ]
        symbolic_config["mapping_probe_status_counts"] = mapping_manifest[
            "mapping_probe_status_counts"
        ]
        manifest = {
            "formula_sha256": _sha256(formula.encode()),
            "base_cnf_sha256": _sha256(base_raw),
            "base_body_sha256": _sha256(body),
            **mapping_manifest,
        }
        if (
            manifest["formula_sha256"] != symbolic_config["formula_sha256"]
            or manifest["base_cnf_sha256"] != symbolic_config["base_sha256"]
            or key_mapping != symbolic_config["key_one_literals_bit0_through_bit19"]
            or manifest["output_mapping_sha256"]
            != symbolic_config["output_one_literal_matrix_sha256"]
            or manifest["mapping_probe_count"] != symbolic_config["mapping_export_count"]
            or export["status"] not in {"sat", "unknown"}
        ):
            raise RuntimeError("A280T cross-material symbolic compile gate failed")
        dummy_raw, _, dummy_instantiation = template.instantiate_output(
            base_raw,
            output_mapping,
            dummy["target_words"][0],
        )
        if len(dummy_raw) <= len(base_raw) or dummy_instantiation["unit_count"] != 512:
            raise RuntimeError("A280T dummy output instantiation gate failed")

    protocol: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-symbolic-template-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_from_A278_public_material_without_reading_A279_target",
        "master_protocol": {
            "path": str(master_path.relative_to(ROOT)),
            "sha256": expected_master_sha256,
            "scientific_design_sha256": master["scientific_design_sha256"],
        },
        "public_template_sha256": master["cross_material_public_template_sha256"],
        "anchors": {
            "preflight_runner": {
                "path": str(RUNNER.relative_to(ROOT)),
                "sha256": _file_sha256(RUNNER),
            },
            "public_core": {
                "path": str(public_path.relative_to(ROOT)),
                "sha256": _file_sha256(public_path),
            },
            "symbolic_template": {
                "path": str(template_path.relative_to(ROOT)),
                "sha256": _file_sha256(template_path),
            },
            "inherited_symbolic_protocol": {
                "path": str(old_symbolic_path.relative_to(ROOT)),
                "sha256": old_symbolic_sha256,
            },
            "Bitwuzla": {
                "path": str(bitwuzla_path),
                "sha256": _file_sha256(bitwuzla_path),
            },
        },
        "symbolic_R20_template": symbolic_config,
        "compile_manifest": manifest,
        "target_independence": {
            "A279_protocol_opened": False,
            "A279_target_words_read": False,
            "synthetic_label": 0,
            "synthetic_target_constants_removed_before_formula_hash": True,
            "symbolic_formula_depends_only_on_A278_public_material": True,
            "later_target_instantiation_is_exactly_512_unit_polarities": True,
        },
    }
    protocol["scientific_design_sha256"] = _canonical_sha256(
        {
            "master_protocol_sha256": expected_master_sha256,
            "public_template_sha256": protocol["public_template_sha256"],
            "symbolic_R20_template": symbolic_config,
            "target_independence": protocol["target_independence"],
        }
    )
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--expected-master-sha256", default=MASTER_SHA256)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--root-reviewed", action="store_true")
    args = parser.parse_args(argv)
    protocol = build_protocol(
        master_path=args.master,
        expected_master_sha256=args.expected_master_sha256,
        root_review_acknowledged=args.root_reviewed,
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "scientific_design_sha256": protocol["scientific_design_sha256"],
                "formula_sha256": protocol["symbolic_R20_template"]["formula_sha256"],
                "base_sha256": protocol["symbolic_R20_template"]["base_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
