#!/usr/bin/env python3
"""A348: measure every W46 high12 cell through sixteen fixed-low4 CNF slices."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a348_chacha20_r20_w46_direct12_slices"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_direct12_sliced_reader_a348_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_direct12_sliced_reader_a348_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_direct12_sliced_reader_a348.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_direct12_sliced_reader_a348.sh"

A340_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_target_conditioned_causal_order_a340.py"
A341_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_familywise_channel_portfolio_a341.py"
A342_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_exhaustive_reader_ensemble_a342.py"
A251_WRAPPER = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
A275_READER = RESEARCH / "experiments/chacha20_round20_selected_channel_target_replication_measure.py"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A340_PREFLIGHT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_preflight_v1.json"
A340_BASE_CNF = RESEARCH / "artifacts/a340_chacha20_r20_w46_target_conditioned_causal/a340_chacha20_r20_w46_b1_base.cnf"
A341_RESULT = RESULTS / "chacha20_round20_w46_familywise_channel_portfolio_a341_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"

ATTEMPT_ID = "A348"
DESIGN_SHA256 = "d31649a3138e823c238bf8ff1318679d614f1b49ae0d53e9ebe4a0889b706b17"
WIDTH = 46
PREFIX_BITS = 12
HIGH_BITS = 8
LOW_BITS = 4
CELLS = 1 << PREFIX_BITS
SLICES = tuple(range(1 << LOW_BITS))
COARSE_CELLS = 1 << HIGH_BITS
HORIZONS = [1, 2, 4, 8]
WATCHDOG_SECONDS = 2.0
WORKERS = 8
ZSTD_LEVEL = 10

SOURCE_SHA256 = {
    A340_RUNNER: "7c5812f7c8ab53312de45ec425e9bfbbae66c149b1944b489aeaa711087e95ff",
    A251_WRAPPER: "3a1d63d223712997519f72143ebcc3e5725a8f8659eadbd9389465dd0fe654f6",
    A275_READER: "218815280ce978aba16ba857db80828424e390cc1d141a1be3d33fb330c4e56b",
    A325_RESULT: "534d2d769f387bca90b9ab1f2c43a98a6030c1e3c1039270c1d2e109a38d7ce2",
    A340_PREFLIGHT: "129f4f7cec98322cdf7b60a0e25e7286fd1f6712339181f30bf9b4b05f77f5f6",
    A340_BASE_CNF: "64e28ee08090257a98567e573724d9a35824c3870172bea74611c69db25e8121",
    A341_RESULT: "4ebc8041d469a57e064a31eb3099a46cb8a8dd998090b9fef70a3e9233fef7d6",
    A342_RESULT: "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb",
}

DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A348 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A340 = load_module(A340_RUNNER, "a348_a340")
A341 = load_module(A341_RUNNER, "a348_a341")
A342 = load_module(A342_RUNNER, "a348_a342")
WRAPPER = load_module(A251_WRAPPER, "a348_clause_identity")
A275 = load_module(A275_READER, "a348_a275")

file_sha256 = A340.file_sha256
canonical_sha256 = A340.canonical_sha256
canonical_bytes = A340.canonical_bytes
atomic_json = A340.atomic_json
atomic_bytes = A340.atomic_bytes
relative = A340.relative
path_from_ref = A340.path_from_ref
anchor = A340.anchor
sha256 = A340.sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A348 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    scoring = value.get("scoring_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-sliced-reader-a348-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "post_A325_mechanism_development_frozen_before_direct12_measurement_or_true_prefix_scoring"
        or measurement.get("complete_direct_prefix_bits") != PREFIX_BITS
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("low4_slices") != len(SLICES)
        or measurement.get("concurrent_slice_workers") != WORKERS
        or measurement.get("conflict_horizons") != HORIZONS
        or measurement.get("target_labels_used_during_measurement") != 0
        or scoring.get("A325_true_prefix_revealed_only_after_all_4096_cells_are_measured")
        is not True
        or boundary.get("A325_candidate_or_prefix_used_to_construct_slice_CNF")
        is not False
        or boundary.get("new_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A348 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A348 implementation already exists")
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists() or MEASUREMENTS.exists():
        raise RuntimeError("A348 implementation must precede all measurements")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A348 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-sliced-reader-a348-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_direct12_measurement_or_true_prefix_scoring",
        "design_sha256": DESIGN_SHA256,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A348 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-sliced-reader-a348-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_direct12_measurement_or_true_prefix_scoring"
        or value.get("design_sha256") != DESIGN_SHA256
    ):
        raise RuntimeError("A348 implementation semantics differ")
    expected = {"design": DESIGN, "runner": Path(__file__), "test": TEST, "reproducer": REPRO}
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A348 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A348 implementation commitment differs")
    return value


def _base_cnf_parts(raw: bytes) -> tuple[int, int, bytes]:
    lines = raw.splitlines(keepends=True)
    fields = lines[0].split() if lines else []
    if len(fields) != 4 or fields[:2] != [b"p", b"cnf"]:
        raise ValueError("A348 base CNF header differs")
    variables, clauses = int(fields[2]), int(fields[3])
    body = b"".join(lines[1:])
    if not body.endswith(b"\n"):
        body += b"\n"
    return variables, clauses, body


def low4_unit_literals(low4: int, source_mapping: Sequence[int]) -> list[int]:
    if low4 not in SLICES or len(source_mapping) != WIDTH:
        raise ValueError("A348 low4 slice or source mapping differs")
    result = []
    for offset, coordinate in enumerate((37, 36, 35, 34)):
        one_literal = int(source_mapping[coordinate])
        bit = (low4 >> (LOW_BITS - 1 - offset)) & 1
        result.append(one_literal if bit else -one_literal)
    if len({abs(value) for value in result}) != LOW_BITS:
        raise RuntimeError("A348 low4 unit variables alias")
    return result


def render_slice_cnf(base_raw: bytes, *, low4: int, source_mapping: Sequence[int]) -> bytes:
    variables, clauses, body = _base_cnf_parts(base_raw)
    units = low4_unit_literals(low4, source_mapping)
    suffix = b"".join(f"{literal} 0\n".encode("ascii") for literal in units)
    return f"p cnf {variables} {clauses + len(units)}\n".encode("ascii") + body + suffix


def slice_cell(high8: int, low4: int) -> int:
    if not 0 <= high8 < COARSE_CELLS or low4 not in SLICES:
        raise ValueError("A348 high8/low4 cell differs")
    return (high8 << LOW_BITS) | low4


def split_cell(cell: int) -> tuple[int, int]:
    if not 0 <= cell < CELLS:
        raise ValueError("A348 direct12 cell differs")
    return cell >> LOW_BITS, cell & (len(SLICES) - 1)


def _write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(path, compressed)
    return {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def _read_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A348 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A348 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A348 slice measurement is not canonical")
    return value


def _slice_paths(low4: int) -> tuple[Path, Path]:
    return ARTIFACTS / f"slice_{low4:02x}.cnf", MEASUREMENTS / f"slice_{low4:02x}.json.zst"


def _prepare_slices(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = A340_BASE_CNF.read_bytes()
    mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists():
            if cnf_path.read_bytes() != expected:
                raise RuntimeError(f"A348 existing slice CNF differs: {low4}")
        else:
            atomic_bytes(cnf_path, expected)
        rows.append(
            {
                "low4": low4,
                "low4_binary": f"{low4:04b}",
                "unit_literals": low4_unit_literals(low4, mapping),
                "cnf": anchor(cnf_path),
                "measurement_path": measurement_path,
            }
        )
    return rows


def _validate_slice_measurement(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    stages = run.get("stages", [])
    cells = run.get("cells", [])
    if (
        value.get("schema") != "chacha20-round20-w46-direct12-slice-a348-measurement-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("label_used_for_feature_construction_or_scoring") is not False
        or value.get("complete_candidate_cover") is not True
        or len(cells) != COARSE_CELLS
        or not 1 <= len(stages) <= COARSE_CELLS * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A348 slice measurement gate failed: {low4}")


def _run_slice(row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = _read_measurement(path)
        _validate_slice_measurement(value, low4)
        return {"low4": low4, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A348_W46_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable_run = {
        key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w46-direct12-slice-a348-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "low4": low4,
        "low4_binary": f"{low4:04b}",
        "fixed_unit_literals": list(row["unit_literals"]),
        "cnf_sha256": row["cnf"]["sha256"],
        "run": stable_run,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(stable_run.get("cells", [])) == COARSE_CELLS,
    }
    _validate_slice_measurement(measurement, low4)
    return {"low4": low4, "resumed": False, "ledger": _write_measurement(path, measurement)}


def _rank_order(scores: Sequence[float]) -> list[int]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CELLS,) or not np.isfinite(values).all():
        raise ValueError("A348 direct12 score field differs")
    result = sorted(range(CELLS), key=lambda cell: (-float(values[cell]), cell))
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A348 direct12 order is incomplete")
    return result


def _slice_zscores(scores: np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CELLS,) or not np.isfinite(values).all():
        raise ValueError("A348 slice normalization input differs")
    result = np.empty(CELLS, dtype=np.float64)
    for low4 in SLICES:
        cells = np.asarray([slice_cell(high8, low4) for high8 in range(COARSE_CELLS)])
        field = values[cells]
        scale = float(field.std())
        if not math.isfinite(scale) or scale <= 0.0:
            raise RuntimeError(f"A348 slice score variance vanished: {low4}")
        result[cells] = (field - float(field.mean())) / scale
    return result


def _all_view_scores(
    measurements: Mapping[int, Mapping[str, Any]], model: Any, groups: Mapping[str, Sequence[int]]
) -> dict[str, np.ndarray]:
    a341_selected = json.loads(A341_RESULT.read_bytes())["known_key_selection"][
        "selected_feature_indices"
    ]
    a342_selection = json.loads(A342_RESULT.read_bytes())["selection"]
    pair_indices = [int(value) for value in a342_selection["pair"]["selected_indices"]]
    triple_indices = [int(value) for value in a342_selection["triple"]["selected_indices"]]

    fields = {
        "A340_selected8": np.empty(CELLS, dtype=np.float64),
        "A341_selected_single": np.empty(CELLS, dtype=np.float64),
        "A342_selected_pair": np.empty(CELLS, dtype=np.float64),
        "A342_selected_triple": np.empty(CELLS, dtype=np.float64),
    }
    for low4 in SLICES:
        measurement = measurements[low4]
        run = measurement["run"]
        if any(cell.get("final_status") != "unknown" for cell in run["cells"]):
            raise RuntimeError("A348 terminal cells require hard-prune handling")
        matrix = A275._target_feature_matrix(measurement)  # noqa: SLF001
        contributions = A341.standardized_contributions(
            matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        selected8 = contributions[:, A340.FEATURE_INDICES].sum(axis=1)
        selected_single = A341.local_pairwise_residual(
            contributions[:, np.asarray(a341_selected, dtype=np.int64)].sum(axis=1)
        )
        grouped = A341.grouped_scores(contributions, groups)
        view_scores: dict[str, np.ndarray] = {}
        for group, scores in grouped.items():
            view_scores[f"{group}::direct_additive_contribution"] = scores
            view_scores[f"{group}::normalized_8cube_graph_laplacian"] = (
                A341.local_pairwise_residual(scores)
            )
        names = []
        for group in sorted(groups):
            names.extend(
                [
                    f"{group}::direct_additive_contribution",
                    f"{group}::normalized_8cube_graph_laplacian",
                ]
            )
        ranks = np.stack(
            [A342.midrank_vector_descending(view_scores[name]) for name in names], axis=0
        )
        pair_score = -ranks[pair_indices].sum(axis=0)
        triple_score = -ranks[triple_indices].sum(axis=0)
        for high8 in range(COARSE_CELLS):
            cell = slice_cell(high8, low4)
            fields["A340_selected8"][cell] = selected8[high8]
            fields["A341_selected_single"][cell] = selected_single[high8]
            fields["A342_selected_pair"][cell] = pair_score[high8]
            fields["A342_selected_triple"][cell] = triple_score[high8]
    result = {}
    for name, field in fields.items():
        result[f"{name}_global_raw"] = field
        result[f"{name}_slice_z"] = _slice_zscores(field)
    return result


def _hard_partition(measurements: Mapping[int, Mapping[str, Any]], public_seed: str) -> dict[str, Any]:
    statuses: dict[str, list[int]] = {"sat": [], "unknown": [], "unsat": []}
    for low4 in SLICES:
        for high8, row in enumerate(measurements[low4]["run"]["cells"]):
            statuses[row["final_status"]].append(slice_cell(high8, low4))
    seed = bytes.fromhex(public_seed)
    unknown = sorted(
        statuses["unknown"],
        key=lambda cell: hashlib.sha256(b"A348|hard-partition|" + seed + cell.to_bytes(2, "big")).digest(),
    )
    order = statuses["sat"] + unknown + statuses["unsat"]
    return {"statuses": statuses, "order": order}


def _build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a348d12")
    writer._rules = []
    writer.add_rule(
        name="slice_closure_to_direct12_grid",
        description="Sixteen exact low4 unit slices crossed with all high8 assumptions cover every high12 W46 cell once.",
        pattern=["A340_public_output_CNF", "sixteen_low4_unit_slices"],
        conclusion="A348_complete_direct12_measurement",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="direct12_grid_to_reader_panel",
        description="Frozen known-key readers score the complete direct12 grid before the confirmed A325 prefix is inspected.",
        pattern=["A348_complete_direct12_measurement", "frozen_A340_A342_readers"],
        conclusion="A348_direct12_reader_panel",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A325:public_output_CNF",
        mechanism="sixteen_fixed_low4_CNF_slices_cross_all_high8_assumptions",
        outcome="A348:complete_direct12_grid",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="complete 4096-cell model-free measurement",
        domain="ChaCha20 R20 plus feed-forward W46 prefix inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A348:complete_direct12_grid",
        mechanism="frozen_multiview_reader_panel_within_slice_and_global_readouts",
        outcome="A348:direct12_rank_panel",
        confidence=1.0,
        source=payload["result_sha256"],
        quantification=json.dumps(payload["rank_panel"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="post-A325 mechanism calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:public_output_CNF",
        mechanism="materialized_direct12_measurement_and_reader_closure",
        outcome="A348:direct12_rank_panel",
        confidence=1.0,
        source="materialized:A348_direct12_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A348 direct12 target-conditioned inference",
        entities=["A325:public_output_CNF", "A348:complete_direct12_grid", "A348:direct12_rank_panel"],
    )
    writer.add_gap(
        subject="A348:direct12_rank_panel",
        predicate="next_required_object",
        expected_object_type="prospectively_frozen_direct12_reader_on_fresh_target",
        confidence=1.0,
        suggested_queries=["Which predeclared direct12 view transfers to a fresh public-output target?"],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a348d12"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A348 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {"terminal_chain": all_rows[-1], "next_gap": reader._gaps[0]},
    }


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A348 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    preflight = json.loads(A340_PREFLIGHT.read_bytes())
    if (
        preflight.get("source_mapping_sha256")
        != canonical_sha256(preflight["source_one_literals_bit0_upward"])
        or len(preflight.get("source_one_literals_bit0_upward", [])) != WIDTH
    ):
        raise RuntimeError("A348 A340 source mapping differs")
    rows = _prepare_slices(preflight)
    _a275, _model, _a291, _indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {
            executor.submit(
                _run_slice,
                row,
                helper=helper,
                key_mapping=preflight["synthetic_reader_mapping"],
            ): int(row["low4"])
            for row in rows
        }
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError("A348 slice completion cover differs")

    measurements = {
        row["low4"]: _read_measurement(
            path_from_ref(row["ledger"]["path"]), row["ledger"]
        )
        for row in completed
    }
    for low4, value in measurements.items():
        _validate_slice_measurement(value, low4)
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    for value in measurements.values():
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status_counts[cell["final_status"]] += 1
    if sum(status_counts.values()) != CELLS:
        raise RuntimeError("A348 direct12 status cover differs")

    # The confirmed prefix is deliberately loaded only after every slice has closed.
    a325 = json.loads(A325_RESULT.read_bytes())
    candidate = int(a325["discovery"]["candidate"])
    true_prefix = (candidate & 0xFFFFFFFF) >> 20
    if true_prefix != int(a325["discovery"]["prefix12"]):
        raise RuntimeError("A348 confirmed A325 prefix codec differs")

    rank_panel: dict[str, Any] = {}
    orders: dict[str, list[int]] = {}
    score_hashes: dict[str, str] = {}
    if status_counts["sat"] or status_counts["unsat"]:
        partition = _hard_partition(measurements, preflight["A325_public_challenge_sha256"])
        orders["hard_terminal_partition"] = partition["order"]
        evidence_stage = "POST_A325_COMPLETE_DIRECT12_HARD_PARTITION_RETAINED"
    else:
        _selection, _a272, model, groups = A341.reconstruct_known_key_selection(
            json.loads(A341.DESIGN.read_bytes())
        )
        score_fields = _all_view_scores(measurements, model, groups)
        if tuple(score_fields) != tuple(design["scoring_contract"]["candidate_views"]):
            raise RuntimeError("A348 frozen score-view sequence differs")
        for name, field in score_fields.items():
            orders[name] = _rank_order(field)
            score_hashes[name] = canonical_sha256(field.tolist())
        evidence_stage = "POST_A325_COMPLETE_DIRECT12_MULTIVIEW_MECHANISM_CALIBRATION_RETAINED"
    for name, order in orders.items():
        rank = order.index(true_prefix) + 1
        rank_panel[name] = {
            "rank_one_based": rank,
            "gain_bits_vs_uniform_complete_4096_cover": math.log2(CELLS / rank),
            "domain_reduction_factor_at_rank": CELLS / rank,
            "order_uint16be_sha256": sha256(
                b"".join(cell.to_bytes(2, "big") for cell in order)
            ),
        }

    measurement_summary = {
        "low4_slices": len(SLICES),
        "high8_cells_per_slice": COARSE_CELLS,
        "complete_direct12_cells": CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": WORKERS,
        "target_labels_used_during_measurement": 0,
        "candidate_assignments_executed": 0,
    }
    ledgers = [
        {
            **row["ledger"],
            "low4": row["low4"],
            "low4_binary": f"{row['low4']:04b}",
            "resumed": row["resumed"],
        }
        for row in completed
    ]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-sliced-reader-a348-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "measurement_sha256": canonical_sha256(
            {"measurement_summary": measurement_summary, "measurement_ledger": ledgers}
        ),
        "confirmed_prefix12": true_prefix,
        "confirmed_prefix12_hex": f"{true_prefix:03x}",
        "confirmed_prefix_revealed_only_after_complete_measurement": True,
        "rank_panel": rank_panel,
        "orders": orders,
        "score_field_sha256": score_hashes,
        "information_boundary": design["information_boundary"],
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A325_result": anchor(A325_RESULT, SOURCE_SHA256[A325_RESULT]),
            "A340_preflight": anchor(A340_PREFLIGHT, SOURCE_SHA256[A340_PREFLIGHT]),
            "A340_base_CNF": anchor(A340_BASE_CNF, SOURCE_SHA256[A340_BASE_CNF]),
            "A341_result": anchor(A341_RESULT, SOURCE_SHA256[A341_RESULT]),
            "A342_result": anchor(A342_RESULT, SOURCE_SHA256[A342_RESULT]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": evidence_stage,
            "measurement_sha256": payload["measurement_sha256"],
            "confirmed_prefix12": true_prefix,
            "rank_panel": rank_panel,
            "score_field_sha256": score_hashes,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = _build_causal(payload)
    atomic_json(RESULT, payload)
    best = min(rank_panel.items(), key=lambda item: (item[1]["rank_one_based"], item[0]))
    atomic_bytes(
        REPORT,
        (
            "# A348 — complete direct12 public-output-conditioned W46 readout\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Complete directly measured prefix cells: **{CELLS:,}**\n"
            f"- Solver stages: **{stage_count:,}**\n"
            f"- Status counts: **{status_counts}**\n"
            f"- Confirmed A325 prefix after measurement: **0x{true_prefix:03x}**\n"
            f"- Best declared readout: **{best[0]}**, rank **{best[1]['rank_one_based']} / {CELLS}**\n"
            "- Candidate assignments executed by A348: **zero**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "slice_CNF_count": len(list(ARTIFACTS.glob("slice_*.cnf"))) if ARTIFACTS.exists() else 0,
        "slice_measurement_count": len(list(MEASUREMENTS.glob("slice_*.json.zst")))
        if MEASUREMENTS.exists()
        else 0,
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure:
        if not args.expected_implementation_sha256:
            parser.error("--measure requires --expected-implementation-sha256")
        payload = measure(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
