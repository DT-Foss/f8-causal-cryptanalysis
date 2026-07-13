#!/usr/bin/env python3
"""Learn a key-disjoint R20 propagation atlas, freeze ranks, then reveal target."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader, ExactRule
from arx_carry_leak.exact_cnf import ExactCNF
from arx_carry_leak.key_atlas import (
    RidgeLogisticModel,
    candidate_order,
    candidate_scores,
    exact_rank,
    fit_ridge_logistic,
)
from arx_carry_leak.propagation_features import (
    F1_NAMES,
    F2_NAMES,
    F3_NAMES,
    F4_NAMES,
    FEATURE_NAMES,
    extract_propagation_features,
)


ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
R20_RUNNER = RESEARCH / "experiments" / "chacha20_round20_global_incremental_transfer.py"
ATLAS_HELPER = Path(__file__).with_name("chacha20_round20_knownkey_atlas_helpers.py")
TEMPLATE_HELPER = Path(__file__).with_name("chacha20_round20_symbolic_template.py")

ATTEMPT_ID = "A214C"
SCHEMA = "chacha20-round20-knownkey-propagation-atlas-v3"
PROTOCOL_FILENAME = "chacha20_round20_knownkey_propagation_atlas_v3.json"
PROTOCOL_SHA256 = "aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698"
PARENT_PROTOCOL_FILENAME = "chacha20_round20_knownkey_propagation_atlas_v1.json"
PARENT_PROTOCOL_SHA256 = "6a344841f044222f2354e11f791c4c84fd63211f5698f1280a4e4c42fb44ba85"
R20_RUNNER_SHA256 = "1825035b90317e9d6c8a2ee0894f2569eada44177ee01ced49d043ca37ec881d"
RIDGE_GRID = (0.01, 0.1, 1.0, 10.0, 100.0)
MODEL_FAMILIES: dict[str, tuple[str, ...]] = {
    "F1": F1_NAMES,
    "F2": F2_NAMES,
    "F3": F3_NAMES,
    "F4": F4_NAMES,
    "F1_F2_F3_F4_combined": FEATURE_NAMES,
}


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
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
    )


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> dict[str, Any]:
    path = RESEARCH / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A214B frozen protocol hash differs")
    correction = json.loads(path.read_bytes())
    parent_path = RESEARCH / "configs" / PARENT_PROTOCOL_FILENAME
    if _file_sha256(parent_path) != PARENT_PROTOCOL_SHA256:
        raise RuntimeError("A214B parent protocol hash differs")
    parent = json.loads(parent_path.read_bytes())
    anchors = correction.get("anchors", {})
    template = correction.get("symbolic_R20_template", {})
    boundary = correction.get("information_boundary", {})
    gates = {
        "schema": correction.get("schema")
        == "chacha20-round20-knownkey-propagation-atlas-protocol-v3",
        "attempt": correction.get("attempt_id") == ATTEMPT_ID,
        "state": correction.get("protocol_state")
        == "frozen_after_A214B_preflight_found_duplicate_inline_target_expressions_and_before_any_atlas_feature_model_candidate_order_target_key_or_R20_solver_outcome_was_available_or_read",
        "parent": correction.get("parent_learning_protocol", {}).get("sha256")
        == PARENT_PROTOCOL_SHA256,
        "A213": anchors.get("A213_result_sha256")
        == "6bdaa4cef0c5e5172e731abee5f97826830366a1283fb8a342c8c7d5450e48fa",
        "R20_runner": anchors.get("R20_global_transfer_runner_sha256")
        == R20_RUNNER_SHA256,
        "challenge": anchors.get("public_target_challenge_sha256")
        == "98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762",
        "ledger": anchors.get("knownkey_ledger_sha256")
        == "b0b1add2b4185c0b7a5ef02397ed54d3e504a19866a833601382e725adbdc91f",
        "base_CNF": template.get("base_sha256")
        == "086368fd3825d8059b90d244c9b1e5d2912acc75e705f81d3c53265305348963",
        "target_CNF": template.get("instantiated_target_sha256")
        == "3ef89a66f8a65bad929b45f32755713768883735e5b005738ab34474adf6ae1a",
        "ridge_grid": tuple(
            parent.get("learning_protocol", {}).get("ridge_lambda_grid", ())
        )
        == RIDGE_GRID,
        "R20_blind": boundary.get(
            "R20_numeric_or_gray_status_counts_models_or_cells_known_at_freeze"
        )
        is False,
        "target_blind": boundary.get("target_low20_known_at_freeze") is False,
        "knownkey_scope": boundary.get("knownkey_training_scope_is_explicit")
        is True,
        "drift_removed": boundary.get(
            "all_target_expressions_symbolized_before_any_feature_measurement"
        )
        is True,
    }
    failed = [name for name, passed in gates.items() if not passed]
    if failed:
        raise RuntimeError(f"A214B frozen protocol identity gate failed: {failed}")
    return {**parent, **correction, "_parent_protocol": parent}


def _load_modules(
    protocol: dict[str, Any]
) -> tuple[Any, Any, Any, list[dict[str, Any]]]:
    if _file_sha256(R20_RUNNER) != R20_RUNNER_SHA256:
        raise RuntimeError("A214 pinned R20 runner hash differs")
    r20 = _import_path(R20_RUNNER, "a214_pinned_r20")
    helper = _import_path(ATLAS_HELPER, "a214_knownkey_helpers")
    template = _import_path(TEMPLATE_HELPER, "a214_symbolic_template")
    rows = helper.atlas_ledger()
    if (
        helper.atlas_ledger_sha256(rows)
        != protocol["anchors"]["knownkey_ledger_sha256"]
        or len(rows) != 24
        or len({row["low20"] for row in rows}) != 24
    ):
        raise RuntimeError("A214 deterministic atlas ledger gate failed")
    return r20, helper, template, rows


def _custom_cnf_and_mapping(
    *,
    r20: Any,
    r20_protocol: dict[str, Any],
    formula: str,
    label: str,
    directory: Path,
    expected_one_literals: Sequence[int],
) -> tuple[Path, dict[str, Any]]:
    base_path = directory / f"{label}.cnf"
    exported = r20._export_cnf(
        label=f"A214_{label}", formula=formula, output=base_path, protocol=r20_protocol
    )
    base_raw = base_path.read_bytes()
    lines = base_raw.splitlines(keepends=True)
    if (
        exported["returncode"] != 0
        or exported["externally_timed_out"]
        or exported["export_status"] != "unknown"
        or lines[0].decode().strip() != "p cnf 68783 216461"
    ):
        raise RuntimeError(f"A214 {label} base CNF export gate failed")
    body = b"".join(lines[1:])
    body_sha = _sha256(body)

    def probe(item: tuple[int, int]) -> tuple[int, int, int]:
        bit, value = item
        assertion = f"(assert (= ((_ extract {bit} {bit}) k0) #b{value}))"
        probe_formula = formula.replace("(check-sat)", assertion + "\n(check-sat)", 1)
        output = directory / f"{label}_probe_b{bit}_v{value}.cnf"
        result = r20._export_cnf(
            label=f"A214_{label}_b{bit}_v{value}",
            formula=probe_formula,
            output=output,
            protocol=r20_protocol,
        )
        raw = output.read_bytes()
        probe_lines = raw.splitlines(keepends=True)
        fields = probe_lines[-1].split()
        exact = (
            result["returncode"] == 0
            and not result["externally_timed_out"]
            and result["export_status"] == "unknown"
            and probe_lines[0].decode().strip() == "p cnf 68783 216462"
            and len(fields) == 2
            and fields[1] == b"0"
            and _sha256(b"".join(probe_lines[1:-1])) == body_sha
        )
        output.unlink()
        if not exact:
            raise RuntimeError(f"A214 {label} bit-probe exact-delta gate failed")
        return bit, value, int(fields[0])

    items = [(bit, value) for bit in range(20) for value in (0, 1)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        probe_rows = list(executor.map(probe, items))
    lookup = {(bit, value): literal for bit, value, literal in probe_rows}
    one_literals = []
    for bit in range(20):
        zero, one = lookup[(bit, 0)], lookup[(bit, 1)]
        if zero != -one:
            raise RuntimeError(f"A214 {label} signed mapping polarity differs")
        one_literals.append(one)
    if one_literals != list(expected_one_literals):
        raise RuntimeError(f"A214 {label} key-literal mapping differs")
    return base_path, {
        "label": label,
        "formula_sha256": _sha256(formula.encode()),
        "base_cnf_bytes": len(base_raw),
        "base_cnf_sha256": _sha256(base_raw),
        "base_body_sha256": body_sha,
        "header": lines[0].decode().strip(),
        "probe_count": 40,
        "one_literals_bit0_through_bit19": one_literals,
    }


def _absolute_structure_sha256(cnf: ExactCNF) -> str:
    digest = hashlib.sha256()
    for clause in cnf.clauses:
        digest.update(len(clause).to_bytes(1, "little"))
        digest.update(np.asarray([abs(value) for value in clause], dtype="<u4").tobytes())
    return digest.hexdigest()


def _literal_for(bit: int, value: int, one_literals: Sequence[int]) -> int:
    literal = int(one_literals[bit])
    return literal if value else -literal


def _probe_rows(
    cnf: ExactCNF, one_literals: Sequence[int]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    base = cnf.propagate()
    if base.conflicted:
        raise RuntimeError("A214 base CNF conflicts")
    rows: list[dict[str, Any]] = []
    for bit in range(20):
        for value in (0, 1):
            state = cnf.propagate([_literal_for(bit, value, one_literals)], base=base)
            if state.conflicted:
                raise RuntimeError("A214 unary probe conflicts; frozen feature schema has no sentinel")
            rows.append(
                {
                    "arity": 1,
                    "bits": [bit],
                    "values": [value],
                    "features": extract_propagation_features(cnf, base, state),
                }
            )
    for first in range(20):
        for second in range(first + 1, 20):
            for first_value in (0, 1):
                for second_value in (0, 1):
                    state = cnf.propagate(
                        [
                            _literal_for(first, first_value, one_literals),
                            _literal_for(second, second_value, one_literals),
                        ],
                        base=base,
                    )
                    if state.conflicted:
                        raise RuntimeError(
                            "A214 pair probe conflicts; frozen feature schema has no sentinel"
                        )
                    rows.append(
                        {
                            "arity": 2,
                            "bits": [first, second],
                            "values": [first_value, second_value],
                            "features": extract_propagation_features(cnf, base, state),
                        }
                    )
    if len(rows) != 800 or sum(row["arity"] == 1 for row in rows) != 40:
        raise RuntimeError("A214 complete unary/pair cover differs")
    return rows, {
        "base_assigned_variables": base.assigned_count,
        "base_satisfied_clauses": int(np.count_nonzero(base.satisfied)),
        "probe_count": len(rows),
        "feature_rows_sha256": _canonical_sha256(rows),
    }


def _challenge_features(
    *,
    cnf_raw: bytes,
    label: str,
    one_literals: Sequence[int],
    instantiation: dict[str, Any],
) -> dict[str, Any]:
    cnf = ExactCNF.from_dimacs(cnf_raw)
    if (
        cnf.variable_count != 80767
        or cnf.clause_count != 252887
        or cnf.length_counts != {1: 1556, 2: 139058, 3: 112273}
    ):
        raise RuntimeError(f"A214B {label} strict symbolic-template CNF gate failed")
    rows, summary = _probe_rows(cnf, one_literals)
    return {
        "label": label,
        "instantiation": instantiation,
        "absolute_clause_structure_sha256": _absolute_structure_sha256(cnf),
        "summary": summary,
        "rows": rows,
    }


def _row_label(row: dict[str, Any], low20: int) -> int:
    return int(
        all(((low20 >> bit) & 1) == value for bit, value in zip(row["bits"], row["values"], strict=True))
    )


def _matrix(
    challenges: Sequence[dict[str, Any]],
    *,
    arity: int,
    feature_names: Sequence[str],
) -> tuple[np.ndarray, np.ndarray]:
    vectors: list[list[float]] = []
    labels: list[int] = []
    for challenge in challenges:
        for row in challenge["rows"]:
            if row["arity"] != arity:
                continue
            vectors.append([row["features"][name] for name in feature_names])
            labels.append(_row_label(row, challenge["low20"]))
    return np.asarray(vectors, dtype=np.float64), np.asarray(labels, dtype=np.uint8)


def _fit_models(
    challenges: Sequence[dict[str, Any]],
    feature_names: Sequence[str],
    ridge_lambda: float,
    *,
    label_low20_override: Sequence[int] | None = None,
) -> tuple[RidgeLogisticModel, RidgeLogisticModel]:
    material = list(challenges)
    if label_low20_override is not None:
        material = [
            {**row, "low20": int(value)}
            for row, value in zip(material, label_low20_override, strict=True)
        ]
    unary_x, unary_y = _matrix(material, arity=1, feature_names=feature_names)
    pair_x, pair_y = _matrix(material, arity=2, feature_names=feature_names)
    return (
        fit_ridge_logistic(
            unary_x,
            unary_y,
            feature_names=feature_names,
            ridge_lambda=ridge_lambda,
        ),
        fit_ridge_logistic(
            pair_x,
            pair_y,
            feature_names=feature_names,
            ridge_lambda=ridge_lambda,
        ),
    )


def _factor_tables(
    challenge: dict[str, Any],
    feature_names: Sequence[str],
    models: tuple[RidgeLogisticModel, RidgeLogisticModel],
) -> tuple[np.ndarray, np.ndarray]:
    unary = np.full((20, 2), np.nan)
    pairs = np.full((20, 20, 2, 2), np.nan)
    unary_rows = [row for row in challenge["rows"] if row["arity"] == 1]
    pair_rows = [row for row in challenge["rows"] if row["arity"] == 2]
    ux = np.asarray(
        [[row["features"][name] for name in feature_names] for row in unary_rows]
    )
    px = np.asarray(
        [[row["features"][name] for name in feature_names] for row in pair_rows]
    )
    for row, logit in zip(unary_rows, models[0].logits(ux), strict=True):
        unary[row["bits"][0], row["values"][0]] = logit
    for row, logit in zip(pair_rows, models[1].logits(px), strict=True):
        first, second = row["bits"]
        first_value, second_value = row["values"]
        pairs[first, second, first_value, second_value] = logit
    if not np.isfinite(unary).all():
        raise RuntimeError("A214 unary factor table incomplete")
    for first in range(20):
        for second in range(first + 1, 20):
            if not np.isfinite(pairs[first, second]).all():
                raise RuntimeError("A214 pair factor table incomplete")
    pairs[np.isnan(pairs)] = 0.0
    return unary, pairs


def _rank_challenge(
    challenge: dict[str, Any],
    feature_names: Sequence[str],
    models: tuple[RidgeLogisticModel, RidgeLogisticModel],
) -> tuple[int, np.ndarray]:
    unary, pairs = _factor_tables(challenge, feature_names, models)
    scores = candidate_scores(unary, pairs)
    return exact_rank(scores, challenge["low20"]), scores


def _rank_metrics(ranks: Sequence[int]) -> dict[str, Any]:
    values = np.asarray(ranks, dtype=np.int64)
    return {
        "ranks": [int(value) for value in values],
        "median_rank": float(np.median(values)),
        "hit_at_1024": int(np.count_nonzero(values <= 1024)),
        "mean_reciprocal_rank": float(np.mean(1.0 / values)),
    }


def _selection_key(row: dict[str, Any]) -> tuple[float, int, float, float]:
    metrics = row["validation"]
    return (
        float(metrics["median_rank"]),
        -int(metrics["hit_at_1024"]),
        -float(metrics["mean_reciprocal_rank"]),
        float(row["ridge_lambda"]),
    )


def _train_family(
    name: str,
    feature_names: Sequence[str],
    training: Sequence[dict[str, Any]],
    validation: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    grid = []
    fitted: dict[float, tuple[RidgeLogisticModel, RidgeLogisticModel]] = {}
    for ridge_lambda in RIDGE_GRID:
        print(f"A214C fit {name} lambda={ridge_lambda}", flush=True)
        models = _fit_models(training, feature_names, ridge_lambda)
        fitted[ridge_lambda] = models
        ranks = [
            _rank_challenge(challenge, feature_names, models)[0]
            for challenge in validation
        ]
        grid.append(
            {
                "ridge_lambda": ridge_lambda,
                "validation": _rank_metrics(ranks),
            }
        )
    selected = min(grid, key=_selection_key)
    models = fitted[float(selected["ridge_lambda"])]
    return {
        "family": name,
        "feature_names": list(feature_names),
        "selection_grid": grid,
        "selected_ridge_lambda": selected["ridge_lambda"],
        "selected_validation": selected["validation"],
        "unary_model": models[0].as_dict(),
        "pair_model": models[1].as_dict(),
        "_models": models,
    }


def _complete_key_null(
    *,
    training: Sequence[dict[str, Any]],
    validation: Sequence[dict[str, Any]],
    feature_names: Sequence[str],
    ridge_lambda: float,
    observed: dict[str, Any],
) -> dict[str, Any]:
    keys = [row["low20"] for row in training]
    rows = []
    for null_index in range(64):
        if null_index % 8 == 0:
            print(f"A214C complete-key null {null_index}/64", flush=True)
        shift = 1 + null_index % 15
        rotated = keys[shift:] + keys[:shift]
        models = _fit_models(
            training,
            feature_names,
            ridge_lambda,
            label_low20_override=rotated,
        )
        ranks = [
            _rank_challenge(challenge, feature_names, models)[0]
            for challenge in validation
        ]
        rows.append(
            {
                "null_index": null_index,
                "complete_key_rotation": shift,
                **_rank_metrics(ranks),
            }
        )
    observed_median = float(observed["median_rank"])
    p_lower = (1 + sum(row["median_rank"] <= observed_median for row in rows)) / 65.0
    return {
        "null_count": len(rows),
        "rows": rows,
        "observed_median_rank": observed_median,
        "lower_tail_plus_one_p": p_lower,
        "complete_key_unit_preserved": True,
    }


def _model_from_dict(value: dict[str, Any]) -> RidgeLogisticModel:
    return RidgeLogisticModel(
        feature_names=tuple(value["feature_names"]),
        means=tuple(value["means"]),
        scales=tuple(value["scales"]),
        intercept=float(value["intercept"]),
        coefficients=tuple(value["coefficients"]),
        ridge_lambda=float(value["ridge_lambda"]),
        optimizer_iterations=int(value["optimizer_iterations"]),
        optimizer_gradient_norm=float(value["optimizer_gradient_norm"]),
    )


def _target_orders(
    target: dict[str, Any], trained: Sequence[dict[str, Any]]
) -> tuple[list[dict[str, Any]], np.ndarray, dict[str, np.ndarray]]:
    records = []
    rank_sum = np.zeros(1 << 20, dtype=np.uint64)
    orders: dict[str, np.ndarray] = {}
    for model in trained:
        feature_names = tuple(model["feature_names"])
        models = (
            _model_from_dict(model["unary_model"]),
            _model_from_dict(model["pair_model"]),
        )
        unary, pairs = _factor_tables(target, feature_names, models)
        scores = candidate_scores(unary, pairs)
        order = candidate_order(scores)
        ranks = np.empty(len(order), dtype=np.uint32)
        ranks[order] = np.arange(len(order), dtype=np.uint32)
        rank_sum += ranks
        orders[model["family"]] = order
        records.append(
            {
                "family": model["family"],
                "candidate_order_uint32_le_sha256": _sha256(
                    order.astype("<u4", copy=False).tobytes()
                ),
                "candidate_scores_float64_le_sha256": _sha256(
                    scores.astype("<f8", copy=False).tobytes()
                ),
                "top_1024_low20": [int(value) for value in order[:1024]],
                "top_score": float(scores[order[0]]),
            }
        )
    candidates = np.arange(1 << 20, dtype=np.uint32)
    consensus = np.lexsort((candidates, rank_sum)).astype(np.uint32, copy=False)
    orders["F5_multiview_consensus"] = consensus
    consensus_record = {
        "family": "F5_multiview_consensus",
        "candidate_order_uint32_le_sha256": _sha256(
            consensus.astype("<u4", copy=False).tobytes()
        ),
        "rank_sum_uint64_le_sha256": _sha256(
            rank_sum.astype("<u8", copy=False).tobytes()
        ),
        "top_1024_low20": [int(value) for value in consensus[:1024]],
        "component_count": len(trained),
    }
    records.append(consensus_record)
    return records, consensus, orders


def _vector_reveal_target(challenge: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    matches: list[int] = []
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    constants = np.asarray([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)

    def rol(values: np.ndarray, distance: int) -> np.ndarray:
        return (values << np.uint32(distance)) | (values >> np.uint32(32 - distance))

    qrs = (
        ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)),
        ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)),
    )
    batch_size = 1 << 16
    for first in range(0, 1 << 20, batch_size):
        count = min(batch_size, (1 << 20) - first)
        initial = np.empty((16, count), dtype=np.uint32)
        initial[:4] = constants[:, None]
        initial[4] = np.uint32(challenge["known_key_word0_upper12"]) | np.arange(
            first, first + count, dtype=np.uint32
        )
        initial[5:12] = np.asarray(
            challenge["known_key_words_1_through_7"], dtype=np.uint32
        )[:, None]
        initial[12] = np.uint32(challenge["counter_start"])
        initial[13:16] = np.asarray(challenge["nonce_words"], dtype=np.uint32)[:, None]
        state = initial.copy()
        for round_index in range(20):
            for a, b, c, d in qrs[round_index & 1]:
                state[a] += state[b]
                state[d] = rol(state[d] ^ state[a], 16)
                state[c] += state[d]
                state[b] = rol(state[b] ^ state[c], 12)
                state[a] += state[b]
                state[d] = rol(state[d] ^ state[a], 8)
                state[c] += state[d]
                state[b] = rol(state[b] ^ state[c], 7)
        output = state + initial
        local = np.flatnonzero(np.all(output == target[:, None], axis=0))
        matches.extend(first + int(index) for index in local)
    if len(matches) != 1:
        raise RuntimeError(f"A214 independent target reveal found {len(matches)} candidates")
    return matches[0], {
        "method": "independent_complete_2^20_NumPy_standard_ChaCha20_first_512bit_block",
        "candidate_count": 1 << 20,
        "batch_size": batch_size,
        "complete_domain_executed": True,
        "matching_candidate_count": len(matches),
    }


def _rank_in_order(order: np.ndarray, target: int) -> int:
    positions = np.flatnonzero(order == target)
    if len(positions) != 1:
        raise RuntimeError("A214 target is not unique in candidate order")
    return int(positions[0]) + 1


def _causal_graph(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    source = f"measurement:sha256:{payload['measurement_sha256']}"
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_knownkey_propagation_atlas",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "prereveal_sha256": payload["prereveal_sha256"],
            "target_key_unavailable_until_after_prereveal": True,
        },
    )
    builder.add_rule(
        ExactRule(
            name="knownkey_atlas_to_unseen_ranking",
            first="fits_key_disjoint_propagation_atlas",
            second="applies_frozen_multiview_candidate_order",
            conclusion="transfers_knownkey_map_to_unseen_R20_target",
        )
    )
    builder.add_triplet(
        edge_id="a214-knownkey-atlas",
        trigger="A214:16_known_R20_training_keys_plus_8_disjoint_validation_keys",
        mechanism="fits_key_disjoint_propagation_atlas",
        outcome="A214:frozen_models_and_validation",
        confidence=1.0,
        evidence_kind="complete_key_disjoint_supervised_atlas",
        source=source,
        attrs={
            "training_key_count": 16,
            "validation_key_count": 8,
            "feature_families": list(MODEL_FAMILIES),
            "complete_key_null_p": payload["prereveal"]["complete_key_label_null"][
                "lower_tail_plus_one_p"
            ],
        },
    )
    builder.add_triplet(
        edge_id="a214-prereveal-orders",
        trigger="A214:frozen_models_and_validation",
        mechanism="applies_frozen_multiview_candidate_order",
        outcome="A214:sealed_target_candidate_orders",
        confidence=1.0,
        evidence_kind="hash_sealed_prereveal_candidate_orders",
        source=source,
        attrs={
            "prereveal_sha256": payload["prereveal_sha256"],
            "order_hashes": {
                row["family"]: row["candidate_order_uint32_le_sha256"]
                for row in payload["prereveal"]["target_candidate_orders"]
            },
        },
    )
    builder.add_triplet(
        edge_id="a214-independent-reveal",
        trigger="A214:sealed_target_candidate_orders",
        mechanism="independent_complete_domain_target_reveal_after_seal",
        outcome=f"A214:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="postseal_complete_domain_reveal_and_4096bit_confirmation",
        source=source,
        attrs={
            "target_ranks": payload["target_ranks"],
            "target_collision": payload["target_collision_with_atlas"],
            "all_blocks_match": payload["confirmation"]["all_blocks_match"],
            "control_rejected": not payload["confirmation"]["control_first_block_match"],
        },
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A214 causal reader gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    ranks = payload["target_ranks"]
    lines = [
        "# ChaCha20 R20 Known-Key Propagation Atlas (A214)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A214 learns propagation-cloud signatures from 16 known R20 keys, selects all "
        "hyperparameters on eight different known keys, seals five model orders plus a "
        "correlation-aware consensus, and only then reveals the unseen target key by an "
        "independent complete `2^20` ChaCha20 enumeration.",
        "",
        "## Frozen target ranks",
        "",
    ]
    for family, rank in ranks.items():
        lines.append(f"- `{family}`: rank **{rank:,}** / 1,048,576")
    lines.extend(
        [
            "",
            "## Leakage barriers",
            "",
            f"- Prereveal SHA-256: `{payload['prereveal_sha256']}`",
            "- The target low20 value was absent during feature selection, model fitting, "
            "  validation, rank construction, and prereveal serialization.",
            f"- Target collided with an atlas key: `{payload['target_collision_with_atlas']}`",
            f"- Independent confirmation bits: `{payload['confirmation']['output_bits_checked']}`",
            f"- Flipped control rejected: `{not payload['confirmation']['control_first_block_match']}`",
            "",
            "## Reproduction",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(
    *,
    prereveal_output: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
) -> dict[str, Any]:
    protocol = _load_protocol()
    r20, helper, template_helper, ledger = _load_modules(protocol)
    analysis = r20.analyze()
    public = analysis["public_challenge"]
    with tempfile.TemporaryDirectory(prefix="a214-knownkey-atlas-") as temporary:
        directory = Path(temporary)
        base_raw, key_mapping, output_mapping, template_manifest = (
            template_helper.compile_template(
                r20=r20,
                public_challenge=public,
                protocol=protocol,
                directory=directory,
            )
        )
        target_raw, target_units, target_instantiation = (
            template_helper.instantiate_output(
                base_raw, output_mapping, public["target_words"][0]
            )
        )
        template_config = protocol["symbolic_R20_template"]
        if (
            target_instantiation["header"] != template_config["instantiated_header"]
            or target_instantiation["bytes"]
            != template_config["instantiated_target_bytes"]
            or target_instantiation["sha256"]
            != template_config["instantiated_target_sha256"]
            or target_instantiation["unit_int32le_sha256"]
            != template_config["instantiated_target_unit_int32le_sha256"]
        ):
            raise RuntimeError("A214B public target symbolic instantiation differs")
        measured_target = _challenge_features(
            cnf_raw=target_raw,
            label="unseen_public_R20_target",
            one_literals=key_mapping,
            instantiation=target_instantiation,
        )
        target = {
            "label": "unseen_public_R20_target",
            "rows": measured_target["rows"],
            "summary": measured_target["summary"],
            "absolute_clause_structure_sha256": measured_target[
                "absolute_clause_structure_sha256"
            ],
        }
        print("A214C target propagation features complete", flush=True)

        atlas_challenges: list[dict[str, Any]] = []
        instantiation_manifests: list[dict[str, Any]] = []
        for ledger_row in ledger:
            challenge = helper.training_challenge(
                public,
                low20=ledger_row["low20"],
                chacha_block=r20.P1._chacha_block,
            )
            raw, units, instantiation = template_helper.instantiate_output(
                base_raw, output_mapping, challenge["target_words"][0]
            )
            measured = _challenge_features(
                cnf_raw=raw,
                label=f"{ledger_row['split']}_{ledger_row['index']:02d}",
                one_literals=key_mapping,
                instantiation=instantiation,
            )
            if measured["absolute_clause_structure_sha256"] != target[
                "absolute_clause_structure_sha256"
            ]:
                raise RuntimeError(
                    "A214B instantiated graph absolute structure differs from target"
                )
            atlas_challenges.append(
                {
                    "split": ledger_row["split"],
                    "index": ledger_row["index"],
                    "low20": ledger_row["low20"],
                    "rows": measured["rows"],
                    "summary": measured["summary"],
                }
            )
            instantiation_manifests.append(
                {
                    "split": ledger_row["split"],
                    "index": ledger_row["index"],
                    "low20_sha256": _sha256(
                        int(ledger_row["low20"]).to_bytes(4, "little")
                    ),
                    "instantiation": instantiation,
                    "unit_count": len(units),
                    "absolute_clause_structure_sha256": measured[
                        "absolute_clause_structure_sha256"
                    ],
                    "feature_rows_sha256": measured["summary"][
                        "feature_rows_sha256"
                    ],
                }
            )
            print(
                f"A214C {ledger_row['split']} {ledger_row['index'] + 1}/"
                f"{16 if ledger_row['split'] == 'train' else 8} features complete",
                flush=True,
            )

    training = [row for row in atlas_challenges if row["split"] == "train"]
    validation = [row for row in atlas_challenges if row["split"] == "validation"]
    trained = [
        _train_family(name, names, training, validation)
        for name, names in MODEL_FAMILIES.items()
    ]
    combined = next(row for row in trained if row["family"] == "F1_F2_F3_F4_combined")
    null = _complete_key_null(
        training=training,
        validation=validation,
        feature_names=FEATURE_NAMES,
        ridge_lambda=float(combined["selected_ridge_lambda"]),
        observed=combined["selected_validation"],
    )
    serializable_models = [
        {key: value for key, value in row.items() if key != "_models"} for row in trained
    ]
    target_orders, _consensus_order, order_arrays = _target_orders(
        target, serializable_models
    )
    prereveal = {
        "schema": "chacha20-round20-knownkey-propagation-atlas-prereveal-v3",
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "target_key_available_during_this_artifact": False,
        "R20_solver_output_read_during_this_artifact": False,
        "atlas_ledger_sha256": helper.atlas_ledger_sha256(ledger),
        "symbolic_template_manifest": template_manifest,
        "known_key_instantiation_manifest_sha256": _canonical_sha256(
            instantiation_manifests
        ),
        "known_key_instantiation_manifests": instantiation_manifests,
        "target_instantiation": target_instantiation,
        "target_feature_rows_sha256": measured_target["summary"][
            "feature_rows_sha256"
        ],
        "absolute_clause_structure_sha256": target["absolute_clause_structure_sha256"],
        "models": serializable_models,
        "complete_key_label_null": null,
        "target_candidate_orders": target_orders,
        "all_model_weights_headers_and_orders_frozen": True,
    }
    _atomic_json(prereveal_output, prereveal)
    prereveal_sha256 = _file_sha256(prereveal_output)
    if json.loads(prereveal_output.read_bytes()) != prereveal:
        raise RuntimeError("A214 prereveal atomic readback differs")

    target_low20, reveal = _vector_reveal_target(public)
    ranks = {
        family: _rank_in_order(order, target_low20)
        for family, order in order_arrays.items()
    }
    atlas_values = {row["low20"] for row in ledger}
    collision = target_low20 in atlas_values
    model = r20._decode_model(public, [(target_low20 >> bit) & 1 for bit in range(20)])
    confirmation = r20._confirm_model(
        public,
        mode="A214_postseal_independent_reveal",
        prefix8=f"{(target_low20 >> 12) & 0xFF:08b}",
        model=model,
    )
    if not confirmation["all_blocks_match"] or confirmation["control_first_block_match"]:
        raise RuntimeError("A214 revealed target failed independent 4096-bit confirmation")
    consensus_rank = ranks["F5_multiview_consensus"]
    validation_beats_null = null["lower_tail_plus_one_p"] <= 0.05
    if collision:
        evidence_stage = "TARGET_KEY_COLLISION_BOUNDARY"
    elif not validation_beats_null:
        evidence_stage = "KNOWNKEY_PROPAGATION_ATLAS_REPRESENTATION_BOUNDARY"
    elif consensus_rank == 1:
        evidence_stage = "UNSEEN_R20_KEY_RANK1_TRANSFER_CONFIRMED"
    elif consensus_rank <= 1024 and validation_beats_null:
        evidence_stage = "UNSEEN_R20_KEY_TOP1024_TRANSFER_RETAINED"
    elif consensus_rank <= 1024:
        evidence_stage = "UNSEEN_R20_KEY_DOMAIN_RANKING_DISCOVERY"
    else:
        evidence_stage = "KNOWNKEY_PROPAGATION_ATLAS_REPRESENTATION_BOUNDARY"

    measurement = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "prereveal_path": str(prereveal_output),
        "prereveal_sha256": prereveal_sha256,
        "prereveal": prereveal,
        "target_reveal": {
            **reveal,
            "target_low20": target_low20,
            "target_low20_hex": f"{target_low20:05x}",
        },
        "target_collision_with_atlas": collision,
        "target_ranks": ranks,
        "consensus_top_k_hits": {
            str(k): consensus_rank <= k for k in (1, 8, 32, 256, 1024, 1 << 20)
        },
        "confirmation": confirmation,
        "evidence_stage": evidence_stage,
        "information_boundary": protocol["information_boundary"],
    }
    measurement_sha256 = _canonical_sha256(measurement)
    payload = {**measurement, "measurement_sha256": measurement_sha256}
    causal = _causal_graph(payload, causal_output)
    payload["causal_artifact"] = causal
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prereveal-output",
        type=Path,
        default=RESEARCH
        / "results"
        / "v1"
        / "chacha20_round20_knownkey_propagation_atlas_v3_prereveal.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH / "results" / "v1" / "chacha20_round20_knownkey_propagation_atlas_v3.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH / "results" / "v1" / "chacha20_round20_knownkey_propagation_atlas_v3.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_KNOWNKEY_PROPAGATION_ATLAS_V3.md",
    )
    args = parser.parse_args()
    payload = run(
        prereveal_output=args.prereveal_output,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
    )
    print(payload["evidence_stage"])
    print(json.dumps(payload["target_ranks"], sort_keys=True))
    print(f"wrote {args.prereveal_output}")
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output}")
    print(f"wrote {args.report_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
