#!/usr/bin/env python3
"""Execute the frozen A251 exact learned-clause identity reader.

Every eight-bit candidate prefix starts from a fresh copy of the same unsolved
ChaCha20-R20 CNF.  Exact learned clauses are captured at four shallow conflict
horizons, projected away from the eight candidate-assumption variables, and
read by a nested prefix-blind Bernoulli Product-of-Experts.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.learned_clause_reader import (  # noqa: E402
    TOKEN_FAMILIES,
    ClauseIdentityTable,
    LearnedClausePoE,
    build_clause_identity_table,
)

PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_clause_identity_reader_v1.json"
PROTOCOL_SHA256 = "c2a6c2280b8c1c652d67453d12c5987506ffd6b88fa2290cc7340d357c63c9f7"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_clause_identity_reader_v1.json"
SHARD_ROOT = ROOT / "research/results/v1/chacha20_round20_fresh_clause_identity_reader_v1"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_clause_identity_reader_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_IDENTITY_READER_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A251"
SHARD_SCHEMA = "chacha20-round20-fresh-clause-identity-measurement-v1"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-identity-reader-result-v1"
ZSTD_LEVEL = 19


@dataclass(frozen=True)
class _ClauseTableCache:
    table: ClauseIdentityTable
    negative_support: Mapping[str, int]
    candidate_postings: Mapping[str, tuple[int, ...]]


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


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    _atomic_bytes(path, raw)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A251 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A251 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    measurement = protocol.get("measurement", {})
    feature = protocol.get("feature_contract", {})
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-identity-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A250_personal_causal_readback_and_synthetic_PHP_preflight_before_any_R20_learned_clause_identity_measurement_or_model_fit"
        or protocol.get("input", {}).get("known_key_count") != 20
        or len(protocol.get("input", {}).get("labels", [])) != 20
        or len(set(protocol.get("input", {}).get("labels", []))) != 20
        or measurement.get("conflict_horizons") != [1, 2, 4, 8]
        or measurement.get("maximum_concurrent_key_processes") != 2
        or measurement.get("bounded_variable_addition_enabled") is not False
        or measurement.get("early_stop_permitted") is not False
        or feature.get("candidate_numeric_value_or_candidate_bits_included") is not False
        or operator.get("operator_setting_count") != 27
        or boundary.get("any_R20_learned_clause_identity_measurement_before_protocol_freeze")
        is not False
        or boundary.get("any_learned_clause_PoE_fit_before_protocol_freeze") is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A251 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        path = _anchor_path(path_value)
        if not isinstance(expected, str) or _file_sha256(path) != expected:
            raise RuntimeError(f"A251 anchored dependency hash differs: {path_key}")
    a242 = _import_path(ROOT / anchors["A242_runner_path"], "a251_a242")
    return protocol, a242


def _prepare(
    protocol: Mapping[str, Any], a242: Any, directory: Path
) -> dict[str, Any]:
    a242_protocol = a242._load_protocol()
    prepared = a242._prepare(a242_protocol, directory)
    labels = list(protocol["input"]["labels"])
    if [row["label"] for row in prepared["rows"]] != labels:
        raise RuntimeError("A251 known-key design slice differs from frozen labels")
    anchors = protocol["anchors"]
    clause_wrapper = _import_path(
        ROOT / anchors["clause_identity_wrapper_path"], "a251_clause_wrapper"
    )
    # The wrapper lazily imports its shared parser.  Load it once here before
    # worker threads start so no thread can observe a partially initialized
    # module through sys.modules.
    clause_wrapper._load_base_wrapper()
    build = clause_wrapper.compile_helper()
    helper = Path(build["binary_path"])
    if (
        build["source_sha256_started"]
        != anchors["clause_identity_native_source_sha256"]
        or build["source_sha256_finished"]
        != anchors["clause_identity_native_source_sha256"]
        or build["base_source_sha256_started"]
        != anchors["base_native_source_sha256"]
        or build["base_source_sha256_finished"]
        != anchors["base_native_source_sha256"]
        or build["cadical_header_sha256"] != anchors["cadical_header_sha256"]
        or build["cadical_library_sha256"]
        != anchors["cadical_static_library_sha256"]
        or _file_sha256(helper) != build["binary_sha256"]
    ):
        raise RuntimeError("A251 clause-identity helper build gate failed")
    return {
        **prepared,
        "clause_wrapper": clause_wrapper,
        "clause_helper": helper,
        "clause_helper_build": build,
    }


def analyze() -> dict[str, Any]:
    protocol, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "known_key_count": protocol["input"]["known_key_count"],
        "candidate_measurements": protocol["input"]["known_key_count"] * 256,
        "operator_settings": protocol["operator"]["operator_setting_count"],
        "protocol_state": protocol["protocol_state"],
        "R20_clause_identity_measurement_started": False,
    }


def _stable_run(run: Mapping[str, Any]) -> dict[str, Any]:
    omitted = {"command", "process_elapsed_seconds"}
    return {key: value for key, value in run.items() if key not in omitted}


def _measurement_path(label: str, order_name: str) -> Path:
    return SHARD_ROOT / f"{label}.{order_name}.measurement.json.zst"


def _write_measurement(path: Path, measurement: Mapping[str, Any]) -> dict[str, Any]:
    raw = _canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    _atomic_bytes(path, compressed)
    return {
        "path": str(path.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": _sha256(compressed),
    }


def _read_measurement(path: Path) -> dict[str, Any]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != SHARD_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != PROTOCOL_SHA256
        or value.get("complete_candidate_cover") is not True
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A251 measurement shard gate failed: {path.name}")
    build_clause_identity_table(value)
    return value


def _execute_one(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    row: Mapping[str, Any],
    order_name: str,
    order: Sequence[str],
    directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output = _measurement_path(str(row["label"]), order_name)
    if output.exists():
        measurement = _read_measurement(output)
        if measurement["label"] != row["label"] or measurement["order_name"] != order_name:
            raise RuntimeError("A251 resumable shard identity differs")
        compressed = output.read_bytes()
        raw = zstandard.ZstdDecompressor().decompress(compressed)
        return measurement, {
            "path": str(output.relative_to(ROOT)),
            "raw_bytes": len(raw),
            "raw_sha256": _sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": _sha256(compressed),
            "resumed": True,
        }
    public = prepared["public"]
    template = prepared["template"]
    challenge = public.build_known_challenge(
        prepared["public_material"], low20=int(row["low20"])
    )
    raw_cnf, _, instantiation = template.instantiate_output(
        prepared["base_raw"], prepared["output_mapping"], challenge["target_words"][0]
    )
    key_directory = directory / f"{row['label']}_{order_name}"
    key_directory.mkdir(parents=True, exist_ok=True)
    cnf = key_directory / "instance.cnf"
    _atomic_bytes(cnf, raw_cnf)
    if _file_sha256(cnf) != instantiation["sha256"]:
        raise RuntimeError("A251 instantiated CNF readback differs")
    started = time.perf_counter()
    run = prepared["clause_wrapper"].run_fresh_clause_identity(
        helper=prepared["clause_helper"],
        cnf=cnf,
        mode=f"A251_{row['label']}_{order_name}",
        order=order,
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=protocol["measurement"]["conflict_horizons"],
        watchdog_seconds=float(protocol["measurement"]["watchdog_seconds_per_stage"]),
        external_timeout_seconds=900.0,
    )
    measurement = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "label": row["label"],
        "order_name": order_name,
        "known_key_design": {
            "prefix_split": row["prefix_split"],
            "prefix_index": row["prefix_index"],
            "prefix8": row["prefix8"],
            "prefix8_binary": row["prefix8_binary"],
            "suffix_split": row["suffix_split"],
            "suffix_index": row["suffix_index"],
            "suffix12": row["suffix12"],
            "low20": row["low20"],
        },
        "public_target_block_sha256": list(challenge["target_block_sha256"]),
        "cnf_instantiation": instantiation,
        "run": _stable_run(run),
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "label_used_only_after_fixed_measurement": True,
        "complete_candidate_cover": len(run["cells"]) == 256,
    }
    build_clause_identity_table(measurement)
    ledger = _write_measurement(output, measurement)
    cnf.unlink(missing_ok=True)
    return measurement, {**ledger, "resumed": False}


def _stable_order_view(measurement: Mapping[str, Any]) -> dict[str, Any]:
    def stable(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in row.items()
            if key not in {"mode", "cell_index", "elapsed_seconds"}
        }

    run = measurement["run"]
    stages = sorted(
        (stable(row) for row in run["stages"]),
        key=lambda row: (row["prefix8"], row["horizon"]),
    )
    cells = sorted(
        (stable(row) for row in run["cells"]), key=lambda row: row["prefix8"]
    )
    summary = stable(run["summary"])
    return {"stages": stages, "cells": cells, "summary": summary}


def _prefix_index(label: str) -> int:
    marker = "a220_select_p"
    if not label.startswith(marker):
        raise ValueError("A251 label is not a select-prefix row")
    return int(label[len(marker) : len(marker) + 2])


def _descending_midrank(scores: np.ndarray, true_prefix: int) -> float:
    target = float(scores[true_prefix])
    better = int(np.count_nonzero(scores > target))
    ties = int(np.count_nonzero(scores == target))
    return 1.0 + better + 0.5 * (ties - 1)


def _score_tables(
    model: LearnedClausePoE, tables: Sequence[ClauseIdentityTable]
) -> list[dict[str, Any]]:
    rows = []
    for table in tables:
        scores = model.scores(table)
        rows.append(
            {
                "label": table.label,
                "prefix_index": _prefix_index(table.label),
                "true_prefix": table.true_prefix,
                "true_score": float(scores[table.true_prefix]),
                "midrank": _descending_midrank(scores, table.true_prefix),
                "scores": [float(value) for value in scores],
            }
        )
    return rows


def _cache_table(table: ClauseIdentityTable) -> _ClauseTableCache:
    negative_support: Counter[str] = Counter()
    postings: defaultdict[str, list[int]] = defaultdict(list)
    for candidate, tokens in enumerate(table.candidate_tokens):
        for token in tokens:
            postings[token].append(candidate)
        if candidate != table.true_prefix:
            negative_support.update(tokens)
    return _ClauseTableCache(
        table=table,
        negative_support=dict(negative_support),
        candidate_postings={
            token: tuple(candidates) for token, candidates in postings.items()
        },
    )


def _fit_cached_clause_poe(
    training: Sequence[_ClauseTableCache],
    *,
    minimum_positive_support: int,
    beta_smoothing: float,
    token_log_odds_cap: float,
) -> LearnedClausePoE:
    positive_support: Counter[str] = Counter()
    for cache in training:
        positive_support.update(
            cache.table.candidate_tokens[cache.table.true_prefix]
        )
    positive_documents = len(training)
    negative_documents = positive_documents * 255
    weights: dict[str, float] = {}
    for token, positive_count in positive_support.items():
        if positive_count < minimum_positive_support:
            continue
        negative_count = sum(
            int(cache.negative_support.get(token, 0)) for cache in training
        )
        positive_probability = (positive_count + beta_smoothing) / (
            positive_documents + 2.0 * beta_smoothing
        )
        negative_probability = (negative_count + beta_smoothing) / (
            negative_documents + 2.0 * beta_smoothing
        )
        log_odds = math.log(
            positive_probability / (1.0 - positive_probability)
        ) - math.log(negative_probability / (1.0 - negative_probability))
        weights[token] = float(
            max(-token_log_odds_cap, min(token_log_odds_cap, log_odds))
        )
    return LearnedClausePoE(
        token_weights=weights,
        minimum_positive_support=minimum_positive_support,
        beta_smoothing=float(beta_smoothing),
        token_log_odds_cap=float(token_log_odds_cap),
        positive_documents=positive_documents,
        negative_documents=negative_documents,
    )


def _cached_scores(model: LearnedClausePoE, cache: _ClauseTableCache) -> np.ndarray:
    family_index = {family: index for index, family in enumerate(TOKEN_FAMILIES)}
    sums = np.zeros((len(TOKEN_FAMILIES), 256), dtype=np.float64)
    counts = np.zeros((len(TOKEN_FAMILIES), 256), dtype=np.int32)
    for token, weight in model.token_weights.items():
        candidates = cache.candidate_postings.get(token)
        if not candidates:
            continue
        family = token.split("|", 1)[0]
        index = family_index.get(family)
        if index is None:
            raise RuntimeError("A251 cached token family differs")
        candidate_array = np.fromiter(candidates, dtype=np.int32)
        sums[index, candidate_array] += float(weight)
        counts[index, candidate_array] += 1
    scores = np.zeros(256, dtype=np.float64)
    for index in range(len(TOKEN_FAMILIES)):
        present = counts[index] > 0
        scores[present] += sums[index, present] / counts[index, present]
    if not np.isfinite(scores).all():
        raise RuntimeError("A251 cached clause PoE produced non-finite scores")
    return scores


def _score_cached_tables(
    model: LearnedClausePoE, caches: Sequence[_ClauseTableCache]
) -> list[dict[str, Any]]:
    rows = []
    for cache in caches:
        table = cache.table
        scores = _cached_scores(model, cache)
        rows.append(
            {
                "label": table.label,
                "prefix_index": _prefix_index(table.label),
                "true_prefix": table.true_prefix,
                "true_score": float(scores[table.true_prefix]),
                "midrank": _descending_midrank(scores, table.true_prefix),
                "scores": [float(value) for value in scores],
            }
        )
    return rows


def _mean_log2(rows: Sequence[Mapping[str, Any]]) -> float:
    return sum(math.log2(float(row["midrank"])) for row in rows) / len(rows)


def _select_operator(
    training: Sequence[_ClauseTableCache],
    supports: Sequence[int],
    smoothings: Sequence[float],
    caps: Sequence[float],
) -> tuple[int, float, float, list[dict[str, Any]]]:
    groups = sorted({_prefix_index(cache.table.label) for cache in training})
    if len(groups) < 2:
        raise ValueError("A251 inner selection requires multiple prefix groups")
    ledger = []
    for support in supports:
        for smoothing in smoothings:
            for cap in caps:
                rows = []
                retained_counts = []
                for test_group in groups:
                    inner_train = [
                        cache
                        for cache in training
                        if _prefix_index(cache.table.label) != test_group
                    ]
                    inner_test = [
                        cache
                        for cache in training
                        if _prefix_index(cache.table.label) == test_group
                    ]
                    model = _fit_cached_clause_poe(
                        inner_train,
                        minimum_positive_support=int(support),
                        beta_smoothing=float(smoothing),
                        token_log_odds_cap=float(cap),
                    )
                    rows.extend(_score_cached_tables(model, inner_test))
                    retained_counts.append(len(model.token_weights))
                ledger.append(
                    {
                        "minimum_positive_support": int(support),
                        "beta_smoothing": float(smoothing),
                        "token_log_odds_cap": float(cap),
                        "inner_holdout_mean_log2_rank": _mean_log2(rows),
                        "inner_retained_token_counts": retained_counts,
                        "inner_holdout_ranks": [
                            {
                                key: row[key]
                                for key in (
                                    "label",
                                    "prefix_index",
                                    "true_prefix",
                                    "midrank",
                                )
                            }
                            for row in rows
                        ],
                    }
                )
    selected = min(
        ledger,
        key=lambda row: (
            row["inner_holdout_mean_log2_rank"],
            -row["minimum_positive_support"],
            -row["beta_smoothing"],
            row["token_log_odds_cap"],
        ),
    )
    return (
        int(selected["minimum_positive_support"]),
        float(selected["beta_smoothing"]),
        float(selected["token_log_odds_cap"]),
        ledger,
    )


def nested_evaluate(
    tables: Sequence[ClauseIdentityTable],
    supports: Sequence[int],
    smoothings: Sequence[float],
    caps: Sequence[float],
) -> dict[str, Any]:
    groups = sorted({_prefix_index(table.label) for table in tables})
    if len(tables) != 20 or groups != [0, 1, 2, 3, 4]:
        raise ValueError("A251 outer fold geometry differs")
    caches = [_cache_table(table) for table in tables]
    folds = []
    all_rows = []
    for outer_group in groups:
        training = [
            cache
            for cache in caches
            if _prefix_index(cache.table.label) != outer_group
        ]
        testing = [
            cache
            for cache in caches
            if _prefix_index(cache.table.label) == outer_group
        ]
        support, smoothing, cap, inner_ledger = _select_operator(
            training, supports, smoothings, caps
        )
        model = _fit_cached_clause_poe(
            training,
            minimum_positive_support=support,
            beta_smoothing=smoothing,
            token_log_odds_cap=cap,
        )
        scored = _score_cached_tables(model, testing)
        model_dict = model.as_dict()
        fold = {
            "outer_prefix_index": outer_group,
            "outer_true_prefix": testing[0].table.true_prefix,
            "selected_minimum_positive_support": support,
            "selected_beta_smoothing": smoothing,
            "selected_token_log_odds_cap": cap,
            "inner_selection": inner_ledger,
            "model_sha256": _canonical_sha256(model_dict),
            "model": model_dict,
            "test_rows": scored,
            "test_mean_log2_rank": _mean_log2(scored),
        }
        folds.append(fold)
        all_rows.extend(scored)
    observed = _mean_log2(all_rows)
    shifted = []
    for xor_offset in range(256):
        ranks = []
        for row in all_rows:
            scores = np.asarray(row["scores"], dtype=np.float64)
            ranks.append(
                _descending_midrank(scores, int(row["true_prefix"]) ^ xor_offset)
            )
        shifted.append(sum(math.log2(rank) for rank in ranks) / len(ranks))
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    exact_p = sum(value <= observed + 1e-15 for value in shifted) / 256.0
    return {
        "outer_folds": folds,
        "outer_holdout_rows": all_rows,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "outer_prefix_folds_with_positive_bit_gain": sum(
            uniform - fold["test_mean_log2_rank"] > 0 for fold in folds
        ),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": exact_p,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def _table_sha256(table: ClauseIdentityTable) -> str:
    digest = hashlib.sha256()
    digest.update(table.label.encode())
    digest.update(table.true_prefix.to_bytes(1, "little"))
    for candidate, tokens in enumerate(table.candidate_tokens):
        digest.update(candidate.to_bytes(1, "little"))
        for token in sorted(tokens):
            encoded = token.encode()
            digest.update(len(encoded).to_bytes(4, "little"))
            digest.update(encoded)
    return digest.hexdigest()


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    a242: Any,
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = a242._load_dotcausal(dotcausal_src)
    evaluation = payload["evaluation"]
    retained = payload["retention_gate"]["passed"]
    outcome = (
        "A251:exact_clause_identity_transfer_retained"
        if retained
        else "A251:exact_clause_identity_representation_boundary"
    )
    writer = CausalWriter(api_id="a251")
    writer._rules = []
    writer.add_rule(
        name="assumption_projected_clause_identity",
        description="Projecting the eight temporary candidate-assumption variables out of every learned clause preserves exact propagated CNF identity without leaking candidate bits into the reader.",
        pattern=["exact_shallow_learned_clauses", "assumption_variable_projection"],
        conclusion="candidate_blind_clause_topology",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_unseen_prefix_clause_validation",
        description="Every outer prefix is scored by a clause-identity PoE whose hyperparameters and token weights were selected without that prefix group.",
        pattern=["inner_clause_operator_selection", "unseen_outer_prefix"],
        conclusion="prefix_blind_clause_transfer_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A251:R20_fresh_candidate_CNF_copies",
        mechanism="fixed_conflict_horizons_with_bounded_variable_addition_disabled",
        outcome="A251:exact_shallow_learned_clause_corpus",
        confidence=1.0,
        source=payload["native_source_sha256"],
        quantification="20 known keys x 256 candidates x horizons 1,2,4,8",
        evidence=json.dumps(payload["clause_corpus"], sort_keys=True),
        domain="exact CDCL clause identity",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A251:exact_shallow_learned_clause_corpus",
        mechanism="remove_eight_candidate_assumption_variable_identities",
        outcome="A251:eight_candidate_blind_clause_token_families",
        confidence=1.0,
        source=payload["reader_source_sha256"],
        quantification="signed/unsigned variables, exact clauses, and signed pairs with stage-specific and horizon-collapsed views",
        evidence=json.dumps(payload["feature_contract"], sort_keys=True),
        domain="typed learned-clause projection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A251:eight_candidate_blind_clause_token_families",
        mechanism="nested_Bernoulli_product_of_experts",
        outcome="A251:five_unseen_prefix_clause_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="five outer folds; 27 frozen operator settings selected inside training folds",
        evidence=json.dumps(
            [
                {
                    "prefix": fold["outer_prefix_index"],
                    "support": fold["selected_minimum_positive_support"],
                    "smoothing": fold["selected_beta_smoothing"],
                    "cap": fold["selected_token_log_odds_cap"],
                    "mean_log2_rank": fold["test_mean_log2_rank"],
                }
                for fold in evaluation["outer_folds"]
            ],
            sort_keys=True,
        ),
        domain="nested known-key exact-identity reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A251:five_unseen_prefix_clause_models",
        mechanism="unseen_prefix_ranks_plus_all_256_XOR_controls",
        outcome=outcome,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=(
            f"gain={evaluation['mean_log2_rank_bit_gain']:.12f}; "
            f"exact p={evaluation['exact_shared_xor_p']:.12f}"
        ),
        evidence=json.dumps(payload["retention_gate"], sort_keys=True),
        domain="exact XOR-invariant outer validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A251:numeric_and_reverse_candidate_orders",
        mechanism="fresh_state_exact_clause_order_replication",
        outcome="A251:nonvolatile_clause_identity_measurement_identity",
        confidence=1.0,
        source=payload["order_replication_sha256"],
        quantification="one complete 256-candidate key replicated in reverse order",
        evidence=json.dumps(payload["order_replication"], sort_keys=True),
        domain="solver-history identity control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A251:R20_fresh_candidate_CNF_copies",
        mechanism="materialized_exact_clause_identity_chain",
        outcome=outcome,
        confidence=1.0,
        source="materialized:assumption_projected_clause_identity+nested_unseen_prefix_clause_validation",
        quantification="five-edge closure retained in-file",
        evidence="Materialized after complete fresh-state collection, nested outer evaluation, reverse-order replication, and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A251 exact learned-clause chain",
        entities=[
            "A251:R20_fresh_candidate_CNF_copies",
            "fixed_conflict_horizons_with_bounded_variable_addition_disabled",
            "A251:exact_shallow_learned_clause_corpus",
            "remove_eight_candidate_assumption_variable_identities",
            "A251:eight_candidate_blind_clause_token_families",
        ],
    )
    writer.add_cluster(
        name="A251 nested unseen-prefix chain",
        entities=[
            "nested_Bernoulli_product_of_experts",
            "A251:five_unseen_prefix_clause_models",
            "unseen_prefix_ranks_plus_all_256_XOR_controls",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_entirely_new_known_key_clause_identity_validation"
            if retained
            else "public_CNF_semantic_topology_and_graph_distance_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the selected clause operator before generating new prefix groups.",
                "If retained prospectively, order a sealed unknown target without exhaustive evaluation.",
            ]
            if retained
            else [
                "Map learned variable IDs to ChaCha operations, rounds, lanes, and bit positions.",
                "Do correct candidates occupy a transferable graph-distance geometry even when exact IDs do not recur?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a251"
        or len(explicit) != 5
        or len(rows) != 6
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A251 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    evaluation = payload["evaluation"]
    causal = payload["causal"]
    lines = [
        "# A251 — ChaCha20-R20 exact learned-clause identity reader",
        "",
        "This frozen experiment captures exact shallow-CDCL learned clauses from fresh candidate solvers, projects away all eight candidate-assumption variables, and evaluates a nested prefix-blind Product-of-Experts across five unseen prefix groups.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Outer-holdout mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Rank-information gain: **{evaluation['mean_log2_rank_bit_gain']:.12f} bits**",
        f"- Exact shared-XOR p: **{evaluation['exact_shared_xor_p']:.12f}**",
        f"- Prefix folds with positive gain: **{evaluation['outer_prefix_folds_with_positive_bit_gain']} / 5**",
        f"- Reverse-order exact identity: **{payload['order_replication']['nonvolatile_measurements_identical']}**",
        f"- Captured accepted clauses: **{payload['clause_corpus']['accepted_learned_clauses']}**",
        "",
        "## Outer folds",
        "",
        "| Prefix | Min support | Beta | Cap | Retained tokens | Mean log2 rank |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for fold in evaluation["outer_folds"]:
        lines.append(
            f"| {fold['outer_prefix_index']} | {fold['selected_minimum_positive_support']} | {fold['selected_beta_smoothing']} | {fold['selected_token_log_odds_cap']} | {fold['model']['retained_token_count']} | {fold['test_mean_log2_rank']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / inferred: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        ]
    )
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, a242 = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a251_clause_identity_") as temporary:
        directory = Path(temporary)
        prepared = _prepare(protocol, a242, directory)
        numeric = prepared["fresh"].numeric_order()
        jobs = [(row, "numeric", numeric) for row in prepared["rows"]]
        replicate_label = protocol["measurement"]["order_replication"]["label"]
        replicate_row = next(
            row for row in prepared["rows"] if row["label"] == replicate_label
        )
        jobs.append((replicate_row, "reverse_numeric", list(reversed(numeric))))
        measurements: dict[tuple[str, str], dict[str, Any]] = {}
        ledgers: dict[tuple[str, str], dict[str, Any]] = {}
        with ThreadPoolExecutor(
            max_workers=int(protocol["measurement"]["maximum_concurrent_key_processes"])
        ) as executor:
            futures = {
                executor.submit(
                    _execute_one,
                    protocol=protocol,
                    prepared=prepared,
                    row=row,
                    order_name=order_name,
                    order=order,
                    directory=directory,
                ): (str(row["label"]), order_name)
                for row, order_name, order in jobs
            }
            for future in as_completed(futures):
                identity = futures[future]
                measurement, ledger = future.result()
                measurements[identity] = measurement
                ledgers[identity] = ledger
                print(
                    "A251_KEY "
                    + json.dumps(
                        {
                            "label": identity[0],
                            "order": identity[1],
                            "seconds": measurement["volatile_process_elapsed_seconds"],
                            "accepted_clauses": measurement["run"]["summary"][
                                "learned_clause_accepted_total"
                            ],
                            "resumed": ledger["resumed"],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
    labels = list(protocol["input"]["labels"])
    numeric_measurements = [measurements[(label, "numeric")] for label in labels]
    tables = [build_clause_identity_table(item) for item in numeric_measurements]
    replicate_numeric = measurements[(replicate_label, "numeric")]
    replicate_reverse = measurements[(replicate_label, "reverse_numeric")]
    numeric_view = _stable_order_view(replicate_numeric)
    reverse_view = _stable_order_view(replicate_reverse)
    order_replication = {
        "label": replicate_label,
        "numeric_stable_sha256": _canonical_sha256(numeric_view),
        "reverse_stable_sha256": _canonical_sha256(reverse_view),
        "nonvolatile_measurements_identical": numeric_view == reverse_view,
    }
    operator = protocol["operator"]
    evaluation = nested_evaluate(
        tables,
        operator["minimum_positive_support_grid"],
        operator["beta_smoothing_grid"],
        operator["token_log_odds_cap_grid"],
    )
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["outer_prefix_folds_with_positive_bit_gain"]
        >= gate["minimum_outer_prefix_folds_with_positive_bit_gain"]
        and order_replication["nonvolatile_measurements_identical"]
    )
    ordered_ledgers = [
        {"label": label, "order": order_name, **ledgers[(label, order_name)]}
        for label, order_name in [
            *((label, "numeric") for label in labels),
            (replicate_label, "reverse_numeric"),
        ]
    ]
    clause_corpus = {
        "known_keys": len(numeric_measurements),
        "candidate_measurements": len(numeric_measurements) * 256,
        "accepted_learned_clauses": sum(
            item["run"]["summary"]["learned_clause_accepted_total"]
            for item in numeric_measurements
        ),
        "rejected_large_clauses": sum(
            item["run"]["summary"]["learned_clause_rejected_large_total"]
            for item in numeric_measurements
        ),
        "projected_token_counts_per_key": [
            sum(len(tokens) for tokens in table.candidate_tokens) for table in tables
        ],
        "bounded_variable_addition_enabled": False,
        "candidate_assumption_variables_projected_before_tokenization": True,
    }
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_EXACT_CLAUSE_IDENTITY_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_EXACT_CLAUSE_IDENTITY_REPRESENTATION_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "feature_contract": protocol["feature_contract"],
        "operator_grid": {
            "minimum_positive_support": operator["minimum_positive_support_grid"],
            "beta_smoothing": operator["beta_smoothing_grid"],
            "token_log_odds_cap": operator["token_log_odds_cap_grid"],
            "settings": operator["operator_setting_count"],
        },
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "order_replication": order_replication,
        "order_replication_sha256": _canonical_sha256(order_replication),
        "clause_corpus": clause_corpus,
        "measurement_ledger": ordered_ledgers,
        "measurement_ledger_sha256": _canonical_sha256(ordered_ledgers),
        "input_table_sha256": _canonical_sha256(
            [
                {
                    "label": table.label,
                    "true_prefix": table.true_prefix,
                    "table_sha256": _table_sha256(table),
                }
                for table in tables
            ]
        ),
        "fresh_state_gate": {
            "validation_keys": 20,
            "candidate_measurements": 20 * 256,
            "fresh_solver_instances": 20 * 256,
            "identical_base_snapshot_per_key": all(
                item["run"]["base_snapshot_identical_verified"]
                for item in numeric_measurements
            ),
            "complete_candidate_cover": all(
                item["complete_candidate_cover"] for item in numeric_measurements
            ),
            "early_stop_used": False,
        },
        "helper_binary_sha256": prepared["clause_helper_build"]["binary_sha256"],
        "native_source_sha256": protocol["anchors"][
            "clause_identity_native_source_sha256"
        ],
        "reader_source_sha256": protocol["anchors"]["learned_clause_reader_sha256"],
        "template_manifest": prepared["template_manifest"],
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(CAUSAL, payload, a242, dotcausal_src)
    _atomic_json(RESULT, payload)
    _atomic_bytes(REPORT, _report(payload).encode())
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                "mean_log2_rank": evaluation["mean_log2_rank"],
                "bit_gain": evaluation["mean_log2_rank_bit_gain"],
                "exact_shared_xor_p": evaluation["exact_shared_xor_p"],
                "positive_prefix_folds": evaluation[
                    "outer_prefix_folds_with_positive_bit_gain"
                ],
                "accepted_learned_clauses": clause_corpus[
                    "accepted_learned_clauses"
                ],
                "result": str(RESULT),
                "causal": str(CAUSAL),
                "report": str(REPORT),
            },
            indent=2,
        ),
        flush=True,
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args()
    if args.run:
        execute(dotcausal_src=args.dotcausal_src)
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
