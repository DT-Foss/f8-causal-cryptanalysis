#!/usr/bin/env python3
"""Collect resumable key-disjoint A218 R20 budgeted trajectories."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_knownkey_trajectory_atlas_v1.json"
PROTOCOL_SHA256 = "037b415e25e0956a2d8b13cd0bd62a838c50dce6b831ddc8734bd03ed2ec44c7"
PUBLIC_TARGET = RESEARCH / "challenges/chacha20_round20_knownkey_trajectory_atlas_v1_public.json"
DEFAULT_CORPUS = RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_corpus_v1.json"
DEFAULT_TARGET = RESEARCH / "results/v1/chacha20_round20_target_trajectory_v1.json"
DEFAULT_CHECKPOINT = ROOT / ".research_sealed/a218_trajectory_collection_checkpoint_v1.json"
OPERATORS = ("numeric", "reflected_gray8")


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


def _atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    )
    if private:
        temporary.chmod(0o600)
    temporary.replace(path)
    if private:
        path.chmod(0o600)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _forbidden_secret_keys(value: Any) -> set[str]:
    forbidden = {"low20", "low20_hex", "salt", "salt_hex", "secret_low20"}
    found: set[str] = set()
    if isinstance(value, dict):
        found.update(forbidden & set(value))
        for child in value.values():
            found.update(_forbidden_secret_keys(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_forbidden_secret_keys(child))
    return found


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A218 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    public_target = json.loads(PUBLIC_TARGET.read_bytes())
    if (
        public_target.get("schema") != "chacha20-round20-trajectory-target-public-v1"
        or public_target.get("protocol_sha256") != PROTOCOL_SHA256
        or public_target.get("low20_or_salt_present") is not False
        or public_target.get("challenge_sha256")
        != _canonical_sha256(public_target.get("public_challenge"))
        or _forbidden_secret_keys(public_target)
    ):
        raise RuntimeError("A218 public target information boundary failed")
    return protocol, public_target


def _scientific_trajectory(value: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    for row in value["rows"]:
        rows.append(
            {
                "prefix8": row["prefix8"],
                "cell_index": row["cell_index"],
                "status": row["status"],
                "metrics_before": row["metrics_before"],
                "metrics_after": row["metrics_after"],
                "metrics_delta": row["metrics_delta"],
                "active_variables_before": row["active_variables_before"],
                "active_variables_after": row["active_variables_after"],
                "active_variables_delta": row["active_variables_delta"],
                "irredundant_clauses_before": row["irredundant_clauses_before"],
                "irredundant_clauses_after": row["irredundant_clauses_after"],
                "irredundant_clauses_delta": row["irredundant_clauses_delta"],
                "redundant_clauses_before": row["redundant_clauses_before"],
                "redundant_clauses_after": row["redundant_clauses_after"],
                "redundant_clauses_delta": row["redundant_clauses_delta"],
            }
        )
    return {
        "mode": value["mode"],
        "order": value["order"],
        "rows": rows,
        "summary": value["summary"],
        "retained_state_continuity_verified": value["retained_state_continuity_verified"],
        "all_watchdogs_clear": value["all_watchdogs_clear"],
    }


def _sanitize_trajectory(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **_scientific_trajectory(value),
        "stdout_sha256": value["stdout_sha256"],
        "stderr_sha256": value["stderr_sha256"],
        "helper_returncode": value["helper_returncode"],
        "volatile_process_elapsed_seconds": value["process_elapsed_seconds"],
    }


def _measurement_rows(challenges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "split": row.get("split"),
            "index": row.get("index"),
            "label": row["label"],
            "known_low20": row.get("known_low20"),
            "target_prefix8": row.get("target_prefix8"),
            "public_challenge_sha256": row.get("public_challenge_sha256"),
            "commitment_sha256": row.get("commitment_sha256"),
            "trajectories": {
                name: _scientific_trajectory(row["trajectories"][name]) for name in OPERATORS
            },
        }
        for row in challenges
    ]


def _verify_final(path: Path, *, schema: str, public_hash: str) -> dict[str, Any]:
    payload = json.loads(path.read_bytes())
    if (
        payload.get("schema") != schema
        or payload.get("attempt_id") != "A218"
        or payload.get("protocol_sha256") != PROTOCOL_SHA256
        or payload.get("public_target_sha256") != public_hash
        or payload.get("complete") is not True
        or payload.get("measurement_sha256")
        != _canonical_sha256(_measurement_rows(payload["challenges"]))
    ):
        raise RuntimeError(f"A218 final trajectory artifact fails gates: {path}")
    return payload


def _run_pair(
    *, trajectory: Any, cnf: Path, key_mapping: list[int], label: str
) -> tuple[dict[str, dict[str, Any]], str]:
    orders = {
        "numeric": trajectory.numeric_order(),
        "reflected_gray8": trajectory.reflected_gray8_order(),
    }

    def run(operator: str) -> dict[str, Any]:
        return trajectory.run_trajectory(
            helper=trajectory.BINARY,
            cnf=cnf,
            mode=f"A218_{label}_{operator}",
            order=orders[operator],
            key_one_literals_bit0_through_bit19=key_mapping,
            conflict_budget=32,
            watchdog_seconds=5.0,
            external_timeout_seconds=600.0,
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {operator: executor.submit(run, operator) for operator in OPERATORS}
            runs = {operator: futures[operator].result() for operator in OPERATORS}
        execution = "concurrent_two_operator_conflict_budgeted"
    except (RuntimeError, subprocess.TimeoutExpired):
        runs = {operator: run(operator) for operator in OPERATORS}
        execution = "sequential_retry_after_concurrent_failure"
    return {operator: _sanitize_trajectory(runs[operator]) for operator in OPERATORS}, execution


def _checkpoint_identity(public_hash: str) -> dict[str, Any]:
    return {
        "schema": "chacha20-round20-trajectory-collection-checkpoint-v1",
        "attempt_id": "A218",
        "protocol_sha256": PROTOCOL_SHA256,
        "public_target_sha256": public_hash,
        "known_challenges": [],
        "target_challenges": [],
    }


def collect(
    *, corpus_output: Path, target_output: Path, checkpoint_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol, public_target = _load_inputs()
    public_hash = _file_sha256(PUBLIC_TARGET)
    if corpus_output.exists() and target_output.exists():
        return (
            _verify_final(
                corpus_output,
                schema="chacha20-round20-knownkey-trajectory-corpus-v1",
                public_hash=public_hash,
            ),
            _verify_final(
                target_output,
                schema="chacha20-round20-target-trajectory-v1",
                public_hash=public_hash,
            ),
        )
    if corpus_output.exists() != target_output.exists():
        raise RuntimeError("partial final A218 trajectory artifacts exist")

    anchors = protocol["anchors"]
    paths = {
        name: ROOT / anchors[key]
        for name, key in (
            ("r20", "R20_runner_path"),
            ("knownkey", "A214_knownkey_helper_path"),
            ("template", "A214_symbolic_template_path"),
            ("trajectory", "trajectory_helper_path"),
            ("native", "native_budgeted_source_path"),
            ("template_protocol", "A214_template_protocol_path"),
        )
    }
    expected = {
        "r20": anchors["R20_runner_sha256"],
        "knownkey": anchors["A214_knownkey_helper_sha256"],
        "template": anchors["A214_symbolic_template_sha256"],
        "trajectory": anchors["trajectory_helper_sha256"],
        "native": anchors["native_budgeted_source_sha256"],
        "template_protocol": anchors["A214_template_protocol_sha256"],
    }
    drift = {
        name: _file_sha256(path)
        for name, path in paths.items()
        if _file_sha256(path) != expected[name]
    }
    if drift:
        raise RuntimeError(f"A218 trajectory collection anchor drift: {drift}")

    r20 = _import_path(paths["r20"], "a218_corpus_r20")
    knownkey = _import_path(paths["knownkey"], "a218_corpus_knownkey")
    template = _import_path(paths["template"], "a218_corpus_template")
    trajectory = _import_path(paths["trajectory"], "a218_corpus_trajectory")
    template_protocol = json.loads(paths["template_protocol"].read_bytes())
    ledger = knownkey.atlas_ledger()
    if knownkey.atlas_ledger_sha256(ledger) != anchors["A214_knownkey_ledger_sha256"]:
        raise RuntimeError("A218 trajectory collection ledger drift")

    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        identity = _checkpoint_identity(public_hash)
        if any(
            checkpoint.get(key) != value
            for key, value in identity.items()
            if key not in {"known_challenges", "target_challenges"}
        ):
            raise RuntimeError("A218 trajectory checkpoint identity differs")
    else:
        checkpoint = _checkpoint_identity(public_hash)

    helper_build = trajectory.compile_helper()
    analysis = r20.analyze()
    original_public = analysis["public_challenge"]
    target_challenge = public_target["public_challenge"]
    fixed_fields = (
        "known_key_word0_upper12",
        "known_key_words_1_through_7",
        "counter_start",
        "nonce_words",
        "block_count",
        "rounds",
        "public_seed_hex",
    )
    if any(target_challenge[field] != original_public[field] for field in fixed_fields):
        raise RuntimeError("A218 public target fixed material differs from atlas")

    with tempfile.TemporaryDirectory(prefix="a218-trajectory-corpus-") as raw_directory:
        directory = Path(raw_directory)
        base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
            r20=r20,
            public_challenge=original_public,
            protocol=template_protocol,
            directory=directory,
        )
        completed = {(row["split"], int(row["index"])) for row in checkpoint["known_challenges"]}
        for ledger_row in ledger:
            identity = (ledger_row["split"], int(ledger_row["index"]))
            if identity in completed:
                print(f"A218 resume {identity[0]} {identity[1]:02d}", flush=True)
                continue
            challenge = knownkey.training_challenge(
                original_public,
                low20=int(ledger_row["low20"]),
                chacha_block=r20.P1._chacha_block,
            )
            raw, _, instantiation = template.instantiate_output(
                base_raw, output_mapping, challenge["target_words"][0]
            )
            label = f"{identity[0]}_{identity[1]:02d}"
            cnf = directory / f"a218_{label}.cnf"
            cnf.write_bytes(raw)
            print(f"A218 collect start {label}", flush=True)
            runs, execution = _run_pair(
                trajectory=trajectory,
                cnf=cnf,
                key_mapping=key_mapping,
                label=label,
            )
            cnf.unlink()
            checkpoint["known_challenges"].append(
                {
                    "split": identity[0],
                    "index": identity[1],
                    "label": label,
                    "derivation_label": ledger_row["derivation_label"],
                    "known_low20": int(ledger_row["low20"]),
                    "known_low20_hex": ledger_row["low20_hex"],
                    "target_prefix8": f"{int(ledger_row['low20']) >> 12:08b}",
                    "instantiation": instantiation,
                    "execution": execution,
                    "trajectories": runs,
                }
            )
            _atomic_json(checkpoint_path, checkpoint, private=True)
            print(f"A218 collect complete {label}", flush=True)

        if not checkpoint["target_challenges"]:
            raw, _, instantiation = template.instantiate_output(
                base_raw, output_mapping, target_challenge["target_words"][0]
            )
            cnf = directory / "a218_prospective_target.cnf"
            cnf.write_bytes(raw)
            print("A218 collect start prospective_target", flush=True)
            runs, execution = _run_pair(
                trajectory=trajectory,
                cnf=cnf,
                key_mapping=key_mapping,
                label="prospective_target",
            )
            checkpoint["target_challenges"].append(
                {
                    "label": "prospective_target",
                    "public_challenge_sha256": public_target["challenge_sha256"],
                    "commitment_sha256": public_target["commitment_sha256"],
                    "instantiation": instantiation,
                    "execution": execution,
                    "trajectories": runs,
                }
            )
            _atomic_json(checkpoint_path, checkpoint, private=True)
            print("A218 collect complete prospective_target", flush=True)

    known_rows = sorted(
        checkpoint["known_challenges"], key=lambda row: (row["split"] != "train", row["index"])
    )
    if (
        len(known_rows) != 24
        or sum(row["split"] == "train" for row in known_rows) != 16
        or sum(row["split"] == "validation" for row in known_rows) != 8
        or len(checkpoint["target_challenges"]) != 1
    ):
        raise RuntimeError("A218 trajectory collection is incomplete")
    common = {
        "attempt_id": "A218",
        "protocol_sha256": PROTOCOL_SHA256,
        "public_target_path": str(PUBLIC_TARGET.relative_to(ROOT)),
        "public_target_sha256": public_hash,
        "public_target_challenge_sha256": public_target["challenge_sha256"],
        "target_commitment_sha256": public_target["commitment_sha256"],
        "anchor_hashes": expected,
        "native_helper_build": helper_build,
        "symbolic_template_manifest": template_manifest,
        "key_mapping_bit0_through_bit19": key_mapping,
        "conflict_budget_per_cell": 32,
        "operator_names": list(OPERATORS),
        "secret_file_or_target_label_read": False,
        "complete": True,
    }
    corpus = {
        "schema": "chacha20-round20-knownkey-trajectory-corpus-v1",
        **common,
        "challenges": known_rows,
    }
    corpus["measurement_sha256"] = _canonical_sha256(_measurement_rows(known_rows))
    target_rows = checkpoint["target_challenges"]
    target = {
        "schema": "chacha20-round20-target-trajectory-v1",
        **common,
        "challenges": target_rows,
    }
    target["measurement_sha256"] = _canonical_sha256(_measurement_rows(target_rows))
    _atomic_json(corpus_output, corpus)
    _atomic_json(target_output, target)
    verified_corpus = _verify_final(
        corpus_output,
        schema="chacha20-round20-knownkey-trajectory-corpus-v1",
        public_hash=public_hash,
    )
    verified_target = _verify_final(
        target_output,
        schema="chacha20-round20-target-trajectory-v1",
        public_hash=public_hash,
    )
    checkpoint_path.unlink(missing_ok=True)
    return verified_corpus, verified_target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-output", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--target-output", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    arguments = parser.parse_args()
    corpus, target = collect(
        corpus_output=arguments.corpus_output,
        target_output=arguments.target_output,
        checkpoint_path=arguments.checkpoint,
    )
    print(
        json.dumps(
            {
                "corpus_output": str(arguments.corpus_output),
                "corpus_sha256": _file_sha256(arguments.corpus_output),
                "corpus_measurement_sha256": corpus["measurement_sha256"],
                "target_output": str(arguments.target_output),
                "target_sha256": _file_sha256(arguments.target_output),
                "target_measurement_sha256": target["measurement_sha256"],
                "secret_file_or_target_label_read": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
