#!/usr/bin/env python3
"""Freeze A282's four-target cross-material panel before target generation."""

from __future__ import annotations

import argparse
import copy
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from chacha20_round20_multitarget_common import (
    DEFAULT_DOTCAUSAL_SRC,
    ROOT,
    anchor,
    atomic_json,
    canonical_sha256,
    existing_public_seeds,
    file_sha256,
    import_path,
    load_dotcausal,
    path_ref,
    verify_anchors,
)

ATTEMPT_ID = "A282"
PANEL_SIZE = 4
BASE_MASTER = (
    ROOT / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
)
BASE_MASTER_SHA256 = "256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6"
A281_CANONICAL = (
    ROOT
    / "research/results/v1/chacha20_round20_cross_material_composite_recovery_canonical_v1.json"
)
A281_CANONICAL_SHA256 = "989ef033b1380da7c3fc87c4fd8254fa4edcc2527c9bad7a531245822561de27"
A281_CANONICAL_CAUSAL = A281_CANONICAL.with_suffix(".causal")
A281_CANONICAL_CAUSAL_SHA256 = (
    "dffa65f2138cb0f78aa85078650eda5cba3756c09d93b5de48bc4bf618f3f059"
)
A278_PREFLIGHT = Path(__file__).with_name(
    "chacha20_round20_cross_material_composite_master_preflight.py"
)
A280T_PREFLIGHT = Path(__file__).with_name(
    "chacha20_round20_cross_material_symbolic_preflight.py"
)
A280_RUNNER = Path(__file__).with_name("chacha20_round20_cross_material_measure.py")
A281_RUNNER = Path(__file__).with_name(
    "chacha20_round20_cross_material_composite_recovery.py"
)
COMMON = Path(__file__).with_name("chacha20_round20_multitarget_common.py")
TARGET_PREFLIGHT = Path(__file__).with_name(
    "chacha20_round20_multitarget_target_preflight.py"
)
MEASURE_RUNNER = Path(__file__).with_name("chacha20_round20_multitarget_measure.py")
RECOVERY_RUNNER = Path(__file__).with_name("chacha20_round20_multitarget_recovery.py")
RESIDUAL_ADAPTER = Path(__file__).with_name(
    "chacha20_multitarget_residual_two_pass.py"
)
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_multitarget_panel_master_v1.json"
)


def _submaster_path(index: int) -> Path:
    return (
        ROOT
        / f"research/configs/chacha20_round20_multitarget_t{index:02d}_master_v1.json"
    )


def _symbolic_path(index: int) -> Path:
    return (
        ROOT
        / f"research/configs/chacha20_round20_multitarget_t{index:02d}_symbolic_v1.json"
    )


def make_submaster(
    base: dict[str, Any], public_template: dict[str, Any]
) -> dict[str, Any]:
    """Clone only A278's frozen science while replacing its public material."""

    value = copy.deepcopy(base)
    value["cross_material_public_template"] = public_template
    value["cross_material_public_template_sha256"] = canonical_sha256(public_template)
    value["scientific_design_sha256"] = canonical_sha256(
        {
            "cross_material_public_template": public_template,
            "frozen_schedule": value["frozen_schedule"],
            "target_generation_contract": value["target_generation_contract"],
            "information_boundary": value["information_boundary"],
        }
    )
    return value


def _validate_submaster(value: dict[str, Any]) -> None:
    if (
        value.get("schema")
        != "chacha20-round20-cross-material-composite-master-v1"
        or value.get("attempt_id") != "A278"
        or value.get("protocol_state")
        != "frozen_before_cross_material_target_generation_measurement_order_or_solve"
        or value.get("frozen_schedule", {}).get("measurement", {}).get(
            "complete_256_candidate_cover_before_scoring"
        )
        is not True
        or value.get("information_boundary", {}).get(
            "target_measurement_or_solver_execution_started"
        )
        is not False
    ):
        raise RuntimeError("A282 submaster semantic gate failed")
    expected = canonical_sha256(
        {
            "cross_material_public_template": value["cross_material_public_template"],
            "frozen_schedule": value["frozen_schedule"],
            "target_generation_contract": value["target_generation_contract"],
            "information_boundary": value["information_boundary"],
        }
    )
    if (
        expected != value.get("scientific_design_sha256")
        or canonical_sha256(value["cross_material_public_template"])
        != value.get("cross_material_public_template_sha256")
    ):
        raise RuntimeError("A282 submaster scientific identity differs")
    verify_anchors(value["anchors"], context="A282 submaster")


def _downstream_anchors() -> dict[str, dict[str, str]]:
    paths = {
        "A282_preflight": Path(__file__),
        "common": COMMON,
        "A283_target_preflight": TARGET_PREFLIGHT,
        "A284_measure_runner": MEASURE_RUNNER,
        "A285_recovery_runner": RECOVERY_RUNNER,
        "parallel_residual_adapter": RESIDUAL_ADAPTER,
        "A280T_symbolic_preflight": A280T_PREFLIGHT,
        "A280_order_runner": A280_RUNNER,
        "A281_recovery_runner": A281_RUNNER,
    }
    missing = [path for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"A282 downstream source is missing: {missing[0]}")
    return {name: anchor(path) for name, path in paths.items()}


def build_panel(
    *, root_review_acknowledged: bool, dotcausal_src: Path
) -> dict[str, Any]:
    if root_review_acknowledged is not True:
        raise RuntimeError("A282 freeze requires explicit root review acknowledgement")
    fixed = {
        BASE_MASTER: BASE_MASTER_SHA256,
        A281_CANONICAL: A281_CANONICAL_SHA256,
        A281_CANONICAL_CAUSAL: A281_CANONICAL_CAUSAL_SHA256,
    }
    for path, digest in fixed.items():
        if file_sha256(path) != digest:
            raise RuntimeError(f"A282 retained anchor differs: {path.name}")
    base = json.loads(BASE_MASTER.read_bytes())
    _validate_submaster(base)

    _, CausalReader, reader_source = load_dotcausal(dotcausal_src)
    reader = CausalReader(str(A281_CANONICAL_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a281c"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "multi_target_cross_material_replication_or_wider_unknown_domain"
    ):
        raise RuntimeError("A282 authentic A281C Causal gap differs")

    a278 = import_path(A278_PREFLIGHT, "a282_a278_preflight")
    a280t = import_path(A280T_PREFLIGHT, "a282_a280t_preflight")
    used_seeds = existing_public_seeds()
    rows: list[dict[str, Any]] = []
    for index in range(1, PANEL_SIZE + 1):
        target_id = f"t{index:02d}"
        master_path = _submaster_path(index)
        symbolic_path = _symbolic_path(index)
        if symbolic_path.exists() and not master_path.exists():
            raise RuntimeError(f"A282 orphan symbolic preflight exists: {target_id}")
        if master_path.exists():
            submaster = json.loads(master_path.read_bytes())
            _validate_submaster(submaster)
        else:
            seed = None
            for _ in range(4096):
                proposed = secrets.token_bytes(32)
                if proposed.hex() not in used_seeds:
                    seed = proposed
                    break
            if seed is None:
                raise RuntimeError("A282 could not draw a fresh public-material seed")
            public_template = a278._public_template(seed)
            submaster = make_submaster(base, public_template)
            _validate_submaster(submaster)
            atomic_json(master_path, submaster)
        public_seed = submaster["cross_material_public_template"]["public_seed_hex"]
        if public_seed in {row["public_seed_hex"] for row in rows}:
            raise RuntimeError("A282 panel public material is duplicated")
        used_seeds.add(public_seed)
        master_sha256 = file_sha256(master_path)

        if symbolic_path.exists():
            symbolic = json.loads(symbolic_path.read_bytes())
        else:
            symbolic = a280t.build_protocol(
                master_path=master_path,
                expected_master_sha256=master_sha256,
                root_review_acknowledged=True,
            )
            atomic_json(symbolic_path, symbolic)
        symbolic_sha256 = file_sha256(symbolic_path)
        symbolic_config = symbolic.get("symbolic_R20_template", {})
        compile_manifest = symbolic.get("compile_manifest", {})
        if (
            symbolic.get("schema")
            != "chacha20-round20-cross-material-symbolic-template-v1"
            or symbolic.get("attempt_id") != "A280T"
            or symbolic.get("master_protocol", {}).get("sha256") != master_sha256
            or symbolic.get("target_independence", {}).get("A279_protocol_opened")
            is not False
            or compile_manifest.get("mapping_probe_count") != 102
            or compile_manifest.get("all_mapping_probes_exact_unit_deltas") is not True
        ):
            raise RuntimeError(f"A282 symbolic preflight differs: {target_id}")
        rows.append(
            {
                "target_id": target_id,
                "panel_index": index,
                "master_protocol": anchor(master_path, master_sha256),
                "master_scientific_design_sha256": submaster[
                    "scientific_design_sha256"
                ],
                "public_seed_hex": public_seed,
                "public_template_sha256": submaster[
                    "cross_material_public_template_sha256"
                ],
                "symbolic_protocol": anchor(symbolic_path, symbolic_sha256),
                "symbolic_scientific_design_sha256": symbolic[
                    "scientific_design_sha256"
                ],
                "formula_sha256": symbolic_config["formula_sha256"],
                "base_cnf_sha256": symbolic_config["base_sha256"],
                "key_mapping_sha256": compile_manifest["key_mapping_sha256"],
                "output_mapping_sha256": compile_manifest[
                    "output_mapping_sha256"
                ],
                "mapping_probe_count": compile_manifest["mapping_probe_count"],
            }
        )

    downstream = _downstream_anchors()
    panel: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-panel-master-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "four_public_materials_and_symbolic_mappings_frozen_before_any_target_generation"
        ),
        "research_question": (
            "Does the unchanged A272 selected-channel reader plus A278 composite schedule "
            "produce a strict-subset full-round recovery distribution across four fresh, "
            "independently derived public-material targets?"
        ),
        "retained_anchor": {
            "A281_canonical_result": anchor(A281_CANONICAL, A281_CANONICAL_SHA256),
            "A281_canonical_causal": anchor(
                A281_CANONICAL_CAUSAL, A281_CANONICAL_CAUSAL_SHA256
            ),
            "A278_base_master": anchor(BASE_MASTER, BASE_MASTER_SHA256),
        },
        "source_anchors": downstream,
        "panel_size": PANEL_SIZE,
        "panel_rows": rows,
        "frozen_execution_schedule": {
            "phase_order": [
                "A282_public_material_and_symbolic_freeze",
                "A283_all_target_generation_and_label_discard",
                "A284_all_complete_256_cell_measurements_and_order_freezes",
                "A285_all_recovery_protocol_freezes",
                "A285_recovery_execution",
            ],
            "measurement_parallel_workers": 2,
            "recovery_parallel_workers": 2,
            "per_target_solver_schedule": base["frozen_schedule"],
            "cross_target_adaptation_permitted": False,
            "early_recovery_before_all_orders_frozen": False,
        },
        "target_generation_contract": {
            "all_targets_generated_in_one_post_A282_process": True,
            "source": "secrets.randbits_20",
            "reject_prior_and_intra_panel_low20_prefix8_suffix12": True,
            "reject_prior_and_intra_panel_public_challenge_hashes": True,
            "generation_labels_returned_or_serialized": False,
        },
        "information_boundary": {
            "all_four_public_materials_frozen": True,
            "all_four_symbolic_literal_mappings_frozen": True,
            "all_solver_budgets_frozen": True,
            "any_panel_target_generated": False,
            "any_panel_target_label_available": False,
            "any_panel_measurement_started": False,
            "any_panel_recovery_started": False,
            "cross_target_adaptation_permitted": False,
        },
        "authentic_causal_readback": {
            "A281C_gap": gaps[0],
            "reader_source": reader_source,
            "read_personally_by_main_before_panel_freeze": True,
        },
    }
    panel["scientific_design_sha256"] = canonical_sha256(
        {
            "panel_rows": rows,
            "frozen_execution_schedule": panel["frozen_execution_schedule"],
            "target_generation_contract": panel["target_generation_contract"],
            "information_boundary": panel["information_boundary"],
        }
    )
    return panel


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--root-reviewed", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.freeze:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": path_ref(args.output)}))
        return
    if args.output.exists():
        raise FileExistsError(f"A282 panel master already exists: {args.output}")
    panel = build_panel(
        root_review_acknowledged=args.root_reviewed,
        dotcausal_src=args.dotcausal_src,
    )
    atomic_json(args.output, panel)
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "output": path_ref(args.output),
                "protocol_sha256": file_sha256(args.output),
                "scientific_design_sha256": panel["scientific_design_sha256"],
                "panel_size": panel["panel_size"],
                "mapping_probes": sum(
                    row["mapping_probe_count"] for row in panel["panel_rows"]
                ),
                "target_generated": False,
                "measurement_or_recovery_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
