#!/usr/bin/env python3
"""Apply the test-key-only A427 packaging amendment without changing measurements."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w50_majority_3to1_complete_portfolio_a427.py"
)

OLD_IMPLEMENTATION_SHA256 = "474a212ec1e697692e741905ed5aeffcc0a474e53b77e0934eb1963211f3b6de"
OLD_MODEL_SHA256 = "7eac909d07410d618a4102301af24fd684844844b5d0aec12c5cd743ce289edb"
OLD_RESULT_SHA256 = "f1b46c59875b5ac089827fe67cb10d8f58553e7abd505a32e09ad0706bec6d85"
OLD_TEST_SHA256 = "b0e57406804ebf0f41ff95fe31a3ce9b21efa6a0c9b36e0d5069bb8b5be55f01"
NEW_TEST_SHA256 = "c6f550867679cf8feabd29625d013743cb75a92cefc7ff0420bc5995ba360702"
EXTERNAL_MEASUREMENT_SHA256 = "7a07cfcb9a79da52c1a0bca697c5dcf7198ff242e453582e74253df43227c284"
SCHEDULE_SHA256 = "00f579ee4d9376322b5adeadc6d0c2ecd6ff3dc217375675b9fe317fcf9aaee1"
CAUSAL_SHA256 = "c05aa4fc5158c20000a4c6903e29e2f82753638f221a086dd54f105605b7da64"


def load_runner():
    spec = importlib.util.spec_from_file_location("a427_packaging_amendment", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A427 runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    module = load_runner()
    if module.file_sha256(module.IMPLEMENTATION) != OLD_IMPLEMENTATION_SHA256:
        raise RuntimeError("A427 pre-amendment implementation hash differs")
    if module.file_sha256(module.MODEL) != OLD_MODEL_SHA256:
        raise RuntimeError("A427 pre-amendment model hash differs")
    if module.file_sha256(module.RESULT) != OLD_RESULT_SHA256:
        raise RuntimeError("A427 pre-amendment result hash differs")
    if module.file_sha256(module.TEST) != NEW_TEST_SHA256:
        raise RuntimeError("A427 corrected test hash differs")
    if module.file_sha256(module.CAUSAL) != CAUSAL_SHA256:
        raise RuntimeError("A427 Causal hash differs before packaging amendment")

    implementation = json.loads(module.IMPLEMENTATION.read_bytes())
    model = json.loads(module.MODEL.read_bytes())
    result = json.loads(module.RESULT.read_bytes())
    selection_sha256 = module.canonical_sha256(model["selection_evidence"])
    if (
        implementation["anchors"]["test"]["sha256"] != OLD_TEST_SHA256
        or result["external_measurement_sha256"] != EXTERNAL_MEASUREMENT_SHA256
        or result["schedule_commitment_sha256"] != SCHEDULE_SHA256
        or result["causal"]["sha256"] != CAUSAL_SHA256
    ):
        raise RuntimeError("A427 pre-amendment scientific commitments differ")

    common = {
        "schema": "chacha20-round20-w50-a427-packaging-amendment-v1",
        "reason": "correct test-only scheduler proof keys: complete_cover_cells, duplicate_cells, uncovered_cells",
        "scientific_design_changed": False,
        "reader_or_schedule_changed": False,
        "selection_evidence_changed": False,
        "external_measurement_changed": False,
        "causal_artifact_changed": False,
        "prior_test_sha256": OLD_TEST_SHA256,
        "corrected_test_sha256": NEW_TEST_SHA256,
        "selection_evidence_sha256": selection_sha256,
        "external_measurement_sha256": EXTERNAL_MEASUREMENT_SHA256,
        "schedule_commitment_sha256": SCHEDULE_SHA256,
        "causal_sha256": CAUSAL_SHA256,
    }

    implementation["anchors"]["test"]["sha256"] = NEW_TEST_SHA256
    implementation["packaging_amendment"] = {
        **common,
        "prior_implementation_sha256": OLD_IMPLEMENTATION_SHA256,
    }
    implementation.pop("implementation_commitment_sha256")
    implementation["implementation_commitment_sha256"] = module.canonical_sha256(
        implementation
    )
    module.atomic_json(module.IMPLEMENTATION, implementation)
    new_implementation_sha256 = module.file_sha256(module.IMPLEMENTATION)

    model["implementation_sha256"] = new_implementation_sha256
    model["implementation_commitment_sha256"] = implementation[
        "implementation_commitment_sha256"
    ]
    model["anchors"]["implementation"]["sha256"] = new_implementation_sha256
    model["packaging_amendment"] = {
        **common,
        "prior_implementation_sha256": OLD_IMPLEMENTATION_SHA256,
        "prior_model_sha256": OLD_MODEL_SHA256,
        "amended_implementation_sha256": new_implementation_sha256,
    }
    model.pop("model_commitment_sha256")
    model["model_commitment_sha256"] = module.canonical_sha256(model)
    if module.canonical_sha256(model["selection_evidence"]) != selection_sha256:
        raise RuntimeError("A427 selection evidence changed during packaging amendment")
    module.atomic_json(module.MODEL, model)
    new_model_sha256 = module.file_sha256(module.MODEL)

    result["implementation_sha256"] = new_implementation_sha256
    result["implementation_commitment_sha256"] = implementation[
        "implementation_commitment_sha256"
    ]
    result["model_sha256"] = new_model_sha256
    result["model_commitment_sha256"] = model["model_commitment_sha256"]
    result["anchors"]["implementation"]["sha256"] = new_implementation_sha256
    result["anchors"]["model"]["sha256"] = new_model_sha256
    result["packaging_amendment"] = {
        **common,
        "prior_implementation_sha256": OLD_IMPLEMENTATION_SHA256,
        "prior_model_sha256": OLD_MODEL_SHA256,
        "prior_result_sha256": OLD_RESULT_SHA256,
        "amended_implementation_sha256": new_implementation_sha256,
        "amended_model_sha256": new_model_sha256,
        "causal_scientific_source_model_sha256": OLD_MODEL_SHA256,
    }
    if (
        result["external_measurement_sha256"] != EXTERNAL_MEASUREMENT_SHA256
        or result["schedule_commitment_sha256"] != SCHEDULE_SHA256
        or module.file_sha256(module.CAUSAL) != CAUSAL_SHA256
    ):
        raise RuntimeError("A427 scientific output changed during packaging amendment")
    module.atomic_json(module.RESULT, result)

    print(
        json.dumps(
            {
                "amended_implementation_sha256": new_implementation_sha256,
                "amended_model_sha256": new_model_sha256,
                "amended_result_sha256": module.file_sha256(module.RESULT),
                "selection_evidence_sha256": selection_sha256,
                "external_measurement_sha256": result["external_measurement_sha256"],
                "schedule_commitment_sha256": result["schedule_commitment_sha256"],
                "causal_sha256": module.file_sha256(module.CAUSAL),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
