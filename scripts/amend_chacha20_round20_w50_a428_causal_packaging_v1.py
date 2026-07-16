#!/usr/bin/env python3
"""Amend only A428's Causal-writer packaging anchor after its frozen API fix."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
IMPLEMENTATION = ROOT / "research/configs/chacha20_round20_w50_global_best_rank_wavefront_a428_implementation_v1.json"
RUNNER = ROOT / "research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py"
PRIOR_IMPLEMENTATION_SHA256 = "14ffd78e72c87322051d1a3ff5c9e1419e07c28542166a1e684fbbbade3b8941"
PRIOR_RUNNER_SHA256 = "cc865810f5a724c266b5ff8a88627e756d46f3f49ee7ff7d4ab5c284b03fea1c"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    if file_sha256(IMPLEMENTATION) != PRIOR_IMPLEMENTATION_SHA256:
        raise RuntimeError("A428 prior implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if value["anchors"]["runner"]["sha256"] != PRIOR_RUNNER_SHA256:
        raise RuntimeError("A428 prior runner anchor differs")
    new_runner_sha256 = file_sha256(RUNNER)
    value["anchors"]["runner"]["sha256"] = new_runner_sha256
    value["packaging_amendment"] = {
        "schema": "chacha20-round20-w50-a428-causal-packaging-amendment-v1",
        "reason": "use the authentic dotcausal v1 save and verified CausalReader API",
        "prior_implementation_sha256": PRIOR_IMPLEMENTATION_SHA256,
        "prior_runner_sha256": PRIOR_RUNNER_SHA256,
        "amended_runner_sha256": new_runner_sha256,
        "scientific_design_changed": False,
        "wavefront_algorithm_changed": False,
        "candidate_schedule_measurement_available_before_fix": False,
        "production_schedule_available_before_fix": False,
        "production_candidate_assignments_executed_before_fix": 0,
    }
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    value["implementation_commitment_sha256"] = canonical_sha256(unsigned)
    temporary = IMPLEMENTATION.with_name(f".{IMPLEMENTATION.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, IMPLEMENTATION)
    print(json.dumps({"implementation_sha256": file_sha256(IMPLEMENTATION), "runner_sha256": new_runner_sha256}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
