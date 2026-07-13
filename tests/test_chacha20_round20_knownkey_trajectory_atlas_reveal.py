from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_knownkey_trajectory_atlas_reveal.py"


def _module():
    spec = importlib.util.spec_from_file_location("a218_reveal_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("validation_p", "target_rank", "expected"),
    [
        (0.05, 1, "FULLROUND_R20_KNOWNKEY_TRAJECTORY_RANK1_TRANSFER_CONFIRMED"),
        (0.01, 16, "FULLROUND_R20_KNOWNKEY_TRAJECTORY_TOP16_TRANSFER_CONFIRMED"),
        (0.01, 64, "FULLROUND_R20_KNOWNKEY_TRAJECTORY_TOP64_TRANSFER_CONFIRMED"),
        (0.01, 65, "FULLROUND_R20_KNOWNKEY_TRAJECTORY_DOMAIN_REDUCTION_RETAINED"),
        (0.2, 1, "FULLROUND_R20_TARGET_RANK1_WITH_VALIDATION_NULL_BOUNDARY"),
        (
            0.01,
            256,
            "FULLROUND_R20_VALIDATION_ASSOCIATION_WITH_TARGET_TRANSFER_BOUNDARY",
        ),
        (0.2, 128, "FULLROUND_R20_TRAJECTORY_REPRESENTATION_BOUNDARY_RETAINED"),
    ],
)
def test_evidence_stage_preserves_joint_and_split_boundaries(
    validation_p: float, target_rank: int, expected: str
) -> None:
    module = _module()
    assert module.evidence_stage(validation_p=validation_p, target_rank=target_rank) == expected


def test_reveal_commitment_matches_commit_generator_domain() -> None:
    reveal = _module()
    commit_source = ROOT / "research/experiments/chacha20_round20_trajectory_target_commit.py"
    spec = importlib.util.spec_from_file_location("a218_commit_cross_test", commit_source)
    assert spec is not None and spec.loader is not None
    commit = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = commit
    spec.loader.exec_module(commit)
    salt = bytes(range(32))
    assert reveal.target_commitment(low20=0x54321, salt=salt) == commit.target_commitment(
        low20=0x54321, salt=salt
    )
