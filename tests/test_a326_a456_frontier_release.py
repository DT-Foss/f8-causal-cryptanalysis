from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _verifier():
    path = ROOT / "scripts/verify_a326_a456_frontier.py"
    spec = importlib.util.spec_from_file_location("verify_a326_a456_frontier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a326_a456_frontier_release() -> None:
    verifier = _verifier()
    verifier.check_publication_boundary()
    verifier.check_headline_invariants()
    verifier.check_manifest()
