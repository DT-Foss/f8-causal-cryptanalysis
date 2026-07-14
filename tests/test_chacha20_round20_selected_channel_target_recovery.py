from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_selected_channel_target_recovery.py"
)
PUBLIC_CORE = ROOT / "research/experiments/chacha20_round20_public_core.py"
A220_PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a274_decode_model_uses_bit0_through_bit19_order() -> None:
    module = _load(RUNNER, "a274_decode_test")
    bits = [0] * 20
    bits[0] = 1
    bits[7] = 1
    bits[19] = 1
    assert module._decode_model(bits) == (1 | (1 << 7) | (1 << 19))


def test_a274_evidence_stage_preserves_frozen_discovery_band() -> None:
    module = _load(RUNNER, "a274_stage_test")
    assert (
        module._evidence_stage(confirmation=None, attempted=128)
        == "FULLROUND_R20_TARGET_BLIND_TOP128_SELECTED_CHANNEL_RECOVERY_BOUNDARY"
    )
    assert "TOP16" in module._evidence_stage(confirmation={"ok": True}, attempted=12)
    assert "TOP64" in module._evidence_stage(confirmation={"ok": True}, attempted=40)
    assert "TOP128" in module._evidence_stage(confirmation={"ok": True}, attempted=100)


def test_a274_dual_confirmation_checks_all_eight_standard_blocks() -> None:
    import json

    module = _load(RUNNER, "a274_confirmation_test")
    public = _load(PUBLIC_CORE, "a274_public_test")
    template = json.loads(A220_PROTOCOL.read_bytes())["public_only_R20_material"]
    low20 = 0x5A19C
    challenge = public.build_known_challenge(template, low20=low20)
    confirmation = module._confirm(public, challenge, low20)
    assert confirmation["all_blocks_match"] is True
    assert confirmation["all_cross_implementation_blocks_match"] is True
    assert confirmation["output_bits_checked"] == 4096
    assert confirmation["control_first_block_match"] is False
