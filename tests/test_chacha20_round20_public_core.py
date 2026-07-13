from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_public_core.py"
SYMBOLIC_SOURCE = ROOT / "research/experiments/chacha20_round20_symbolic_template.py"
PILOT_CONFIG = ROOT / "research/pilots/chacha20_round20_partition_v1/config.json"


def _module():
    spec = importlib.util.spec_from_file_location("a220_public_core_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _module()


def _symbolic_module():
    spec = importlib.util.spec_from_file_location("a220_public_symbolic_test", SYMBOLIC_SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SYMBOLIC = _symbolic_module()


def _public_template() -> dict:
    challenge = json.loads(PILOT_CONFIG.read_bytes())["public_challenge"]
    return {key: value for key, value in challenge.items() if key in MODULE.PUBLIC_TEMPLATE_FIELDS}


def test_public_template_and_known_challenge_exclude_labels_and_historical_artifacts() -> None:
    public = MODULE.validate_public_template(_public_template())
    challenge = MODULE.build_known_challenge(public, low20=0xEDA50)
    assert set(public) == MODULE.PUBLIC_TEMPLATE_FIELDS
    assert not (MODULE.TARGET_FIELDS & set(public))
    assert not (MODULE.SECRET_FIELDS & set(challenge))
    assert challenge["target_block_sha256"] == [
        "e2dc4801124f70820c7d8729fcb916c6aef5fb635be8902bbf6aa8e3895a05f8",
        "1401f660e836c00d886a9dde1396306bfb007249a743ddfc7529794fba727dff",
        "0e0cf16c782ee733f8f9966db010140f9f1a0b3295b2ba468f9e6c5e43ff8194",
        "1ed6be3a9e151bdbb24670eb9a789bc8bdbbd008126ed2e2c87f56bb7429a814",
        "904a8741be3ebb35673bdec753789cdc2ba3c193d3f06a5587b8c12316e7908b",
        "54ad4926643debfb2389a9f6ed97837b6fee9482fd38b89359ad9d1a0ba63f9c",
        "9bae0fecdbcfa5af43e641451c9182dfc4d4592ada761baed47596783bcd90e1",
        "16b3ab03510d0a6219c80c5fb54020cf936c5bdabc93256d5ae4689946ed194d",
    ]
    assert MODULE.provenance()["historical_result_or_causal_loader_present"] is False


def test_public_core_passes_rfc8439_block_vector() -> None:
    key_words = [
        int.from_bytes(bytes(range(offset, offset + 4)), "little") for offset in range(0, 32, 4)
    ]
    words = MODULE.P1._chacha_block(
        key_words=key_words,
        counter=1,
        nonce_words=[0x09000000, 0x4A000000, 0x00000000],
        rounds=20,
    )
    assert MODULE._word_bytes(words).hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_public_template_rejects_target_secret_or_derivation_damage() -> None:
    public = _public_template()
    with_target = {**public, "target_words": []}
    with pytest.raises(RuntimeError, match="field set differs"):
        MODULE.validate_public_template(with_target)
    with_secret = {**public, "low20": 1}
    with pytest.raises(RuntimeError, match="field set differs"):
        MODULE.validate_public_template(with_secret)
    damaged = copy.deepcopy(public)
    damaged["nonce_words"][0] ^= 1
    with pytest.raises(RuntimeError, match="derivation differs"):
        MODULE.validate_public_template(damaged)


def test_source_formula_is_exact_and_target_sensitive_without_analyze_loader() -> None:
    public = _public_template()
    challenge = MODULE.build_known_challenge(public, low20=0xEDA50)
    other = MODULE.build_known_challenge(public, low20=0x12345)
    assert MODULE._source_formula(challenge) != MODULE._source_formula(other)
    formula = SYMBOLIC.symbolic_formula(MODULE, challenge)
    other_formula = SYMBOLIC.symbolic_formula(MODULE, other)
    assert formula == other_formula
    assert hashlib.sha256(formula.encode()).hexdigest() == (
        "1dbf9c0ac93f42189c425006327bfddbe6f9da6dd32e76863cba2fc799a149d6"
    )
    assert len(formula.encode()) == 38851
