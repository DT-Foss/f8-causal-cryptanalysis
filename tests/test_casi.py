from arx_carry_leak.casi import run_casi_target
from arx_carry_leak.nano_ciphers import NANO_CIPHER_REGISTRY


def test_nanjing_registry_has_41_ciphers() -> None:
    assert len(NANO_CIPHER_REGISTRY) == 41


def test_casi_adapter_emits_portable_result() -> None:
    result = run_casi_target("simon32_64", samples=100, seeds=1, rounds=2)
    assert result["method"] == "CASI_live-casi_0.9.1"
    assert result["target"] == "simon32_64"
    assert result["samples"] == 100
    assert len(result["per_seed"]) == 1
    assert isinstance(result["casi_mean"], float)
