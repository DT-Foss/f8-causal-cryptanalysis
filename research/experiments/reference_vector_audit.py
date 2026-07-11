#!/usr/bin/env python3
"""Cross-check packaged Speck and Threefish implementations against primary KATs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_encrypt_block,
    speck_round_keys,
    threefish256_encrypt,
)
from arx_carry_leak.nano_ciphers import (
    SIMON_PARAMS,
    SPECK_PARAMS,
    _SIMON_Z_SEQ,
    _simon_encrypt,
    _simon_key_schedule,
    _speck_encrypt,
    _speck_key_schedule,
)


SPECK_VECTORS = {
    "speck32_64": ("1918111009080100", "6574694c", "a86842f2"),
    "speck48_72": ("1211100a0908020100", "20796c6c6172", "c049a5385adc"),
    "speck48_96": ("1a19181211100a0908020100", "6d2073696874", "735e10b6445d"),
    "speck64_96": ("131211100b0a090803020100", "74614620736e6165", "9f7952ec4175946c"),
    "speck64_128": (
        "1b1a1918131211100b0a090803020100",
        "3b7265747475432d",
        "8c6fa548454e028b",
    ),
    "speck96_96": (
        "0d0c0b0a0908050403020100",
        "65776f68202c656761737520",
        "9e4d09ab717862bdde8f79aa",
    ),
    "speck96_144": (
        "1514131211100d0c0b0a0908050403020100",
        "656d6974206e69202c726576",
        "2bf31072228a7ae440252ee6",
    ),
    "speck128_128": (
        "0f0e0d0c0b0a09080706050403020100",
        "6c617669757165207469206564616d20",
        "a65d9851797832657860fedf5c570d18",
    ),
    "speck128_192": (
        "17161514131211100f0e0d0c0b0a09080706050403020100",
        "726148206665696843206f7420746e65",
        "1be4cf3a13135566f9bc185de03c1886",
    ),
    "speck128_256": (
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        "65736f6874206e49202e72656e6f6f70",
        "4109010405c0f53e4eeeb48d9c188f43",
    ),
}

SIMON_VECTORS = {
    "simon32_64": ("1918111009080100", "65656877", "c69be9bb"),
    "simon48_72": ("1211100a0908020100", "6120676e696c", "dae5ac292cac"),
    "simon48_96": ("1a19181211100a0908020100", "72696320646e", "6e06a5acf156"),
    "simon64_96": ("131211100b0a090803020100", "6f7220676e696c63", "5ca2e27f111a8fc8"),
    "simon64_128": (
        "1b1a1918131211100b0a090803020100",
        "656b696c20646e75",
        "44c8fc20b9dfa07a",
    ),
    "simon96_96": (
        "0d0c0b0a0908050403020100",
        "2072616c6c69702065687420",
        "602807a462b469063d8ff082",
    ),
    "simon96_144": (
        "1514131211100d0c0b0a0908050403020100",
        "74616874207473756420666f",
        "ecad1c6c451e3f59c5db1ae9",
    ),
    "simon128_128": (
        "0f0e0d0c0b0a09080706050403020100",
        "63736564207372656c6c657661727420",
        "49681b1e1e54fe3f65aa832af84e0bbc",
    ),
    "simon128_192": (
        "17161514131211100f0e0d0c0b0a09080706050403020100",
        "206572656874206e6568772065626972",
        "c4ac61effcdc0d4f6c9c8d6e2597b85b",
    ),
    "simon128_256": (
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        "74206e69206d6f6f6d69732061207369",
        "8d2b5579afc8a3a03bf72a87efe7b868",
    ),
}

SOURCES = {
    "speck": "https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf",
    "simon": "https://eprint.iacr.org/2013/404.pdf",
    "threefish": "https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf",
    "threefish_kat": "Skein 1.3 NIST submission KAT_MCT/skein_golden_kat_short_internals.txt",
}


def _speck_result(name: str, key_hex: str, plaintext_hex: str, expected_hex: str) -> dict:
    variant = SPECK_VARIANTS[name]
    word_bytes = variant.word_size // 8
    key_little_endian = bytes.fromhex(key_hex)[::-1]
    key_words = [
        int.from_bytes(key_little_endian[offset : offset + word_bytes], "little")
        for offset in range(0, len(key_little_endian), word_bytes)
    ]
    plaintext = bytes.fromhex(plaintext_hex)
    x = int.from_bytes(plaintext[:word_bytes], "big")
    y = int.from_bytes(plaintext[word_bytes:], "big")
    round_keys = speck_round_keys(variant, key_words, variant.full_rounds)
    got_x, got_y = speck_encrypt_block(x, y, round_keys, variant)
    actual = got_x.to_bytes(word_bytes, "big") + got_y.to_bytes(word_bytes, "big")
    return {
        "target": name,
        "rounds": variant.full_rounds,
        "expected": expected_hex,
        "actual": actual.hex(),
        "pass": actual.hex() == expected_hex,
    }


def _words_from_key(key_hex: str, word_bytes: int) -> list[int]:
    little_endian = bytes.fromhex(key_hex)[::-1]
    return [
        int.from_bytes(little_endian[offset : offset + word_bytes], "little")
        for offset in range(0, len(little_endian), word_bytes)
    ]


def _nano_speck_result(name: str, key_hex: str, plaintext_hex: str, expected_hex: str) -> dict:
    block_bits, key_bits = (int(part) for part in name.removeprefix("speck").split("_"))
    word_size, m, rounds, alpha, beta = SPECK_PARAMS[(block_bits, key_bits)]
    word_bytes = word_size // 8
    keys = _words_from_key(key_hex, word_bytes)
    x = int(plaintext_hex[: 2 * word_bytes], 16)
    y = int(plaintext_hex[2 * word_bytes :], 16)
    round_keys = _speck_key_schedule(keys, word_size, m, rounds, alpha, beta)
    actual_words = _speck_encrypt(x, y, round_keys, word_size, alpha, beta)
    actual = "".join(f"{word:0{2 * word_bytes}x}" for word in actual_words)
    return {
        "target": f"nano_{name}",
        "rounds": rounds,
        "expected": expected_hex,
        "actual": actual,
        "pass": actual == expected_hex,
    }


def _nano_simon_result(name: str, key_hex: str, plaintext_hex: str, expected_hex: str) -> dict:
    block_bits, key_bits = (int(part) for part in name.removeprefix("simon").split("_"))
    word_size, m, rounds, z_index = SIMON_PARAMS[(block_bits, key_bits)]
    word_bytes = word_size // 8
    keys = _words_from_key(key_hex, word_bytes)
    x = int(plaintext_hex[: 2 * word_bytes], 16)
    y = int(plaintext_hex[2 * word_bytes :], 16)
    round_keys = _simon_key_schedule(keys, word_size, m, rounds, _SIMON_Z_SEQ[z_index])
    actual_words = _simon_encrypt(x, y, round_keys, word_size)
    actual = "".join(f"{word:0{2 * word_bytes}x}" for word in actual_words)
    return {
        "target": f"nano_{name}",
        "rounds": rounds,
        "expected": expected_hex,
        "actual": actual,
        "pass": actual == expected_hex,
    }


def _threefish_results() -> list[dict]:
    cases = [
        {
            "target": "threefish256_zero",
            "plaintext": [0, 0, 0, 0],
            "key": [0, 0, 0, 0],
            "tweak": [0, 0],
            "expected": [
                0x94EEEA8B1F2ADA84,
                0xADF103313EAE6670,
                0x952419A1F4B16D53,
                0xD83F13E63C9F6B11,
            ],
        },
        {
            "target": "threefish256_official_nonzero",
            "plaintext": [
                0xF8F9FAFBFCFDFEFF,
                0xF0F1F2F3F4F5F6F7,
                0xE8E9EAEBECEDEEEF,
                0xE0E1E2E3E4E5E6E7,
            ],
            "key": [
                0x1716151413121110,
                0x1F1E1D1C1B1A1918,
                0x2726252423222120,
                0x2F2E2D2C2B2A2928,
            ],
            "tweak": [0x0706050403020100, 0x0F0E0D0C0B0A0908],
            "expected": [
                0xDF8FEA0EFF91D0E0,
                0xD50AD82EE69281C9,
                0x76F48D58085D869D,
                0xDF975E95B5567065,
            ],
        },
    ]
    results = []
    for case in cases:
        actual = threefish256_encrypt(case["plaintext"], case["key"], case["tweak"], 72)
        results.append(
            {
                "target": case["target"],
                "rounds": 72,
                "expected": [f"{word:016x}" for word in case["expected"]],
                "actual": [f"{word:016x}" for word in actual],
                "pass": actual == case["expected"],
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    results = [
        _speck_result(name, key, plaintext, expected)
        for name, (key, plaintext, expected) in SPECK_VECTORS.items()
    ]
    results.extend(
        _nano_speck_result(name, key, plaintext, expected)
        for name, (key, plaintext, expected) in SPECK_VECTORS.items()
    )
    results.extend(
        _nano_simon_result(name, key, plaintext, expected)
        for name, (key, plaintext, expected) in SIMON_VECTORS.items()
    )
    results.extend(_threefish_results())
    payload = {
        "schema_version": 1,
        "experiment": "primary_reference_vector_audit",
        "sources": SOURCES,
        "passed": sum(result["pass"] for result in results),
        "total": len(results),
        "all_passed": all(result["pass"] for result in results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"reference vectors: {payload['passed']}/{payload['total']} passed")
    print(f"wrote {args.output}")
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
