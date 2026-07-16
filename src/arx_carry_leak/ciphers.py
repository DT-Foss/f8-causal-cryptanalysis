"""Deterministic reference implementations used by the F8 experiments."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

StreamGenerator = Callable[[int, int, int], tuple[bytes, int, int]]


@dataclass(frozen=True)
class SpeckVariant:
    name: str
    block_bits: int
    key_bits: int
    word_size: int
    key_words: int
    full_rounds: int
    alpha: int
    beta: int


SPECK_VARIANTS: dict[str, SpeckVariant] = {
    "speck32_64": SpeckVariant("speck32_64", 32, 64, 16, 4, 22, 7, 2),
    "speck48_72": SpeckVariant("speck48_72", 48, 72, 24, 3, 22, 8, 3),
    "speck48_96": SpeckVariant("speck48_96", 48, 96, 24, 4, 23, 8, 3),
    "speck64_96": SpeckVariant("speck64_96", 64, 96, 32, 3, 26, 8, 3),
    "speck64_128": SpeckVariant("speck64_128", 64, 128, 32, 4, 27, 8, 3),
    "speck96_96": SpeckVariant("speck96_96", 96, 96, 48, 2, 28, 8, 3),
    "speck96_144": SpeckVariant("speck96_144", 96, 144, 48, 3, 29, 8, 3),
    "speck128_128": SpeckVariant("speck128_128", 128, 128, 64, 2, 32, 8, 3),
    "speck128_192": SpeckVariant("speck128_192", 128, 192, 64, 3, 33, 8, 3),
    "speck128_256": SpeckVariant("speck128_256", 128, 256, 64, 4, 34, 8, 3),
}


def _rol(value: int, amount: int, width: int) -> int:
    amount %= width
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def _ror(value: int, amount: int, width: int) -> int:
    amount %= width
    mask = (1 << width) - 1
    return ((value >> amount) | (value << (width - amount))) & mask


def speck_round_keys(
    variant: SpeckVariant, master_key: list[int], n_rounds: int
) -> list[int]:
    """Expand a Speck key.

    ``master_key`` follows the Speck paper convention ``[k0, l0, l1, ...]``.
    F8 needs one transition beyond the specified full round, so ``n_rounds`` is
    intentionally not capped at ``variant.full_rounds``.
    """
    if len(master_key) != variant.key_words:
        raise ValueError(f"{variant.name} expects {variant.key_words} key words")
    if n_rounds < 1:
        raise ValueError("n_rounds must be positive")

    mask = (1 << variant.word_size) - 1
    keys = [master_key[0] & mask]
    l_words = [word & mask for word in master_key[1:]]
    for index in range(n_rounds - 1):
        new_l = (
            _ror(l_words[index], variant.alpha, variant.word_size) + keys[index]
        ) & mask
        new_l ^= index
        l_words.append(new_l)
        keys.append(_rol(keys[index], variant.beta, variant.word_size) ^ new_l)
    return keys


def speck_encrypt_block(
    x: int, y: int, round_keys: list[int], variant: SpeckVariant
) -> tuple[int, int]:
    mask = (1 << variant.word_size) - 1
    for round_key in round_keys:
        x = ((_ror(x, variant.alpha, variant.word_size) + y) & mask) ^ round_key
        y = _rol(y, variant.beta, variant.word_size) ^ x
    return x, y


def _random_words(rng: np.random.Generator, count: int, word_size: int) -> list[int]:
    word_bytes = (word_size + 7) // 8
    mask = (1 << word_size) - 1
    return [int.from_bytes(rng.bytes(word_bytes), "little") & mask for _ in range(count)]


def speck_stream(
    n_blocks: int,
    n_rounds: int,
    seed: int,
    variant_name: str = "speck32_64",
) -> tuple[bytes, int, int]:
    """Generate same-key Speck outputs for counter plaintexts."""
    if n_blocks < 1:
        raise ValueError("n_blocks must be positive")
    variant = SPECK_VARIANTS[variant_name]
    rng = np.random.default_rng(seed)
    master_key = _random_words(rng, variant.key_words, variant.word_size)
    round_keys = speck_round_keys(variant, master_key, n_rounds)
    mask = (1 << variant.word_size) - 1
    word_bytes = variant.word_size // 8
    block_bytes = 2 * word_bytes
    output = bytearray(n_blocks * block_bytes)

    for block_index in range(n_blocks):
        x = (block_index >> variant.word_size) & mask
        y = block_index & mask
        x, y = speck_encrypt_block(x, y, round_keys, variant)
        offset = block_index * block_bytes
        output[offset : offset + word_bytes] = x.to_bytes(word_bytes, "big")
        output[offset + word_bytes : offset + block_bytes] = y.to_bytes(word_bytes, "big")
    return bytes(output), block_bytes, word_bytes


_SIMON_Z0 = 0b11111010001001010110000111001101111101000100101011000011100110


def simon32_64_stream(n_blocks: int, n_rounds: int, seed: int) -> tuple[bytes, int, int]:
    """SIMON32/64 negative control: rotation/AND/XOR, no modular addition."""
    if n_blocks < 1 or n_rounds < 1:
        raise ValueError("n_blocks and n_rounds must be positive")
    rng = np.random.default_rng(seed)
    mask = 0xFFFF
    round_keys = _random_words(rng, 4, 16)
    constant = mask ^ 3
    for index in range(4, n_rounds):
        tmp = _ror(round_keys[index - 1], 3, 16) ^ round_keys[index - 3]
        tmp ^= _ror(tmp, 1, 16)
        z_bit = (_SIMON_Z0 >> (61 - ((index - 4) % 62))) & 1
        round_keys.append(round_keys[index - 4] ^ tmp ^ constant ^ z_bit)

    output = bytearray(n_blocks * 4)
    for block_index in range(n_blocks):
        x = (block_index >> 16) & mask
        y = block_index & mask
        for round_key in round_keys[:n_rounds]:
            f = (_rol(x, 1, 16) & _rol(x, 8, 16)) ^ _rol(x, 2, 16)
            x, y = (y ^ f ^ round_key) & mask, x
        offset = block_index * 4
        output[offset : offset + 2] = x.to_bytes(2, "big")
        output[offset + 2 : offset + 4] = y.to_bytes(2, "big")
    return bytes(output), 4, 2


THREEFISH256_ROTATIONS: tuple[tuple[int, int], ...] = (
    (14, 16),
    (52, 57),
    (23, 40),
    (5, 37),
    (25, 33),
    (46, 12),
    (58, 22),
    (32, 32),
)
THREEFISH1024_ROTATIONS: tuple[tuple[int, ...], ...] = (
    (24, 13, 8, 47, 8, 17, 22, 37),
    (38, 19, 10, 55, 49, 18, 23, 52),
    (33, 4, 51, 13, 34, 41, 59, 17),
    (5, 20, 48, 41, 47, 28, 16, 25),
    (41, 9, 37, 31, 12, 47, 44, 30),
    (16, 34, 56, 51, 4, 53, 42, 41),
    (31, 44, 47, 46, 19, 42, 44, 25),
    (9, 48, 35, 52, 23, 31, 37, 20),
)
THREEFISH1024_PERMUTATION: tuple[int, ...] = (
    0,
    9,
    2,
    13,
    6,
    11,
    4,
    15,
    10,
    7,
    12,
    3,
    14,
    5,
    8,
    1,
)
THREEFISH_C240 = 0x1BD11BDAA9FC1A22
MASK64 = (1 << 64) - 1


def threefish256_encrypt(
    plaintext: list[int],
    key: list[int],
    tweak: list[int],
    n_rounds: int = 72,
) -> list[int]:
    """Threefish-256 reference encryption, including configurable extra rounds."""
    if len(plaintext) != 4 or len(key) != 4 or len(tweak) != 2:
        raise ValueError("Threefish-256 expects 4 plaintext/key words and 2 tweak words")
    if n_rounds < 1:
        raise ValueError("n_rounds must be positive")

    key_schedule = [word & MASK64 for word in key]
    parity = THREEFISH_C240
    for word in key_schedule:
        parity ^= word
    key_schedule.append(parity)
    tweak_schedule = [tweak[0] & MASK64, tweak[1] & MASK64]
    tweak_schedule.append(tweak_schedule[0] ^ tweak_schedule[1])

    state = [word & MASK64 for word in plaintext]
    state[0] = (state[0] + key_schedule[0]) & MASK64
    state[1] = (state[1] + key_schedule[1] + tweak_schedule[0]) & MASK64
    state[2] = (state[2] + key_schedule[2] + tweak_schedule[1]) & MASK64
    state[3] = (state[3] + key_schedule[3]) & MASK64

    for round_index in range(n_rounds):
        rotation_a, rotation_b = THREEFISH256_ROTATIONS[round_index % 8]
        state[0] = (state[0] + state[1]) & MASK64
        state[1] = _rol(state[1], rotation_a, 64) ^ state[0]
        state[2] = (state[2] + state[3]) & MASK64
        state[3] = _rol(state[3], rotation_b, 64) ^ state[2]
        state[1], state[3] = state[3], state[1]

        if (round_index + 1) % 4 == 0:
            subkey_index = (round_index + 1) // 4
            state[0] = (state[0] + key_schedule[subkey_index % 5]) & MASK64
            state[1] = (
                state[1]
                + key_schedule[(subkey_index + 1) % 5]
                + tweak_schedule[subkey_index % 3]
            ) & MASK64
            state[2] = (
                state[2]
                + key_schedule[(subkey_index + 2) % 5]
                + tweak_schedule[(subkey_index + 1) % 3]
            ) & MASK64
            state[3] = (
                state[3] + key_schedule[(subkey_index + 3) % 5] + subkey_index
            ) & MASK64
    return state


def threefish1024_encrypt(
    plaintext: list[int],
    key: list[int],
    tweak: list[int],
    n_rounds: int = 80,
) -> list[int]:
    """Threefish-1024 reference encryption with the standard final subkey."""
    if len(plaintext) != 16 or len(key) != 16 or len(tweak) != 2:
        raise ValueError(
            "Threefish-1024 expects 16 plaintext/key words and 2 tweak words"
        )
    if n_rounds < 1 or n_rounds % 4:
        raise ValueError("Threefish-1024 rounds must be a positive multiple of four")

    key_schedule = [word & MASK64 for word in key]
    parity = THREEFISH_C240
    for word in key_schedule:
        parity ^= word
    key_schedule.append(parity)
    tweak_schedule = [tweak[0] & MASK64, tweak[1] & MASK64]
    tweak_schedule.append(tweak_schedule[0] ^ tweak_schedule[1])

    def inject(state: list[int], subkey_index: int) -> list[int]:
        output = [
            (word + key_schedule[(subkey_index + index) % 17]) & MASK64
            for index, word in enumerate(state)
        ]
        output[13] = (
            output[13] + tweak_schedule[subkey_index % 3]
        ) & MASK64
        output[14] = (
            output[14] + tweak_schedule[(subkey_index + 1) % 3]
        ) & MASK64
        output[15] = (output[15] + subkey_index) & MASK64
        return output

    state = inject([word & MASK64 for word in plaintext], 0)
    for round_index in range(n_rounds):
        mixed = [0] * 16
        rotations = THREEFISH1024_ROTATIONS[round_index % 8]
        for pair_index, rotation in enumerate(rotations):
            left_index = 2 * pair_index
            right_index = left_index + 1
            left = (state[left_index] + state[right_index]) & MASK64
            right = _rol(state[right_index], rotation, 64) ^ left
            mixed[left_index] = left
            mixed[right_index] = right
        state = [mixed[index] for index in THREEFISH1024_PERMUTATION]
        if (round_index + 1) % 4 == 0:
            state = inject(state, (round_index + 1) // 4)
    return state


def threefish256_stream(n_blocks: int, n_rounds: int, seed: int) -> tuple[bytes, int, int]:
    if n_blocks < 1:
        raise ValueError("n_blocks must be positive")
    rng = np.random.default_rng(seed)
    key = _random_words(rng, 4, 64)
    tweak = _random_words(rng, 2, 64)
    output = bytearray(n_blocks * 32)
    for block_index in range(n_blocks):
        state = threefish256_encrypt([block_index & MASK64, 0, 0, 0], key, tweak, n_rounds)
        offset = block_index * 32
        for word_index, word in enumerate(state):
            start = offset + word_index * 8
            output[start : start + 8] = word.to_bytes(8, "big")
    return bytes(output), 32, 8


FULL_ROUNDS: dict[str, int] = {
    **{name: variant.full_rounds for name, variant in SPECK_VARIANTS.items()},
    "simon32_64": 32,
    "threefish256": 72,
}


def get_generator(target: str) -> StreamGenerator:
    if target in SPECK_VARIANTS:
        return lambda n, rounds, seed: speck_stream(n, rounds, seed, target)
    if target == "simon32_64":
        return simon32_64_stream
    if target == "threefish256":
        return threefish256_stream
    raise KeyError(f"unknown F8 target: {target}")


def verify_reference_vectors() -> dict[str, bool]:
    speck = SPECK_VARIANTS["speck32_64"]
    round_keys = speck_round_keys(speck, [0x0100, 0x0908, 0x1110, 0x1918], 22)
    speck_result = speck_encrypt_block(0x6574, 0x694C, round_keys, speck)

    zero_result = threefish256_encrypt([0, 0, 0, 0], [0, 0, 0, 0], [0, 0])
    sequential_key = [
        int.from_bytes(bytes(range(1, 33))[offset : offset + 8], "little")
        for offset in range(0, 32, 8)
    ]
    sequential_result = threefish256_encrypt([0, 0, 0, 0], sequential_key, [0, 0])
    threefish1024_zero = threefish1024_encrypt([0] * 16, [0] * 16, [0, 0])

    return {
        "speck32_64": speck_result == (0xA868, 0x42F2),
        "threefish256_zero": zero_result
        == [0x94EEEA8B1F2ADA84, 0xADF103313EAE6670, 0x952419A1F4B16D53, 0xD83F13E63C9F6B11],
        "threefish256_sequential_key": sequential_result
        == [0xE894160E827BB3D4, 0xDE12213BE83D70BA, 0x2B035298135CCAFF, 0xA7DFCAA344FC69F1],
        "threefish1024_zero": threefish1024_zero
        == [
            0x04B3053D0A3D5CF0,
            0x0136E0D1C7DD85F7,
            0x067B212F6EA78A5C,
            0x0DA9C10B4C54E1C6,
            0x0F4EC27394CBACF0,
            0x32437F0568EA4FD5,
            0xCFF56D1D7654B49C,
            0xA2D5FB14369B2E7B,
            0x540306B460472E0B,
            0x71C18254BCEA820D,
            0xC36B4068BEAF32C8,
            0xFA4329597A360095,
            0xC4A36C28434A5B9A,
            0xD54331444B1046CF,
            0xDF11834830B2A460,
            0x1E39E8DFE1F7EE4F,
        ],
    }
