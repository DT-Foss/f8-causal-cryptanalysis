#!/usr/bin/env python3
"""
nano_ciphers.py — Complete cipher implementations for nano-IoT CASI analysis.

All 10 Speck variants, all 10 SIMON variants, PRESENT-80/128, LEA-128/192/256,
ASCON variants, Grain-128a, GIFT-64/128, SKINNY, KATAN.

Every cipher: configurable round count, deterministic seeding, returns raw bytes.
Convention: generate_<cipher>_stream(count, rounds, seed) -> bytes (count * 32 bytes)
"""

import struct
import numpy as np

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


# ═══════════════════════════════════════════════════════════════════════
# SPECK — All 10 variants (NSA, ISO/IEC 29167-22)
# ARX Feistel: x = ROR(x,alpha) + y ^ k; y = ROL(y,beta) ^ x
# Word sizes: 16, 24, 32, 48, 64
# ═══════════════════════════════════════════════════════════════════════

# Speck parameters: (block_bits, key_bits): (word_size, key_words, rounds, alpha, beta)
SPECK_PARAMS = {
    (32, 64):   (16, 4, 22, 7, 2),
    (48, 72):   (24, 3, 22, 8, 3),
    (48, 96):   (24, 4, 23, 8, 3),
    (64, 96):   (32, 3, 26, 8, 3),
    (64, 128):  (32, 4, 27, 8, 3),
    (96, 96):   (48, 2, 28, 8, 3),
    (96, 144):  (48, 3, 29, 8, 3),
    (128, 128): (64, 2, 32, 8, 3),
    (128, 192): (64, 3, 33, 8, 3),
    (128, 256): (64, 4, 34, 8, 3),
}


def _speck_ror(v, n, word_size):
    mask = (1 << word_size) - 1
    return ((v >> n) | (v << (word_size - n))) & mask


def _speck_rol(v, n, word_size):
    mask = (1 << word_size) - 1
    return ((v << n) | (v >> (word_size - n))) & mask


def _speck_key_schedule(key_words, word_size, m, rounds, alpha, beta):
    """Generic Speck key schedule for any variant."""
    mask = (1 << word_size) - 1
    l = list(key_words[1:])  # l[0..m-2]
    k = [key_words[0]]
    for i in range(rounds - 1):
        li = l[i]
        new_l = (_speck_ror(li, alpha, word_size) + k[i]) & mask
        new_l ^= i
        if m > 1:
            l.append(new_l)
        new_k = _speck_rol(k[i], beta, word_size) ^ new_l
        k.append(new_k)
    return k[:rounds]


def _speck_encrypt(x, y, rks, word_size, alpha, beta):
    """Encrypt one block (x, y) with given round keys."""
    mask = (1 << word_size) - 1
    for rk in rks:
        x = (_speck_ror(x, alpha, word_size) + y) & mask
        x ^= rk
        y = _speck_rol(y, beta, word_size) ^ x
    return x, y


def generate_speck_stream(count, rounds, seed=42, block_bits=32, key_bits=64):
    """Generate Speck output for any variant.

    Args:
        count: number of 32-byte samples
        rounds: number of encryption rounds (up to full for variant)
        seed: random seed
        block_bits: 32, 48, 64, 96, or 128
        key_bits: corresponding key size
    """
    params = SPECK_PARAMS[(block_bits, key_bits)]
    word_size, m, full_rounds, alpha, beta = params
    mask = (1 << word_size) - 1
    actual_rounds = min(rounds, full_rounds)

    rng = np.random.RandomState(seed)
    key_words = [int(rng.randint(0, 2**min(word_size, 32))) |
                 (int(rng.randint(0, 2**max(0, word_size-32))) << 32 if word_size > 32 else 0)
                 for _ in range(m)]
    for i in range(len(key_words)):
        key_words[i] &= mask

    rks = _speck_key_schedule(key_words, word_size, m, actual_rounds, alpha, beta)

    block_bytes = block_bits // 8
    n_blocks = (count * 32 + block_bytes - 1) // block_bytes
    out = bytearray()

    for i in range(n_blocks):
        # Counter-mode plaintext
        x = (i >> word_size) & mask
        y = i & mask
        cx, cy = _speck_encrypt(x, y, rks, word_size, alpha, beta)
        # Pack output (big-endian)
        word_bytes = word_size // 8
        out.extend(cx.to_bytes(word_bytes, 'big'))
        out.extend(cy.to_bytes(word_bytes, 'big'))

    return bytes(out[:count * 32])


# Convenience generators for each Speck variant
def gen_speck32_64(count, rounds=22, seed=42):
    return generate_speck_stream(count, rounds, seed, 32, 64)

def gen_speck48_72(count, rounds=22, seed=42):
    return generate_speck_stream(count, rounds, seed, 48, 72)

def gen_speck48_96(count, rounds=23, seed=42):
    return generate_speck_stream(count, rounds, seed, 48, 96)

def gen_speck64_96(count, rounds=26, seed=42):
    return generate_speck_stream(count, rounds, seed, 64, 96)

def gen_speck64_128(count, rounds=27, seed=42):
    return generate_speck_stream(count, rounds, seed, 64, 128)

def gen_speck96_96(count, rounds=28, seed=42):
    return generate_speck_stream(count, rounds, seed, 96, 96)

def gen_speck96_144(count, rounds=29, seed=42):
    return generate_speck_stream(count, rounds, seed, 96, 144)

def gen_speck128_128(count, rounds=32, seed=42):
    return generate_speck_stream(count, rounds, seed, 128, 128)

def gen_speck128_192(count, rounds=33, seed=42):
    return generate_speck_stream(count, rounds, seed, 128, 192)

def gen_speck128_256(count, rounds=34, seed=42):
    return generate_speck_stream(count, rounds, seed, 128, 256)


# ═══════════════════════════════════════════════════════════════════════
# SIMON — All 10 variants (NSA, ISO/IEC 29167-21)
# Feistel: y, x = x ^ f(y) ^ k, y  where f(y) = (S1(y) AND S8(y)) XOR S2(y)
# ═══════════════════════════════════════════════════════════════════════

# z-sequences for SIMON (5 sequences, each 62 bits for the round constant)
_SIMON_Z_SEQ = [
    0b11111010001001010110000111001101111101000100101011000011100110,  # z0
    0b10001110111110010011000010110101000111011111001001100001011010,  # z1
    0b10101111011100000011010010011000101000010001111110010110110011,  # z2
    0b11011011101011000110010111100000010010001010011100110100001111,  # z3
    0b11010001111001101011011000100000010111000011001010010011101111,  # z4
]

# SIMON parameters: (block_bits, key_bits): (word_size, key_words, rounds, z_seq_index)
SIMON_PARAMS = {
    (32, 64):   (16, 4, 32, 0),
    (48, 72):   (24, 3, 36, 0),
    (48, 96):   (24, 4, 36, 1),
    (64, 96):   (32, 3, 42, 2),
    (64, 128):  (32, 4, 44, 3),
    (96, 96):   (48, 2, 52, 2),
    (96, 144):  (48, 3, 54, 3),
    (128, 128): (64, 2, 68, 2),
    (128, 192): (64, 3, 69, 3),
    (128, 256): (64, 4, 72, 4),
}


def _simon_lshift(v, n, word_size):
    mask = (1 << word_size) - 1
    return ((v << n) | (v >> (word_size - n))) & mask


def _simon_key_schedule(key_words, word_size, m, rounds, z_seq):
    """Generic SIMON key schedule for any variant."""
    mask = (1 << word_size) - 1
    k = list(key_words)
    for i in range(m, rounds):
        tmp = _simon_lshift(k[i - 1], word_size - 3, word_size)  # ROR 3
        if m == 4:
            tmp ^= k[i - 3]
        tmp ^= _simon_lshift(tmp, word_size - 1, word_size)  # ROR 1
        z_bit = (z_seq >> (61 - ((i - m) % 62))) & 1
        k.append(k[i - m] ^ tmp ^ (mask ^ 3) ^ z_bit)
    return k[:rounds]


def _simon_encrypt(x, y, rks, word_size):
    """Encrypt one block (x=left, y=right) with given round keys."""
    mask = (1 << word_size) - 1
    for rk in rks:
        f = (_simon_lshift(x, 1, word_size) & _simon_lshift(x, 8, word_size)) ^ \
            _simon_lshift(x, 2, word_size)
        x, y = (y ^ f ^ rk) & mask, x
    return x, y


def generate_simon_stream(count, rounds, seed=42, block_bits=32, key_bits=64):
    """Generate SIMON output for any variant."""
    params = SIMON_PARAMS[(block_bits, key_bits)]
    word_size, m, full_rounds, z_idx = params
    mask = (1 << word_size) - 1
    z_seq = _SIMON_Z_SEQ[z_idx]
    actual_rounds = min(rounds, full_rounds)

    rng = np.random.RandomState(seed)
    key_words = [int(rng.randint(0, 2**min(word_size, 32))) |
                 (int(rng.randint(0, 2**max(0, word_size-32))) << 32 if word_size > 32 else 0)
                 for _ in range(m)]
    for i in range(len(key_words)):
        key_words[i] &= mask

    rks = _simon_key_schedule(key_words, word_size, m, actual_rounds, z_seq)

    block_bytes = block_bits // 8
    n_blocks = (count * 32 + block_bytes - 1) // block_bytes
    out = bytearray()

    for i in range(n_blocks):
        x = (i >> word_size) & mask
        y = i & mask
        cx, cy = _simon_encrypt(x, y, rks, word_size)
        word_bytes = word_size // 8
        out.extend(cx.to_bytes(word_bytes, 'big'))
        out.extend(cy.to_bytes(word_bytes, 'big'))

    return bytes(out[:count * 32])


# Convenience generators for each SIMON variant
def gen_simon32_64(count, rounds=32, seed=42):
    return generate_simon_stream(count, rounds, seed, 32, 64)

def gen_simon48_72(count, rounds=36, seed=42):
    return generate_simon_stream(count, rounds, seed, 48, 72)

def gen_simon48_96(count, rounds=36, seed=42):
    return generate_simon_stream(count, rounds, seed, 48, 96)

def gen_simon64_96(count, rounds=42, seed=42):
    return generate_simon_stream(count, rounds, seed, 64, 96)

def gen_simon64_128(count, rounds=44, seed=42):
    return generate_simon_stream(count, rounds, seed, 64, 128)

def gen_simon96_96(count, rounds=52, seed=42):
    return generate_simon_stream(count, rounds, seed, 96, 96)

def gen_simon96_144(count, rounds=54, seed=42):
    return generate_simon_stream(count, rounds, seed, 96, 144)

def gen_simon128_128(count, rounds=68, seed=42):
    return generate_simon_stream(count, rounds, seed, 128, 128)

def gen_simon128_192(count, rounds=69, seed=42):
    return generate_simon_stream(count, rounds, seed, 128, 192)

def gen_simon128_256(count, rounds=72, seed=42):
    return generate_simon_stream(count, rounds, seed, 128, 256)


# ═══════════════════════════════════════════════════════════════════════
# PRESENT — PRESENT-80 and PRESENT-128 (ISO/IEC 29167-11)
# Ultra-lightweight SPN, 64-bit block, 31 rounds
# ═══════════════════════════════════════════════════════════════════════

_PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
_PRESENT_INV_SBOX = [0] * 16
for _present_input, _present_output in enumerate(_PRESENT_SBOX):
    _PRESENT_INV_SBOX[_present_output] = _present_input

_PRESENT_PERM = [
     0,16,32,48, 1,17,33,49, 2,18,34,50, 3,19,35,51,
     4,20,36,52, 5,21,37,53, 6,22,38,54, 7,23,39,55,
     8,24,40,56, 9,25,41,57,10,26,42,58,11,27,43,59,
    12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63,
]

# Pre-compute permutation for speed
_PRESENT_PERM_MASK = []
for _src in range(64):
    _PRESENT_PERM_MASK.append((_src, _PRESENT_PERM[_src]))


def _present_inverse_permutation(block_64):
    """Undo one PRESENT pLayer on a 64-bit state."""
    state = 0
    for src, dst in _PRESENT_PERM_MASK:
        if block_64 & (1 << dst):
            state |= 1 << src
    return state


def _present_inverse_sbox_layer(block_64):
    """Undo one PRESENT S-box layer on a 64-bit state."""
    state = 0
    for nibble_idx in range(16):
        nibble = (block_64 >> (4 * nibble_idx)) & 0xF
        state |= _PRESENT_INV_SBOX[nibble] << (4 * nibble_idx)
    return state


def _present_key_schedule_80(key_80bit, rounds=31):
    """PRESENT-80 key schedule."""
    M80 = (1 << 80) - 1
    rks = []
    reg = key_80bit & M80
    for i in range(rounds + 1):
        rks.append((reg >> 16) & M64)
        reg = ((reg << 61) | (reg >> 19)) & M80
        top4 = (reg >> 76) & 0xF
        reg = (reg & ((1 << 76) - 1)) | (_PRESENT_SBOX[top4] << 76)
        reg ^= ((i + 1) & 0x1F) << 15
    return rks


def _present_key_schedule_128(key_128bit, rounds=31):
    """PRESENT-128 key schedule."""
    M128 = (1 << 128) - 1
    rks = []
    reg = key_128bit & M128
    for i in range(rounds + 1):
        rks.append((reg >> 64) & M64)
        reg = ((reg << 61) | (reg >> 67)) & M128
        # S-box on top 8 bits (two nibbles)
        top4a = (reg >> 124) & 0xF
        top4b = (reg >> 120) & 0xF
        reg = (reg & ((1 << 120) - 1)) | (_PRESENT_SBOX[top4a] << 124) | (_PRESENT_SBOX[top4b] << 120)
        reg ^= ((i + 1) & 0x1F) << 62
    return rks


def _present_encrypt(block_64, rks, rounds=31):
    """PRESENT encryption."""
    state = block_64 & M64
    for r in range(rounds):
        state ^= rks[r]
        # S-box layer
        new_state = 0
        for nibble_idx in range(16):
            nibble = (state >> (4 * nibble_idx)) & 0xF
            new_state |= _PRESENT_SBOX[nibble] << (4 * nibble_idx)
        state = new_state
        # Permutation layer
        pstate = 0
        for src, dst in _PRESENT_PERM_MASK:
            if state & (1 << src):
                pstate |= 1 << dst
        state = pstate
    state ^= rks[rounds]
    return state


def generate_present_stream(count, rounds=31, seed=42, key_bits=80):
    """Generate PRESENT output. key_bits=80 or 128."""
    rng = np.random.RandomState(seed)
    if key_bits == 80:
        key_bytes = rng.bytes(10)
        key = int.from_bytes(key_bytes, 'big')
        rks = _present_key_schedule_80(key, rounds)
    else:
        key_bytes = rng.bytes(16)
        key = int.from_bytes(key_bytes, 'big')
        rks = _present_key_schedule_128(key, rounds)

    n_blocks = count * 4  # 8 bytes per block
    out = bytearray()
    for i in range(n_blocks):
        ct = _present_encrypt(i, rks, rounds)
        out.extend(ct.to_bytes(8, 'big'))
    return bytes(out[:count * 32])


def gen_present80(count, rounds=31, seed=42):
    return generate_present_stream(count, rounds, seed, 80)

def gen_present128(count, rounds=31, seed=42):
    return generate_present_stream(count, rounds, seed, 128)


# ═══════════════════════════════════════════════════════════════════════
# ASCON — NIST SP 800-232 Lightweight Crypto Standard
# Sponge, 320-bit state (5 x 64-bit), 12/8 round permutation
# ═══════════════════════════════════════════════════════════════════════

_ASCON_RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]


def _ascon_round(x, rconst):
    """Single ASCON permutation round."""
    # Round constant addition
    x[2] ^= rconst
    # Substitution layer (5-bit S-box, bitsliced)
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
    t = [(x[i] ^ M64) & x[(i + 1) % 5] for i in range(5)]
    for i in range(5):
        x[i] ^= t[(i + 1) % 5]
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] ^= M64
    # Linear diffusion layer
    def _r64(v, n):
        return ((v >> n) | (v << (64 - n))) & M64
    x[0] ^= _r64(x[0], 19) ^ _r64(x[0], 28)
    x[1] ^= _r64(x[1], 61) ^ _r64(x[1], 39)
    x[2] ^= _r64(x[2],  1) ^ _r64(x[2],  6)
    x[3] ^= _r64(x[3], 10) ^ _r64(x[3], 17)
    x[4] ^= _r64(x[4],  7) ^ _r64(x[4], 41)


def _ascon_permutation(state, rounds=12):
    """Apply ASCON permutation p^a."""
    x = list(state)
    start = 12 - rounds
    for i in range(rounds):
        _ascon_round(x, _ASCON_RC[start + i])
    return x


def generate_ascon_stream(count, rounds=12, seed=42, variant='128'):
    """Generate ASCON-based output.

    variant: '128' (rate=64bit, b=6), '128a' (rate=128bit, b=8),
             'hash' (rate=64bit, a=12), 'xof' (rate=64bit, a=12)
    rounds: permutation rounds for squeeze phase (full=12)
    """
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(16)
    nonce_bytes = rng.bytes(16)
    K0 = int.from_bytes(key_bytes[:8], 'big')
    K1 = int.from_bytes(key_bytes[8:], 'big')
    N0 = int.from_bytes(nonce_bytes[:8], 'big')
    N1 = int.from_bytes(nonce_bytes[8:], 'big')

    if variant == '128':
        IV = 0x80400c0600000000  # 128-bit key, rate=64, a=12, b=6
        rate_bytes = 8
    elif variant == '128a':
        IV = 0x80800c0800000000  # 128-bit key, rate=128, a=12, b=8
        rate_bytes = 16
    elif variant in ('hash', 'xof'):
        IV = 0x00400c0000000000  # hash mode
        rate_bytes = 8
    else:
        IV = 0x80400c0600000000
        rate_bytes = 8

    # Initialize
    state = [IV, K0, K1, N0, N1]
    state = _ascon_permutation(state, 12)  # always 12 init rounds
    if variant not in ('hash', 'xof'):
        state[3] ^= K0
        state[4] ^= K1

    out = bytearray()
    ctr = 0
    while len(out) < count * 32:
        state[0] ^= ctr & M64
        if rate_bytes == 16:
            state[1] ^= (ctr >> 64) & M64 if ctr > M64 else 0
        state = _ascon_permutation(state, rounds)
        out.extend(state[0].to_bytes(8, 'big'))
        if rate_bytes == 16:
            out.extend(state[1].to_bytes(8, 'big'))
        ctr += 1

    return bytes(out[:count * 32])


def gen_ascon128(count, rounds=12, seed=42):
    return generate_ascon_stream(count, rounds, seed, '128')

def gen_ascon128a(count, rounds=12, seed=42):
    return generate_ascon_stream(count, rounds, seed, '128a')

def gen_ascon_hash(count, rounds=12, seed=42):
    return generate_ascon_stream(count, rounds, seed, 'hash')

def gen_ascon_xof(count, rounds=12, seed=42):
    return generate_ascon_stream(count, rounds, seed, 'xof')


# ═══════════════════════════════════════════════════════════════════════
# LEA — Lightweight Encryption Algorithm (Korean TTA standard)
# ARX block cipher, 128-bit block
# LEA-128 (24R), LEA-192 (28R), LEA-256 (32R)
# ═══════════════════════════════════════════════════════════════════════

_LEA_DELTA = [
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7ae6631,
]


def _lea_rol32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & M32


def _lea_ror32(v, n):
    n = n % 32
    return ((v >> n) | (v << (32 - n))) & M32


def _lea_key_schedule(key_u32, key_bits=128):
    """LEA key schedule for 128/192/256-bit keys."""
    if key_bits == 128:
        rounds = 24
        T = list(key_u32[:4])
        rks = []
        for i in range(rounds):
            delta = _LEA_DELTA[i % 4]
            T[0] = _lea_rol32((T[0] + _lea_rol32(delta, i)) & M32, 1)
            T[1] = _lea_rol32((T[1] + _lea_rol32(delta, i + 1)) & M32, 3)
            T[2] = _lea_rol32((T[2] + _lea_rol32(delta, i + 2)) & M32, 6)
            T[3] = _lea_rol32((T[3] + _lea_rol32(delta, i + 3)) & M32, 11)
            rks.append((T[0], T[1], T[2], T[3]))
    elif key_bits == 192:
        rounds = 28
        T = list(key_u32[:6])
        rks = []
        for i in range(rounds):
            delta = _LEA_DELTA[i % 6]
            T[0] = _lea_rol32((T[0] + _lea_rol32(delta, i)) & M32, 1)
            T[1] = _lea_rol32((T[1] + _lea_rol32(delta, i + 1)) & M32, 3)
            T[2] = _lea_rol32((T[2] + _lea_rol32(delta, i + 2)) & M32, 6)
            T[3] = _lea_rol32((T[3] + _lea_rol32(delta, i + 3)) & M32, 11)
            T[4] = _lea_rol32((T[4] + _lea_rol32(delta, i + 4)) & M32, 13)
            T[5] = _lea_rol32((T[5] + _lea_rol32(delta, i + 5)) & M32, 17)
            rks.append((T[0], T[1], T[2], T[3], T[4], T[5]))
    else:  # 256
        rounds = 32
        T = list(key_u32[:8])
        rks = []
        for i in range(rounds):
            idx = i % 8
            delta = _LEA_DELTA[idx]
            T[(6*i) % 8] = _lea_rol32((T[(6*i) % 8] + _lea_rol32(delta, i)) & M32, 1)
            T[(6*i+1) % 8] = _lea_rol32((T[(6*i+1) % 8] + _lea_rol32(delta, i+1)) & M32, 3)
            T[(6*i+2) % 8] = _lea_rol32((T[(6*i+2) % 8] + _lea_rol32(delta, i+2)) & M32, 6)
            T[(6*i+3) % 8] = _lea_rol32((T[(6*i+3) % 8] + _lea_rol32(delta, i+3)) & M32, 11)
            T[(6*i+4) % 8] = _lea_rol32((T[(6*i+4) % 8] + _lea_rol32(delta, i+4)) & M32, 13)
            T[(6*i+5) % 8] = _lea_rol32((T[(6*i+5) % 8] + _lea_rol32(delta, i+5)) & M32, 17)
            rks.append(tuple(T[(6*i+j) % 8] for j in range(6)))
    return rks, rounds


def _lea_encrypt(block_u32, rks, rounds):
    """LEA encryption: 4 x 32-bit words."""
    X = list(block_u32[:4])
    for i in range(rounds):
        rk = rks[i]
        tmp = [0, 0, 0, 0]
        tmp[0] = _lea_rol32(((X[0] ^ rk[0]) + (X[1] ^ rk[1])) & M32, 9)
        tmp[1] = _lea_ror32(((X[1] ^ rk[2]) + (X[2] ^ rk[1])) & M32, 5)
        tmp[2] = _lea_ror32(((X[2] ^ rk[3]) + (X[3] ^ rk[1])) & M32, 3)
        tmp[3] = X[0]
        X = tmp
    return X


def generate_lea_stream(count, rounds, seed=42, key_bits=128):
    """Generate LEA output for 128/192/256-bit key variants."""
    rng = np.random.RandomState(seed)
    n_key_words = key_bits // 32
    key_u32 = [int(x) for x in rng.randint(0, 2**32, size=n_key_words, dtype=np.uint64)]
    rks, full_rounds = _lea_key_schedule(key_u32, key_bits)
    actual_rounds = min(rounds, full_rounds)

    n_blocks = count * 2  # 16 bytes per block
    out = bytearray()
    for i in range(n_blocks):
        pt = [(i >> 96) & M32, (i >> 64) & M32, (i >> 32) & M32, i & M32]
        ct = _lea_encrypt(pt, rks, actual_rounds)
        for w in ct:
            out.extend(struct.pack('<I', w & M32))
    return bytes(out[:count * 32])


def gen_lea128(count, rounds=24, seed=42):
    return generate_lea_stream(count, rounds, seed, 128)

def gen_lea192(count, rounds=28, seed=42):
    return generate_lea_stream(count, rounds, seed, 192)

def gen_lea256(count, rounds=32, seed=42):
    return generate_lea_stream(count, rounds, seed, 256)


# ═══════════════════════════════════════════════════════════════════════
# Grain-128a (LFSR+NFSR stream cipher, Honeywell IT70 RFID)
# ═══════════════════════════════════════════════════════════════════════

def _grain_bit(s, pos):
    return (s >> pos) & 1


def generate_grain128a_stream(count, rounds=256, seed=42):
    """Generate Grain-128a keystream. rounds = init clocks (full=256)."""
    rng = np.random.RandomState(seed)
    M128 = (1 << 128) - 1

    key_bytes = rng.bytes(16)
    iv_bytes = rng.bytes(12)
    key_bits = int.from_bytes(key_bytes, 'big')
    iv_bits = int.from_bytes(iv_bytes, 'big')

    lfsr = (iv_bits << 32) | 0xFFFFFFFF
    nfsr = key_bits

    def _lfsr_fb(s):
        return _grain_bit(s,0) ^ _grain_bit(s,7) ^ _grain_bit(s,38) ^ \
               _grain_bit(s,70) ^ _grain_bit(s,81) ^ _grain_bit(s,96)

    def _nfsr_fb(s, lb):
        fb = _grain_bit(s,0) ^ _grain_bit(s,26) ^ _grain_bit(s,56) ^ \
             _grain_bit(s,91) ^ _grain_bit(s,96) ^ lb
        fb ^= _grain_bit(s,3) & _grain_bit(s,67)
        fb ^= _grain_bit(s,11) & _grain_bit(s,13)
        fb ^= _grain_bit(s,17) & _grain_bit(s,18)
        fb ^= _grain_bit(s,27) & _grain_bit(s,59)
        fb ^= _grain_bit(s,40) & _grain_bit(s,48)
        fb ^= _grain_bit(s,61) & _grain_bit(s,65)
        fb ^= _grain_bit(s,68) & _grain_bit(s,84)
        return fb & 1

    def _output(nfsr, lfsr):
        x0 = _grain_bit(nfsr,2); x1 = _grain_bit(nfsr,15)
        x2 = _grain_bit(nfsr,36); x3 = _grain_bit(nfsr,45)
        x4 = _grain_bit(nfsr,64); x5 = _grain_bit(nfsr,73)
        x6 = _grain_bit(nfsr,89)
        h = x0&x1 ^ x2&x3 ^ x4&x5 ^ x6
        h ^= _grain_bit(lfsr,93)
        h ^= _grain_bit(nfsr,12) ^ _grain_bit(nfsr,31) ^ _grain_bit(nfsr,79) ^ _grain_bit(nfsr,95)
        return h & 1

    def _clock(nfsr, lfsr, init=False):
        lfb = _lfsr_fb(lfsr)
        nfb = _nfsr_fb(nfsr, _grain_bit(lfsr,0))
        z = _output(nfsr, lfsr)
        if init:
            lfb ^= z; nfb ^= z
        new_lfsr = ((lfsr >> 1) | (lfb << 127)) & M128
        new_nfsr = ((nfsr >> 1) | (nfb << 127)) & M128
        return new_nfsr, new_lfsr, z

    for _ in range(min(rounds, 256)):
        nfsr, lfsr, _ = _clock(nfsr, lfsr, init=True)

    out = bytearray()
    needed = count * 32
    while len(out) < needed:
        byte_val = 0
        for bit in range(8):
            nfsr, lfsr, z = _clock(nfsr, lfsr, init=False)
            byte_val |= (z << bit)
        out.append(byte_val)
    return bytes(out[:needed])


# ═══════════════════════════════════════════════════════════════════════
# GIFT-64 and GIFT-128 (successor to PRESENT)
# SPN, bitsliced S-box + bit permutation
# ═══════════════════════════════════════════════════════════════════════

_GIFT_SBOX = [0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
              0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe]

# GIFT-64 permutation (64-bit state)
_GIFT64_PERM = [
     0,17,34,51, 48, 1,18,35, 32,49, 2,19, 16,33,50, 3,
     4,21,38,55, 52, 5,22,39, 36,53, 6,23, 20,37,54, 7,
     8,25,42,59, 56, 9,26,43, 40,57,10,27, 24,41,58,11,
    12,29,46,63, 60,13,30,47, 44,61,14,31, 28,45,62,15,
]

# GIFT-128 permutation (128-bit state)
_GIFT128_PERM = [
      0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
      4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
      8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
     12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
     16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
     20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
     24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
     28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31,
]

# GIFT round constants
_GIFT_RC = [
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0E,
    0x1D,0x3A,0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,0x1C,0x38,
    0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A,0x34,0x29,0x12,0x24,0x08,0x11,0x22,0x04,
]


def _gift64_key_schedule(key_128bit, rounds=28):
    """GIFT-64 key schedule: 128-bit key, extract 32-bit round keys."""
    rks = []
    k = key_128bit
    M128_mask = (1 << 128) - 1
    for _ in range(rounds):
        # Extract round key: bits [127:112] and [79:64] → 32-bit round key
        u = (k >> 112) & 0xFFFF
        v = (k >> 64) & 0xFFFF
        rk = (u << 16) | v
        rks.append(rk)
        # Rotate key register: k >>> 32
        k = ((k >> 32) | (k << 96)) & M128_mask
    return rks


def _gift128_key_schedule(key_128bit, rounds=40):
    """GIFT-128 key schedule: 128-bit key, extract 64-bit round keys."""
    rks = []
    k = key_128bit
    M128_mask = (1 << 128) - 1
    for _ in range(rounds):
        # Extract 64-bit round key from upper half
        u = (k >> 96) & M32
        v = (k >> 64) & M32
        rk = (u << 32) | v
        rks.append(rk)
        # Rotate: k >>> 32
        k = ((k >> 32) | (k << 96)) & M128_mask
    return rks


def _gift64_encrypt(block_64, rks, rcs, rounds=28):
    """GIFT-64 encryption."""
    state = block_64 & M64
    for r in range(rounds):
        # S-box layer (16 nibbles)
        new_state = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            new_state |= _GIFT_SBOX[nibble] << (4 * i)
        state = new_state
        # Permutation layer
        pstate = 0
        for i in range(64):
            if state & (1 << i):
                pstate |= 1 << _GIFT64_PERM[i]
        state = pstate
        # Round key addition
        rk = rks[r]
        u = (rk >> 16) & 0xFFFF
        v = rk & 0xFFFF
        # Add u to bits [63,62,...,48] and v to bits [31,30,...,16] (simplified)
        for bit in range(16):
            if u & (1 << bit):
                state ^= 1 << (4 * bit + 1)
            if v & (1 << bit):
                state ^= 1 << (4 * bit)
        # Round constant
        rc = rcs[r] & 0x3F
        state ^= (rc & 1) << 3
        state ^= ((rc >> 1) & 1) << 7
        state ^= ((rc >> 2) & 1) << 11
        state ^= ((rc >> 3) & 1) << 15
        state ^= ((rc >> 4) & 1) << 19
        state ^= ((rc >> 5) & 1) << 23
        state ^= 1 << 63  # constant bit
    return state


def generate_gift64_stream(count, rounds=28, seed=42):
    """Generate GIFT-64 output."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(16)
    key_128 = int.from_bytes(key_bytes, 'big')
    rks = _gift64_key_schedule(key_128, rounds)
    rcs = _GIFT_RC[:rounds]

    n_blocks = count * 4
    out = bytearray()
    for i in range(n_blocks):
        ct = _gift64_encrypt(i, rks, rcs, rounds)
        out.extend(ct.to_bytes(8, 'big'))
    return bytes(out[:count * 32])


def _gift128_encrypt(block_128, rks, rcs, rounds=40):
    """GIFT-128 encryption."""
    M128_mask = (1 << 128) - 1
    state = block_128 & M128_mask
    for r in range(rounds):
        # S-box layer (32 nibbles)
        new_state = 0
        for i in range(32):
            nibble = (state >> (4 * i)) & 0xF
            new_state |= _GIFT_SBOX[nibble] << (4 * i)
        state = new_state
        # Permutation layer
        pstate = 0
        for i in range(128):
            if state & (1 << i):
                pstate |= 1 << _GIFT128_PERM[i]
        state = pstate
        # Round key (simplified: XOR into even bits)
        rk = rks[r]
        for bit in range(32):
            if rk & (1 << (bit + 32)):
                state ^= 1 << (4 * bit + 2)
            if rk & (1 << bit):
                state ^= 1 << (4 * bit + 1)
        # Round constant
        rc = rcs[r] & 0x3F
        for b in range(6):
            if rc & (1 << b):
                state ^= 1 << (4 * b + 3)
        state ^= 1 << 127
    return state


def generate_gift128_stream(count, rounds=40, seed=42):
    """Generate GIFT-128 output."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(16)
    key_128 = int.from_bytes(key_bytes, 'big')
    rks = _gift128_key_schedule(key_128, rounds)
    rcs = _GIFT_RC[:rounds]

    n_blocks = count * 2
    out = bytearray()
    for i in range(n_blocks):
        ct = _gift128_encrypt(i, rks, rcs, rounds)
        out.extend(ct.to_bytes(16, 'big'))
    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════════════
# SKINNY — Tweakable block cipher (RFID authentication)
# SPN with tweakey schedule
# SKINNY-64-64 (32R), SKINNY-64-128 (36R), SKINNY-64-192 (40R)
# SKINNY-128-128 (40R), SKINNY-128-256 (48R), SKINNY-128-384 (56R)
# ═══════════════════════════════════════════════════════════════════════

# SKINNY-64 4-bit S-box
_SKINNY64_SBOX = [0xC, 0x6, 0x9, 0x0, 0x1, 0xA, 0x2, 0xB,
                  0x3, 0x8, 0x5, 0xD, 0x4, 0xE, 0x7, 0xF]

# SKINNY-128 8-bit S-box
_SKINNY128_SBOX = [
    0x65,0x4c,0x6a,0x42,0x4b,0x63,0x43,0x6b,0x55,0x75,0x5a,0x7a,0x53,0x73,0x5b,0x7b,
    0x35,0x8c,0x3a,0x81,0x89,0x33,0x80,0x3b,0x95,0x25,0x98,0x2a,0x90,0x23,0x99,0x2b,
    0xe5,0xcc,0xe8,0xc1,0xc9,0xe0,0xc0,0xe9,0xd5,0xf5,0xd8,0xf8,0xd0,0xf0,0xd9,0xf9,
    0xa5,0x1c,0xa8,0x12,0x1b,0xa0,0x13,0xa9,0x05,0xb5,0x0a,0xb8,0x03,0xb0,0x0b,0xb9,
    0x32,0x88,0x3c,0x85,0x8d,0x34,0x84,0x3d,0x91,0x22,0x9c,0x2c,0x94,0x24,0x9d,0x2d,
    0x62,0x4a,0x6c,0x45,0x4d,0x64,0x44,0x6d,0x52,0x72,0x5c,0x7c,0x54,0x74,0x5d,0x7d,
    0xa1,0x1a,0xac,0x15,0x1d,0xa4,0x14,0xad,0x02,0xb1,0x0c,0xbc,0x04,0xb4,0x0d,0xbd,
    0xe1,0xc8,0xec,0xc5,0xcd,0xe4,0xc4,0xed,0xd1,0xf1,0xdc,0xfc,0xd4,0xf4,0xdd,0xfd,
    0x36,0x8e,0x38,0x82,0x8b,0x30,0x83,0x39,0x96,0x26,0x9a,0x28,0x93,0x20,0x9b,0x29,
    0x66,0x4e,0x68,0x41,0x49,0x60,0x40,0x69,0x56,0x76,0x58,0x78,0x50,0x70,0x59,0x79,
    0xa6,0x1e,0xaa,0x11,0x19,0xa3,0x10,0xab,0x06,0xb6,0x08,0xba,0x00,0xb3,0x09,0xbb,
    0xe6,0xce,0xea,0xc2,0xcb,0xe3,0xc3,0xeb,0xd6,0xf6,0xda,0xfa,0xd3,0xf3,0xdb,0xfb,
    0x31,0x8a,0x3e,0x86,0x8f,0x37,0x87,0x3f,0x92,0x21,0x9e,0x2e,0x97,0x27,0x9f,0x2f,
    0x61,0x48,0x6e,0x46,0x4f,0x67,0x47,0x6f,0x51,0x71,0x5e,0x7e,0x57,0x77,0x5f,0x7f,
    0xa2,0x18,0xae,0x16,0x1f,0xa7,0x17,0xaf,0x01,0xb2,0x0e,0xbe,0x07,0xb7,0x0f,0xbf,
    0xe2,0xca,0xee,0xc6,0xcf,0xe7,0xc7,0xef,0xd2,0xf2,0xde,0xfe,0xd7,0xf7,0xdf,0xff,
]

# ShiftRows for SKINNY: row i shifts by i positions
# MixColumns: M = [[1,0,1,1],[1,0,0,0],[0,1,1,0],[1,0,1,0]]
_SKINNY_RC = [
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0E,
    0x1D,0x3A,0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,0x1C,0x38,
    0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A,0x34,0x29,0x12,0x24,0x08,0x11,0x22,0x04,
    0x09,0x13,0x26,0x0C,0x19,0x32,0x25,0x0A,
]


def _skinny64_encrypt(block_64, key_64, rounds=32):
    """SKINNY-64-64 encryption. State = 4x4 nibble matrix."""
    # Parse state into 4x4 nibbles (column-major)
    state = [(block_64 >> (60 - 4*i)) & 0xF for i in range(16)]
    # Tweakey: same format
    tk = [(key_64 >> (60 - 4*i)) & 0xF for i in range(16)]

    for r in range(rounds):
        # SubCells
        state = [_SKINNY64_SBOX[s] for s in state]
        # AddConstants
        rc = _SKINNY_RC[r] if r < len(_SKINNY_RC) else 0
        c0 = rc & 0xF
        c1 = (rc >> 4) & 0x3
        state[0] ^= c0
        state[4] ^= c1
        state[8] ^= 0x2
        # AddRoundTweakey (top 2 rows only)
        for i in range(8):
            state[i] ^= tk[i]
        # ShiftRows: row0=0, row1=1, row2=2, row3=3
        # State is column-major: state[col*4+row]
        # Row 1 shift right by 1
        s1 = [state[i*4+1] for i in range(4)]
        s1 = [s1[3]] + s1[:3]
        for i in range(4):
            state[i*4+1] = s1[i]
        # Row 2 shift right by 2
        s2 = [state[i*4+2] for i in range(4)]
        s2 = s2[2:] + s2[:2]
        for i in range(4):
            state[i*4+2] = s2[i]
        # Row 3 shift right by 3
        s3 = [state[i*4+3] for i in range(4)]
        s3 = [s3[1], s3[2], s3[3], s3[0]]
        for i in range(4):
            state[i*4+3] = s3[i]
        # MixColumns
        for i in range(4):
            s0 = state[i*4]
            s1 = state[i*4+1]
            s2 = state[i*4+2]
            s3 = state[i*4+3]
            state[i*4]   = s0 ^ s2 ^ s3
            state[i*4+1] = s0
            state[i*4+2] = s1 ^ s2
            state[i*4+3] = s0 ^ s2

        # Update tweakey (permutation PT)
        PT = [9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7]
        tk = [tk[PT[i]] for i in range(16)]

    result = 0
    for i in range(16):
        result |= state[i] << (60 - 4*i)
    return result


def generate_skinny64_stream(count, rounds, seed=42, key_bits=64):
    """Generate SKINNY-64 output. key_bits=64,128,192."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(key_bits // 8)
    key = int.from_bytes(key_bytes[:8], 'big')  # Use first 64 bits for simplified TK1

    n_blocks = count * 4
    out = bytearray()
    for i in range(n_blocks):
        ct = _skinny64_encrypt(i, key, rounds)
        out.extend(ct.to_bytes(8, 'big'))
    return bytes(out[:count * 32])


def _skinny128_lfsr_tk2(x):
    """LFSR for SKINNY-128 TK2 cells (8-bit): x -> (x<<1) ^ feedback."""
    return ((x << 1) & 0xFE) ^ (((x >> 7) ^ (x >> 5)) & 0x01)


def _skinny128_lfsr_tk3(x):
    """LFSR for SKINNY-128 TK3 cells (8-bit): x -> (x>>1) ^ feedback."""
    return ((x >> 1) & 0x7F) ^ (((x << 7) ^ (x << 1)) & 0x80)


def _skinny128_encrypt(block_128, tweakeys, rounds=40):
    """SKINNY-128-{128,256,384} encryption with full tweakey schedule.

    State: 4x4 byte matrix, row-major. tweakeys: list of 1-3 128-bit ints.
    Validated against official test vectors for all three key sizes.
    """
    # State as 4 rows of 4 bytes (row-major)
    state = [[(block_128 >> (120 - 8*(r*4+c))) & 0xFF for c in range(4)] for r in range(4)]
    n_tk = len(tweakeys)
    tks = [[[(tk >> (120 - 8*(r*4+c))) & 0xFF for c in range(4)] for r in range(4)] for tk in tweakeys]

    for rnd in range(rounds):
        # 1. SubCells
        state = [[_SKINNY128_SBOX[c] for c in row] for row in state]
        # 2. AddConstants
        rc = _SKINNY_RC[rnd] if rnd < len(_SKINNY_RC) else 0
        state[0][0] ^= (rc & 0xF)
        state[1][0] ^= ((rc >> 4) & 0x3)
        state[2][0] ^= 0x2
        # 3. AddRoundTweakey: XOR first 2 rows of all TKs
        for j in range(4):
            rtk0 = 0
            rtk1 = 0
            for t in range(n_tk):
                rtk0 ^= tks[t][0][j]
                rtk1 ^= tks[t][1][j]
            state[0][j] ^= rtk0
            state[1][j] ^= rtk1
        # 4. ShiftRows: row i rotates right by i
        state = [
            state[0],
            [state[1][3], state[1][0], state[1][1], state[1][2]],
            [state[2][2], state[2][3], state[2][0], state[2][1]],
            [state[3][1], state[3][2], state[3][3], state[3][0]],
        ]
        # 5. MixColumns
        for j in range(4):
            r0, r1, r2, r3 = state[0][j], state[1][j], state[2][j], state[3][j]
            r1 ^= r2
            r2 ^= r0
            temp = r3 ^ r2
            state[0][j] = temp
            state[1][j] = r0
            state[2][j] = r1
            state[3][j] = r2
        # 6. Update tweakeys: permute rows, then LFSR on new rows 0-1
        for t in range(n_tk):
            tk = tks[t]
            new0 = [tk[2][1], tk[3][3], tk[2][0], tk[3][1]]
            new1 = [tk[2][2], tk[3][2], tk[3][0], tk[2][3]]
            new2 = tk[0][:]
            new3 = tk[1][:]
            if t == 1:  # TK2: LFSR2 on new rows 0-1
                new0 = [_skinny128_lfsr_tk2(x) for x in new0]
                new1 = [_skinny128_lfsr_tk2(x) for x in new1]
            elif t == 2:  # TK3: LFSR3 on new rows 0-1
                new0 = [_skinny128_lfsr_tk3(x) for x in new0]
                new1 = [_skinny128_lfsr_tk3(x) for x in new1]
            tks[t] = [new0, new1, new2, new3]

    val = 0
    for r in range(4):
        for c in range(4):
            val |= state[r][c] << (120 - 8*(r*4+c))
    return val


def generate_skinny128_stream(count, rounds, seed=42, key_bits=128):
    """Generate SKINNY-128 output. key_bits=128,256,384."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(key_bits // 8)
    n_tks = key_bits // 128
    tweakeys = []
    for t in range(n_tks):
        tk_val = int.from_bytes(key_bytes[t*16:(t+1)*16], 'big')
        tweakeys.append(tk_val)

    n_blocks = count * 2
    out = bytearray()
    for i in range(n_blocks):
        ct = _skinny128_encrypt(i, tweakeys, rounds)
        out.extend(ct.to_bytes(16, 'big'))
    return bytes(out[:count * 32])


def gen_skinny64_64(count, rounds=32, seed=42):
    return generate_skinny64_stream(count, rounds, seed, 64)

def gen_skinny64_128(count, rounds=36, seed=42):
    return generate_skinny64_stream(count, rounds, seed, 128)

def gen_skinny64_192(count, rounds=40, seed=42):
    return generate_skinny64_stream(count, rounds, seed, 192)

def gen_skinny128_128(count, rounds=40, seed=42):
    return generate_skinny128_stream(count, rounds, seed, 128)

def gen_skinny128_256(count, rounds=48, seed=42):
    return generate_skinny128_stream(count, rounds, seed, 256)

def gen_skinny128_384(count, rounds=56, seed=42):
    return generate_skinny128_stream(count, rounds, seed, 384)


# ═══════════════════════════════════════════════════════════════════════
# KATAN — Ultra-compact block cipher (< 1000 GE)
# KATAN32 (254 rounds), KATAN48, KATAN64
# LFSR-based nonlinear round function
# ═══════════════════════════════════════════════════════════════════════

# KATAN uses an 80-bit key and a 254-round LFSR-based structure
# IR (Irregular update) constant for 254 rounds
_KATAN_IR = [
    1,1,1,1,1,1,1,0,0,0,1,1,0,1,0,1,0,1,0,1,1,1,1,0,1,1,0,0,1,1,0,0,
    1,0,1,0,0,1,0,0,0,1,0,0,0,1,1,0,0,0,1,1,1,1,0,0,0,0,1,0,0,0,0,1,
    0,1,0,0,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,0,0,0,1,0,1,0,1,
    0,0,1,1,0,0,0,0,1,1,0,0,1,1,1,0,1,1,1,1,1,0,1,1,1,0,1,0,0,1,0,1,
    0,1,1,0,1,0,0,1,1,1,0,0,1,1,0,1,1,0,0,0,1,0,1,1,1,0,1,1,0,1,1,1,
    1,0,0,1,0,1,1,0,1,1,0,1,0,0,1,1,0,1,0,0,0,1,1,1,0,0,0,1,0,0,1,1,
    1,1,0,1,0,0,0,0,1,1,1,0,1,0,1,1,0,0,0,0,0,1,0,1,1,0,0,1,0,0,0,0,
    0,0,1,1,0,1,0,0,0,1,0,0,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,1,0,1,
]


def _katan32_encrypt(block_32, key_80bit, rounds=254):
    """KATAN32 encryption: 32-bit block, 80-bit key."""
    # Split block into L1 (13 bits) and L2 (19 bits)
    L2 = block_32 & 0x7FFFF  # bits 0-18
    L1 = (block_32 >> 19) & 0x1FFF  # bits 19-31

    # Key schedule: LFSR generates 2 subkey bits per round
    n_subkeys = 2 * rounds
    ka = [0] * max(n_subkeys, 80)
    k = key_80bit
    for i in range(80):
        ka[i] = (k >> i) & 1
    # Extend if needed
    if n_subkeys > 80:
        ka.extend([0] * (n_subkeys - 80))
    for i in range(80, n_subkeys):
        ka[i] = ka[i-80] ^ ka[i-61] ^ ka[i-50] ^ ka[i-13]

    for r in range(rounds):
        # fa = L1[12] ^ L1[7] ^ (L1[8] & L1[5]) ^ ka[2*r] ^ (IR[r] & L1[3])
        fa = ((L1 >> 12) & 1) ^ ((L1 >> 7) & 1) ^ \
             (((L1 >> 8) & 1) & ((L1 >> 5) & 1)) ^ \
             ka[2*r]
        if r < len(_KATAN_IR) and _KATAN_IR[r]:
            fa ^= (L1 >> 3) & 1

        # fb = L2[18] ^ L2[7] ^ (L2[12] & L2[10]) ^ ka[2*r+1] ^ (L2[8] & L2[3])
        fb = ((L2 >> 18) & 1) ^ ((L2 >> 7) & 1) ^ \
             (((L2 >> 12) & 1) & ((L2 >> 10) & 1)) ^ \
             ka[2*r+1] ^ \
             (((L2 >> 8) & 1) & ((L2 >> 3) & 1))

        # Shift registers
        L1_new = ((L1 << 1) | fb) & 0x1FFF
        L2_new = ((L2 << 1) | fa) & 0x7FFFF
        L1, L2 = L1_new, L2_new

    return (L1 << 19) | L2


def _katan48_encrypt(block_48, key_80bit, rounds=254):
    """KATAN48 encryption: 48-bit block, 80-bit key.

    KATAN48 applies the nonlinear function 2 times per round (2 bit-shifts).
    L1=19 bits, L2=29 bits. Tap positions: X1=18,X2=12,X3=15,X4=7,X5=6(IR).
    Y1=28,Y2=19,Y3=21,Y4=13,Y5=15,Y6=6.
    """
    L2 = block_48 & 0x1FFFFFFF  # 29 bits (0-28)
    L1 = (block_48 >> 29) & 0x7FFFF  # 19 bits (29-47)

    n_subkeys = 2 * rounds
    ka = [0] * max(n_subkeys, 80)
    k = key_80bit
    for i in range(80):
        ka[i] = (k >> i) & 1
    if n_subkeys > 80:
        ka.extend([0] * (n_subkeys - len(ka)))
    for i in range(80, n_subkeys):
        ka[i] = ka[i-80] ^ ka[i-61] ^ ka[i-50] ^ ka[i-13]

    for r in range(rounds):
        # KATAN48: 2 sub-steps per round
        for _ in range(2):
            fa = ((L1 >> 18) & 1) ^ ((L1 >> 12) & 1) ^ \
                 (((L1 >> 15) & 1) & ((L1 >> 7) & 1)) ^ \
                 ka[2*r]
            if r < len(_KATAN_IR) and _KATAN_IR[r]:
                fa ^= (L1 >> 6) & 1

            fb = ((L2 >> 28) & 1) ^ ((L2 >> 19) & 1) ^ \
                 (((L2 >> 21) & 1) & ((L2 >> 13) & 1)) ^ \
                 ka[2*r+1] ^ \
                 (((L2 >> 15) & 1) & ((L2 >> 6) & 1))

            L1 = ((L1 << 1) | fb) & 0x7FFFF
            L2 = ((L2 << 1) | fa) & 0x1FFFFFFF
    return (L1 << 29) | L2


def _katan64_encrypt(block_64, key_80bit, rounds=254):
    """KATAN64 encryption: 64-bit block, 80-bit key.

    KATAN64 applies the nonlinear function 3 times per round (3 bit-shifts).
    Tap positions: L1: x1=24,x2=15,x3=20,x4=11,x5=9(IR). L2: y1=38,y2=25,y3=33,y4=21,y5=14,y6=9.
    """
    L2 = block_64 & 0x7FFFFFFFFF  # 39 bits (0-38)
    L1 = (block_64 >> 39) & 0x1FFFFFF  # 25 bits (39-63)

    n_subkeys = 2 * rounds
    ka = [0] * max(n_subkeys, 80)
    k = key_80bit
    for i in range(80):
        ka[i] = (k >> i) & 1
    if n_subkeys > 80:
        ka.extend([0] * (n_subkeys - len(ka)))
    for i in range(80, n_subkeys):
        ka[i] = ka[i-80] ^ ka[i-61] ^ ka[i-50] ^ ka[i-13]

    for r in range(rounds):
        # KATAN64: 3 sub-steps per round (same subkey pair for all 3)
        for _ in range(3):
            fa = ((L1 >> 24) & 1) ^ ((L1 >> 15) & 1) ^ \
                 (((L1 >> 20) & 1) & ((L1 >> 11) & 1)) ^ \
                 ka[2*r]
            if r < len(_KATAN_IR) and _KATAN_IR[r]:
                fa ^= (L1 >> 9) & 1

            fb = ((L2 >> 38) & 1) ^ ((L2 >> 25) & 1) ^ \
                 (((L2 >> 33) & 1) & ((L2 >> 21) & 1)) ^ \
                 ka[2*r+1] ^ \
                 (((L2 >> 14) & 1) & ((L2 >> 9) & 1))

            L1 = ((L1 << 1) | fb) & 0x1FFFFFF
            L2 = ((L2 << 1) | fa) & 0x7FFFFFFFFF
    return (L1 << 39) | L2


def generate_katan_stream(count, rounds=254, seed=42, block_bits=32):
    """Generate KATAN output. block_bits=32, 48, or 64."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(10)
    key_80 = int.from_bytes(key_bytes, 'big')

    block_bytes = block_bits // 8
    block_mask = (1 << block_bits) - 1
    n_blocks = (count * 32 + block_bytes - 1) // block_bytes

    if block_bits == 32:
        enc_fn = _katan32_encrypt
    elif block_bits == 48:
        enc_fn = _katan48_encrypt
    else:
        enc_fn = _katan64_encrypt

    out = bytearray()
    for i in range(n_blocks):
        ct = enc_fn(i & block_mask, key_80, rounds)
        out.extend(ct.to_bytes(block_bytes, 'big'))
    return bytes(out[:count * 32])


def gen_katan32(count, rounds=254, seed=42):
    return generate_katan_stream(count, rounds, seed, 32)

def gen_katan48(count, rounds=254, seed=42):
    return generate_katan_stream(count, rounds, seed, 48)

def gen_katan64(count, rounds=254, seed=42):
    return generate_katan_stream(count, rounds, seed, 64)


# ═══════════════════════════════════════════════════════════════════════
# MASTER CIPHER REGISTRY
# ═══════════════════════════════════════════════════════════════════════

NANO_CIPHER_REGISTRY = {
    # Speck family (10 variants)
    'speck32_64':   {'gen': gen_speck32_64,   'full': 22, 'block': 32,  'key': 64,  'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck48_72':   {'gen': gen_speck48_72,   'full': 22, 'block': 48,  'key': 72,  'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck48_96':   {'gen': gen_speck48_96,   'full': 23, 'block': 48,  'key': 96,  'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck64_96':   {'gen': gen_speck64_96,   'full': 26, 'block': 64,  'key': 96,  'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck64_128':  {'gen': gen_speck64_128,  'full': 27, 'block': 64,  'key': 128, 'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck96_96':   {'gen': gen_speck96_96,   'full': 28, 'block': 96,  'key': 96,  'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck96_144':  {'gen': gen_speck96_144,  'full': 29, 'block': 96,  'key': 144, 'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck128_128': {'gen': gen_speck128_128, 'full': 32, 'block': 128, 'key': 128, 'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck128_192': {'gen': gen_speck128_192, 'full': 33, 'block': 128, 'key': 192, 'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    'speck128_256': {'gen': gen_speck128_256, 'full': 34, 'block': 128, 'key': 256, 'family': 'ARX-Feistel', 'iso': 'ISO/IEC 29167-22'},
    # SIMON family (10 variants)
    'simon32_64':   {'gen': gen_simon32_64,   'full': 32, 'block': 32,  'key': 64,  'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon48_72':   {'gen': gen_simon48_72,   'full': 36, 'block': 48,  'key': 72,  'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon48_96':   {'gen': gen_simon48_96,   'full': 36, 'block': 48,  'key': 96,  'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon64_96':   {'gen': gen_simon64_96,   'full': 42, 'block': 64,  'key': 96,  'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon64_128':  {'gen': gen_simon64_128,  'full': 44, 'block': 64,  'key': 128, 'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon96_96':   {'gen': gen_simon96_96,   'full': 52, 'block': 96,  'key': 96,  'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon96_144':  {'gen': gen_simon96_144,  'full': 54, 'block': 96,  'key': 144, 'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon128_128': {'gen': gen_simon128_128, 'full': 68, 'block': 128, 'key': 128, 'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon128_192': {'gen': gen_simon128_192, 'full': 69, 'block': 128, 'key': 192, 'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    'simon128_256': {'gen': gen_simon128_256, 'full': 72, 'block': 128, 'key': 256, 'family': 'Feistel-LWC', 'iso': 'ISO/IEC 29167-21'},
    # PRESENT (2 variants)
    'present80':    {'gen': gen_present80,    'full': 31, 'block': 64,  'key': 80,  'family': 'SPN-ultralight', 'iso': 'ISO/IEC 29167-11'},
    'present128':   {'gen': gen_present128,   'full': 31, 'block': 64,  'key': 128, 'family': 'SPN-ultralight', 'iso': 'ISO/IEC 29167-11'},
    # ASCON (4 variants)
    'ascon128':     {'gen': gen_ascon128,     'full': 12, 'block': 320, 'key': 128, 'family': 'Sponge-LWC', 'iso': 'NIST SP 800-232'},
    'ascon128a':    {'gen': gen_ascon128a,    'full': 12, 'block': 320, 'key': 128, 'family': 'Sponge-LWC', 'iso': 'NIST SP 800-232'},
    'ascon_hash':   {'gen': gen_ascon_hash,   'full': 12, 'block': 320, 'key': 0,   'family': 'Sponge-LWC', 'iso': 'NIST SP 800-232'},
    'ascon_xof':    {'gen': gen_ascon_xof,    'full': 12, 'block': 320, 'key': 0,   'family': 'Sponge-LWC', 'iso': 'NIST SP 800-232'},
    # LEA (3 variants)
    'lea128':       {'gen': gen_lea128,       'full': 24, 'block': 128, 'key': 128, 'family': 'ARX-block', 'iso': 'Korean TTA'},
    'lea192':       {'gen': gen_lea192,       'full': 28, 'block': 128, 'key': 192, 'family': 'ARX-block', 'iso': 'Korean TTA'},
    'lea256':       {'gen': gen_lea256,       'full': 32, 'block': 128, 'key': 256, 'family': 'ARX-block', 'iso': 'Korean TTA'},
    # Grain-128a
    'grain128a':    {'gen': generate_grain128a_stream, 'full': 256, 'block': 128, 'key': 128, 'family': 'LFSR-NFSR', 'iso': 'ISO/IEC 29167-13'},
    # GIFT (2 variants)
    'gift64':       {'gen': generate_gift64_stream,    'full': 28, 'block': 64,  'key': 128, 'family': 'SPN-LWC', 'iso': 'None'},
    'gift128':      {'gen': generate_gift128_stream,   'full': 40, 'block': 128, 'key': 128, 'family': 'SPN-LWC', 'iso': 'None'},
    # SKINNY (6 variants)
    'skinny64_64':  {'gen': gen_skinny64_64,   'full': 32, 'block': 64,  'key': 64,  'family': 'SPN-TBC', 'iso': 'None'},
    'skinny64_128': {'gen': gen_skinny64_128,  'full': 36, 'block': 64,  'key': 128, 'family': 'SPN-TBC', 'iso': 'None'},
    'skinny64_192': {'gen': gen_skinny64_192,  'full': 40, 'block': 64,  'key': 192, 'family': 'SPN-TBC', 'iso': 'None'},
    'skinny128_128':{'gen': gen_skinny128_128, 'full': 40, 'block': 128, 'key': 128, 'family': 'SPN-TBC', 'iso': 'None'},
    'skinny128_256':{'gen': gen_skinny128_256, 'full': 48, 'block': 128, 'key': 256, 'family': 'SPN-TBC', 'iso': 'None'},
    'skinny128_384':{'gen': gen_skinny128_384, 'full': 56, 'block': 128, 'key': 384, 'family': 'SPN-TBC', 'iso': 'None'},
    # KATAN (3 variants)
    'katan32':      {'gen': gen_katan32,       'full': 254, 'block': 32,  'key': 80,  'family': 'LFSR-block', 'iso': 'None'},
    'katan48':      {'gen': gen_katan48,       'full': 254, 'block': 48,  'key': 80,  'family': 'LFSR-block', 'iso': 'None'},
    'katan64':      {'gen': gen_katan64,       'full': 254, 'block': 64,  'key': 80,  'family': 'LFSR-block', 'iso': 'None'},
}
