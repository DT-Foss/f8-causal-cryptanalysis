#!/usr/bin/env python3
"""
Cipher implementations for live-casi.

Eight cipher families, each with configurable round count:
  - ChaCha20    (ARX stream)          — 20 rounds, 64-byte block
  - Salsa20     (ARX stream)          — 20 rounds, 64-byte block
  - AES-128     (SPN block)           — 10 rounds, 16-byte block
  - Speck 32/64 (ARX Feistel)         — 22 rounds, 4-byte block
  - Blowfish    (Feistel keydep)      — 16 rounds, 8-byte block
  - 3DES EDE    (Feistel fixed)       — 16 rounds, 8-byte block
  - RC4         (byte-stream PRGA)    — 256 KSA iterations
  - Camellia-128 (SPN+Feistel hybrid) — 18 rounds, 16-byte block

All generators: generate_*_stream(count, rounds, seed) -> bytes
Returns count * 32 raw bytes (count 32-byte keys).
"""

import struct
import numpy as np

# ═══════════════════════════════════════════════════════════════
# ChaCha20 (ARX stream cipher)
# ═══════════════════════════════════════════════════════════════

def _chacha_qr(s, a, b, c, d):
    M = 0xFFFFFFFF
    s[a] = (s[a] + s[b]) & M; s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >> 16)) & M
    s[c] = (s[c] + s[d]) & M; s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >> 20)) & M
    s[a] = (s[a] + s[b]) & M; s[d] ^= s[a]; s[d] = ((s[d] <<  8) | (s[d] >> 24)) & M
    s[c] = (s[c] + s[d]) & M; s[b] ^= s[c]; s[b] = ((s[b] <<  7) | (s[b] >> 25)) & M


def _chacha_block(key_bytes, counter, nonce_bytes, rounds=20):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + \
            list(struct.unpack('<8I', key_bytes)) + [counter] + \
            list(struct.unpack('<3I', nonce_bytes))
    w = state[:]
    for i in range(rounds):
        if i % 2 == 0:
            _chacha_qr(w, 0, 4, 8,12); _chacha_qr(w, 1, 5, 9,13)
            _chacha_qr(w, 2, 6,10,14); _chacha_qr(w, 3, 7,11,15)
        else:
            _chacha_qr(w, 0, 5,10,15); _chacha_qr(w, 1, 6,11,12)
            _chacha_qr(w, 2, 7, 8,13); _chacha_qr(w, 3, 4, 9,14)
    return struct.pack('<16I', *[((w[i] + state[i]) & 0xFFFFFFFF) for i in range(16)])


def generate_chacha_stream(count, rounds=20, seed=42):
    np.random.seed(seed)
    key = np.random.bytes(32)
    nonce = np.random.bytes(12)
    out = bytearray()
    ctr = 0
    while len(out) < count * 32:
        out.extend(_chacha_block(key, ctr, nonce, rounds))
        ctr += 1
    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# Salsa20 (ARX stream cipher)
# ═══════════════════════════════════════════════════════════════

def _rotl32(v, n):
    return ((v << n) | (v >> np.uint32(32 - n))) & np.uint32(0xFFFFFFFF)


def _salsa_qr(s, a, b, c, d):
    s[:, b] ^= _rotl32((s[:, a] + s[:, d]) & 0xFFFFFFFF, 7)
    s[:, c] ^= _rotl32((s[:, b] + s[:, a]) & 0xFFFFFFFF, 9)
    s[:, d] ^= _rotl32((s[:, c] + s[:, b]) & 0xFFFFFFFF, 13)
    s[:, a] ^= _rotl32((s[:, d] + s[:, c]) & 0xFFFFFFFF, 18)


def generate_salsa_stream(count, rounds=20, seed=42):
    rng = np.random.RandomState(seed)
    key_u32 = rng.randint(0, 2**32, size=8, dtype=np.uint32)
    nonce_u32 = rng.randint(0, 2**32, size=2, dtype=np.uint32)
    CONST = np.array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574], dtype=np.uint32)

    n_blocks = (count + 1) // 2
    batch = 10000
    all_bytes = []

    for start in range(0, n_blocks, batch):
        end = min(start + batch, n_blocks)
        N = end - start
        counters = np.arange(start, end, dtype=np.uint64)

        s = np.zeros((N, 16), dtype=np.uint32)
        s[:, 0] = CONST[0]; s[:, 5] = CONST[1]; s[:, 10] = CONST[2]; s[:, 15] = CONST[3]
        s[:, 1] = key_u32[0]; s[:, 2] = key_u32[1]; s[:, 3] = key_u32[2]; s[:, 4] = key_u32[3]
        s[:, 11] = key_u32[4]; s[:, 12] = key_u32[5]; s[:, 13] = key_u32[6]; s[:, 14] = key_u32[7]
        s[:, 6] = nonce_u32[0]; s[:, 7] = nonce_u32[1]
        s[:, 8] = (counters & 0xFFFFFFFF).astype(np.uint32)
        s[:, 9] = (counters >> 32).astype(np.uint32)

        initial = s.copy()
        for r in range(rounds):
            if r % 2 == 0:
                _salsa_qr(s, 0, 4, 8,12); _salsa_qr(s, 5, 9,13, 1)
                _salsa_qr(s,10,14, 2, 6); _salsa_qr(s,15, 3, 7,11)
            else:
                _salsa_qr(s, 0, 1, 2, 3); _salsa_qr(s, 5, 6, 7, 4)
                _salsa_qr(s,10,11, 8, 9); _salsa_qr(s,15,12,13,14)

        s = (s + initial) & 0xFFFFFFFF
        all_bytes.append(s.astype('<u4').view(np.uint8).reshape(N, 64))

    full = np.concatenate(all_bytes, axis=0)
    return full.reshape(-1, 32)[:count].tobytes()


# ═══════════════════════════════════════════════════════════════
# AES-128 (SPN block cipher)
# ═══════════════════════════════════════════════════════════════

_AES_SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
], dtype=np.uint8)

_AES_RCON = np.array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36], dtype=np.uint8)


def _aes_key_expansion(key_bytes):
    w = np.zeros((44, 4), dtype=np.uint8)
    for i in range(4):
        w[i] = key_bytes[4*i:4*i+4]
    for i in range(4, 44):
        temp = w[i-1].copy()
        if i % 4 == 0:
            temp = np.array([_AES_SBOX[temp[1]], _AES_SBOX[temp[2]],
                             _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]], dtype=np.uint8)
            temp[0] ^= _AES_RCON[i//4 - 1]
        w[i] = w[i-4] ^ temp
    return w.reshape(11, 16)


def _aes_xtime(a):
    return ((a.astype(np.uint16) << 1) ^ (((a.astype(np.uint16) >> 7) & 1) * 0x1b)).astype(np.uint8)


def _aes_ecb_batch(key_bytes, plaintexts, rounds=10):
    N = len(plaintexts)
    rk_all = _aes_key_expansion(key_bytes).reshape(11, 4, 4).transpose(0, 2, 1)
    state = plaintexts.reshape(N, 4, 4).transpose(0, 2, 1).copy()
    state ^= rk_all[0][np.newaxis, :, :]

    for r in range(1, rounds + 1):
        state = _AES_SBOX[state]
        for row in range(1, 4):
            state[:, row, :] = np.roll(state[:, row, :], -row, axis=1)
        if r < rounds:
            s0, s1, s2, s3 = state[:,0,:].copy(), state[:,1,:].copy(), state[:,2,:].copy(), state[:,3,:].copy()
            x0, x1, x2, x3 = _aes_xtime(s0), _aes_xtime(s1), _aes_xtime(s2), _aes_xtime(s3)
            state[:,0,:] = x0 ^ x1 ^ s1 ^ s2 ^ s3
            state[:,1,:] = s0 ^ x1 ^ x2 ^ s2 ^ s3
            state[:,2,:] = s0 ^ s1 ^ x2 ^ x3 ^ s3
            state[:,3,:] = x0 ^ s0 ^ s1 ^ s2 ^ x3
        state ^= rk_all[r][np.newaxis, :, :]

    return state.transpose(0, 2, 1).reshape(N, 16)


def generate_aes_stream(count, rounds=10, seed=42):
    rng = np.random.RandomState(seed)
    aes_key = rng.randint(0, 256, size=16, dtype=np.uint8)
    n_blocks = count * 2
    batch = 20000
    all_blocks = []

    for start in range(0, n_blocks, batch):
        end = min(start + batch, n_blocks)
        bs = end - start
        pt = np.zeros((bs, 16), dtype=np.uint8)
        ctrs = np.arange(start, end, dtype=np.uint64)
        for b in range(8):
            pt[:, b] = ((ctrs >> (8*b)) & 0xFF).astype(np.uint8)
        all_blocks.append(_aes_ecb_batch(aes_key, pt, rounds))

    return np.concatenate(all_blocks).reshape(-1, 32)[:count].tobytes()


# ═══════════════════════════════════════════════════════════════
# Speck 32/64 (ARX Feistel — Gohr benchmark cipher)
# ═══════════════════════════════════════════════════════════════

_M16 = np.uint16(0xFFFF)

def _ror16(v, n):
    return ((v >> np.uint16(n)) | (v << np.uint16(16 - n))) & _M16

def _rol16(v, n):
    return ((v << np.uint16(n)) | (v >> np.uint16(16 - n))) & _M16


def _speck_key_schedule(key_u16, rounds=22):
    m = 3
    l = [key_u16[1+i] for i in range(m)]
    k = [key_u16[0]]
    for i in range(rounds - 1):
        new_l = np.uint16((np.uint32(k[i]) + np.uint32(_ror16(np.array([l[i]], dtype=np.uint16), 7)[0])) & 0xFFFF)
        new_l = np.uint16(new_l ^ np.uint16(i))
        l.append(new_l)
        new_k = np.uint16(_rol16(np.array([k[i]], dtype=np.uint16), 2)[0] ^ new_l)
        k.append(new_k)
    return k[:rounds]


def generate_speck_stream(count, rounds=22, seed=42):
    rng = np.random.RandomState(seed)
    key_u16 = rng.randint(0, 2**16, size=4, dtype=np.uint16)
    rks = _speck_key_schedule(key_u16, rounds)
    n_blocks = count * 8
    batch = 100000
    all_blocks = []

    for start in range(0, n_blocks, batch):
        end = min(start + batch, n_blocks)
        ctrs = np.arange(start, end, dtype=np.uint32)
        x = ((ctrs >> 16) & 0xFFFF).astype(np.uint16)
        y = (ctrs & 0xFFFF).astype(np.uint16)

        for i in range(rounds):
            x = ((_ror16(x, 7).astype(np.uint32) + y.astype(np.uint32)) & 0xFFFF).astype(np.uint16)
            x ^= np.uint16(rks[i])
            y = _rol16(y, 2) ^ x

        blocks = np.zeros((end - start, 4), dtype=np.uint8)
        blocks[:, 0] = (x >> 8).astype(np.uint8)
        blocks[:, 1] = (x & 0xFF).astype(np.uint8)
        blocks[:, 2] = (y >> 8).astype(np.uint8)
        blocks[:, 3] = (y & 0xFF).astype(np.uint8)
        all_blocks.append(blocks)

    return np.concatenate(all_blocks).reshape(-1, 32)[:count].tobytes()


# ═══════════════════════════════════════════════════════════════
# Blowfish (Feistel with key-dependent S-boxes)
# ═══════════════════════════════════════════════════════════════

_BF_P_INIT = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b,
]

# Blowfish S-boxes (4 x 256 uint32, derived from pi digits)
# Compact hex encoding — decoded at import time
_BF_S_HEX = (
    # S0
    "d1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f99"
    "24a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e"
    "0d95748f728eb658718bcd5882154aee7b54a41dc25a59b59c30d5392af26013"
    "c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3e"
    "d71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e81440"
    "55ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a"
    "2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f4898"
    "6b4bb9afc4bfe81b66282193" "61d809ccfb21a991487cac605dec8032"
    "ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f44239"
    "2e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f0"
    "6a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98"
    "a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebe"
    "e06f75d885c12073401a449f56c16aa64ed3aa62363f77061bfedf72429b023d"
    "37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7"
    "e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a2463"
    "68fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09"
    "bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb"
    "5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc8ea5e9f8db3222f8"
    "3c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df82"
    "9e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573"
    "695b27b0bbca58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b"
    "9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8"
    "ef20cada36774c01d07e9efe2bf11fb495dbda4dae909198eaad8e716b93d5a0"
    "d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fbf2122b648888b812900df01c"
    "4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777ea752dfe8b021fa1"
    "e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81d2ada8d9"
    "165fa26680957705" "93cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cf"
    "ebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e226800bb57b8e0af"
    "2464369bf009b91e5563911d59dfa6aa78c14389d95a537f207d5ba202e5b9c5"
    "832603766295cfa911c819684e734a41b3472dca7b14a94a1b510052"
    "9a532915d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91ff296ec6b"
    "2a0dd915b6636521e7b9f9b6ff34052ec585566453b02d5da99f8fa108ba4799"
    "6e85076a",
    # S1
    "4b7a70e9b5b32944db75092ec4192623ad6ea6b049a7df7d9cee60b88fedb266"
    "ecaa8c71699a17ff5664526cc2b19ee1193602a575094c29a0591340e4183a3e"
    "3f54989a5b429d656b8fe4d699f73fd6a1d29c07efe830f54d2d38e6f0255dc1"
    "4cdd20868470eb266382e9c6021ecc5e09686b3f3ebaefc93c9718146b6a70a1"
    "687f358452a0e286b79c5305aa5007373e07841c7fdeae5c8e7d44ec5716f2b8"
    "b03ada37f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc0921bd"
    "d19113f97ca92ff69432477322f547013ae5e58137c2dadcc8b576349af3dda7"
    "a94461460fd0030eecc8c73ea4751e41e238cd993bea0e2f3280bba1183eb331"
    "4e548b384f6db9086f420d03f60a04bf2cb8129024977c795679b072bcaf89af"
    "de9a771fd9930810b38bae12dccf3f2e5512721f2e6b7124501adde69f84cd87"
    "7a5847187408da17bc9f9abce94b7d8cec7aec3adb851dfa63094366c464c3d2"
    "ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002133ae4dd"
    "71dff89e10314e5581ac77d65f11199b043556f1d7a3c76b3c11183b5924a509"
    "f28fe6ed97f1fbfa9ebabf2c1e153c6e86e34570eae96fb1860e5e0a5a3e2ab3"
    "771fe71c4e3d06fa2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36a"
    "c6150eba94e2ea78a5fc3c531e0a2df4f2f74ea7361d2b3d1939260f19c27960"
    "5223a708f71312b6ebadfe6eeac31f66e3bc4595a67bc883b17f37d1018cff28"
    "c332ddefbe6c5aa56558218568ab9802eecea50fdb2f953b2aef7dad5b6e2f84"
    "1521b62829076170ecdd4775619f151013cca830eb61bd960334fe1eaa0363cf"
    "b5735c904c70a239d59e9e0bcbaade14eecc86bc60622ca79cab5cabb2f3846e"
    "648b1eaf19bdf0caa02369b9655abb5040685a323c2ab4b3319ee9d5c021b8f7"
    "9b540b19875fa09995f7997e623d7da8f837889a97e32d7711ed935f16681281"
    "0e358829c7e61fd696dedfa17858ba9957f584a51b227263"
    "9b83c3ff1ac24696cdb30aeb532e30548fd948e46dbc312858ebf2ef34c6ffea"
    "fe28ed61ee7c3c735d4a14d9e864b7e342105d14203e13e045eee2b6a3aaabea"
    "db6c4f15facb4fd0c742f442ef6abbb5654f3b1d41cd2105d81e799e86854dc7"
    "e44b476a3d816250cf62a1f25b8d2646fc8883a0c1c7b6a37f1524c369cb7492"
    "47848a0b5692b285095bbf00ad19489d1462b17423820e0058428d2a0c55f5ea"
    "1dadf43e233f70613372f0928d937e41d65fecf16c223bdb7cde3759cbee7460"
    "4085f2a7ce77326ea607808419f8509ee8efd85561d99735a969a7aac50c06c2"
    "5a04abfc800bcadc9e447a2ec3453484fdd567050e1e9ec9db73dbd3105588cd"
    "675fda79e3674340c5c43465713e38d83d28f89ef16dff20153e21e78fb03d4a"
    "e6e39f2bdb83adf7",
    # S2
    "e93d5a68948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068"
    "d40824713320f46a43b7d4b7500061af1e39f62e9724454614214f74bf8b8840"
    "4d95fc1d96b591af70f4ddd366a02f45bfbc09ec03bd97857fac6dd031cb8504"
    "96eb27b355fd3941da2547e6abca0a9a28507825530429f40a2c86dae9b66dfb"
    "68dc1462d748690068" "0ec0a427a18dee4f3ffea2e887ad8cb58ce0067af4d6b6"
    "aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9ee39d7ab3b124e8b"
    "1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7ca7820fb"
    "fb0af54ed8feb397454056acba48952755533a3a20838d87fe6ba9b7d096954b"
    "55a867bca1159a58cca9296399e1db33a62a4a563f3125f95ef47e1c9029317c"
    "fdf8e80204272f7080bb155c05282ce395c11548e4c66d2248c1133fc70f86dc"
    "07f9c9ee41041f0f404779a45d886e17325f51ebd59bc0d1f2bcc18f41113564"
    "257b7834602a9c60dff8e8a31f636c1b0e12b4c202e1329eaf664fd1cad18115"
    "6b2395e0333e92e13b240b62eebeb92285b2a20ee6ba0d99de720c8c2da2f728"
    "d012784595b794fd647d0862e7ccf5f05449a36f877d48fac39dfd27f33e8d1e"
    "0a476341992eff743a6f6eabf4f8fd37a812dc60a1ebddf8991be14cdb6e6b0d"
    "c67b55106d672c372765d43bdcd0e804f1290dc7cc00ffa3b5390f92690fed0b"
    "667b9ffbcedb7d9ca091cf0bd9155ea3bb132f88515bad247b9479bf763bd6eb"
    "37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b12754ccc782ef11c"
    "6a124237b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9"
    "44421659" "0a121386d90cec6ed5abea2a64af674eda86a85fbebfe98864e4c3fe"
    "9dbc8057f0f7c08660787bf86003604dd1fd8346f6381fb07745ae04d736fccc"
    "83426b33f01eab71b08041873c005e5f77a057bebde8ae2455464299bf582e61"
    "4e58f48ff2ddfda2f474ef388789bdc25366f9c3c8b38e74b475f25546fcd9b9"
    "7aeb26618b1ddf84846a0e79915f95e2466e598e20b457708cd55591c902de4c"
    "b90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1c4324633"
    "e85a1f0209f0be8c4a99a0251d6efe101ab93d1d0ba5a4dfa186f20f2868f169"
    "dcb7da83573906fea1e2ce9b4fcd7f5250115e01a70683faa002b5c40de6d027"
    "9af88c27773f8641c3604c0661a806b5f0177a28c0f586e0006058aa30dc7d62"
    "11e69ed72338ea6353c2dd94c2c21634bbcbee5690bcb6deebfc7da1ce591d76"
    "6f05e4094b7c018839720a3d7c927c2486e3725f724d9db91ac15bb4d39eb8fc"
    "ed54557808fca5b5d83d7cd34dad0fc41e50ef5eb161e6f8a28514d96c51133c"
    "6fd5c7e756e14ec4362abfceddc6c837d79a323492638212670efa8e406000e0",
    # S3
    "3a39ce37d3faf5cfabc27737" "5ac52d1b5cb0679e4fa33742d382274099bc9bbe"
    "d5118e9dbf0f7315d62d1c7ec700c47bb78c1b6b21a19045b26eb1be6a366eb4"
    "5748ab2fbc946e79c6a376d26549c2c8530ff8ee468dde7dd5730a1d4cd04dc6"
    "2939bbdba9ba4650ac9526e8be5ee304a1fad5f06a2d519a63ef8ce29a86ee22"
    "c089c2b843242ef6a51e03aa9cf2d0a483c061ba9be96a4d8fe51550ba645bd6"
    "2826a2f9a73a3ae14ba99586ef5562e9c72fefd3f752f7da3f046f6977fa0a59"
    "80e4a91587b086019b09e6ad3b3ee593e990fd5a9e34d7972cf0b7d9022b8b51"
    "96d5ac3a017da67dd1cf3ed67c7d2d281f9f25cfadf2b89b5ad6b4725a88f54c"
    "e029ac71e019a5e647b0acfded93fa9be8d3c48d283b57ccf8d5662979132e28"
    "785f0191ed756055f7960e44e3d35e8c15056dd488f46dba03a161250564f0bd"
    "c3eb9e153c9057a297271aeca93a072a1b3f6d9b1e6321f5f59c66fb26dcf319"
    "7533d928b155fdf503563482" "8aba3cbb28517711c20ad9f8abcc5167ccad925f"
    "4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce5121ce64774fbe32"
    "a8b6e37ec3293d4648de53696413e680a2ae0810dd6db22469852dfd09072166"
    "b39a460a6445c0dd586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bb"
    "dda26a7e3a59ff453e350a44bcb4cdd572eacea8fa6484bb8d6612aebf3c6f47"
    "d29be463542f5d9eaec2771bf64e6370740e0d8de75b1357f8721671af537d5d"
    "4040cb084eb4e2cc34d2466a0115af84e1b0042895983a1d06b89fb4ce6ea048"
    "6f3f3b823520ab82011a1d4b277227f8611560b1e7933fdcbb3a792b344525bd"
    "a08839e151ce794b2f32c9b7a01fbac9e01cc87ebcc7d1f6cf0111c3a1e8aac7"
    "1a908749d44fbd9ad0dadecbd50ada380339c32ac6913667"
    "8df9317ce0b12b4ff79e59b743f5bb3af2d519ff27d9459cbf97222c15e6fc2a"
    "0f91fc719b941525fae59361ceb69cebc2a8645912baa8d1b6c1075ee3056a0c"
    "10d25065cb03a442e0ec6e0e1698db3b4c98a0be3278e9649f1f9532e0d392df"
    "d3a0342b8971f21e1b0a74414ba3348cc5be7120c37632d8df359f8d9b992f2e"
    "e60b6f470fe3f11de54cda541edad891ce6279cfcd3e7e6f1618b166fd2c1d05"
    "848fd2c5f6fb2299f523f357a632762393a8353156cccd02acf081625a75ebb5"
    "6e16369788d273ccde96629281b949d04c50901b71c65614e6c6c7bd327a140a"
    "45e1d006c3f27b9ac9aa53fd62a80f00bb25bfe235bdd2f671126905b2040222"
    "b6cbcf7ccd769c2b53113ec01640e3d338abbd602547adf0ba38209cf746ce76"
    "77afa1c52075606085cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c"
    "01c36ae4d6ebe1f990d4f869a65cdea03f09252dc208e69fb74e6132ce77e25b"
    "578fdfe33ac372e6",
)


def _decode_sbox_hex(hex_str):
    """Decode hex string to list of 256 uint32 values."""
    b = bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))
    return [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]


# Decode S-boxes at import time
_BF_S_INIT = [_decode_sbox_hex(h) for h in _BF_S_HEX]
_BF_MASK32 = 0xFFFFFFFF


def _bf_f(x, S):
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8) & 0xFF
    d = x & 0xFF
    return ((S[0][a] + S[1][b]) & _BF_MASK32 ^ S[2][c]) + S[3][d] & _BF_MASK32


def _bf_encrypt_pair(L, R, P, S, rounds=16):
    for i in range(rounds):
        L = (L ^ P[i]) & _BF_MASK32
        R = (R ^ _bf_f(L, S)) & _BF_MASK32
        L, R = R, L
    L, R = R, L
    R = (R ^ P[rounds]) & _BF_MASK32
    L = (L ^ P[rounds + 1]) & _BF_MASK32
    return L, R


def _bf_key_expand(key_bytes):
    key_len = len(key_bytes)
    P = list(_BF_P_INIT)
    S = [list(s) for s in _BF_S_INIT]
    j = 0
    for i in range(18):
        data = 0
        for _ in range(4):
            data = ((data << 8) | key_bytes[j % key_len]) & _BF_MASK32
            j += 1
        P[i] = (P[i] ^ data) & _BF_MASK32
    L, R = 0, 0
    for i in range(0, 18, 2):
        L, R = _bf_encrypt_pair(L, R, P, S, 16)
        P[i] = L; P[i+1] = R
    for box in range(4):
        for i in range(0, 256, 2):
            L, R = _bf_encrypt_pair(L, R, P, S, 16)
            S[box][i] = L; S[box][i+1] = R
    return P, S


def generate_blowfish_stream(count, rounds=16, seed=42):
    rng = np.random.RandomState(seed)
    bf_key = rng.randint(0, 256, size=16, dtype=np.uint8).tolist()
    P, S = _bf_key_expand(bf_key)

    n_blocks = count * 4
    batch = 50000
    all_blocks = []
    S_np = [np.array(s, dtype=np.uint64) for s in S]

    for start in range(0, n_blocks, batch):
        end = min(start + batch, n_blocks)
        ctrs = np.arange(start, end, dtype=np.uint64)
        L = ((ctrs >> 32) & _BF_MASK32).astype(np.uint64)
        R = (ctrs & _BF_MASK32).astype(np.uint64)

        for i in range(rounds):
            L = (L ^ np.uint64(P[i])) & _BF_MASK32
            a = ((L >> 24) & 0xFF).astype(np.intp)
            b = ((L >> 16) & 0xFF).astype(np.intp)
            c = ((L >> 8) & 0xFF).astype(np.intp)
            d = (L & 0xFF).astype(np.intp)
            f_val = (((S_np[0][a] + S_np[1][b]) & _BF_MASK32) ^ S_np[2][c]) + S_np[3][d]
            R = (R ^ (f_val & _BF_MASK32)) & _BF_MASK32
            L, R = R, L
        L, R = R, L
        R = (R ^ np.uint64(P[rounds])) & _BF_MASK32
        L = (L ^ np.uint64(P[rounds + 1])) & _BF_MASK32

        L32 = L.astype(np.uint32)
        R32 = R.astype(np.uint32)
        bs = end - start
        blocks = np.zeros((bs, 8), dtype=np.uint8)
        for b in range(4):
            blocks[:, b] = ((L32 >> np.uint32(24 - 8*b)) & 0xFF).astype(np.uint8)
            blocks[:, 4+b] = ((R32 >> np.uint32(24 - 8*b)) & 0xFF).astype(np.uint8)
        all_blocks.append(blocks)

    return np.concatenate(all_blocks).reshape(-1, 32)[:count].tobytes()


# ═══════════════════════════════════════════════════════════════
# 3DES EDE (Feistel with fixed S-boxes)
# NOTE: Pure Python, ~100x slower than vectorized ciphers.
# ═══════════════════════════════════════════════════════════════

_DES_IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
]
_DES_FP = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25,
]
_DES_E = [
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1,
]
_DES_P = [
    16, 7,20,21, 29,12,28,17,  1,15,23,26,  5,18,31,10,
     2, 8,24,14, 32,27, 3, 9, 19,13,30, 6, 22,11, 4,25,
]
_DES_SBOX = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]
_DES_PC1 = [
    57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4,
]
_DES_PC2 = [
    14,17,11,24, 1, 5,  3,28,15, 6,21,10,
    23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32,
]
_DES_ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_MASK28 = 0x0FFFFFFF


def _des_permute(val, table, in_bits, out_bits):
    result = 0
    for i, pos in enumerate(table):
        if val & (1 << (in_bits - pos)):
            result |= (1 << (out_bits - 1 - i))
    return result


def _des_key_schedule(key_64bit, rounds=16):
    cd = _des_permute(key_64bit, _DES_PC1, 64, 56)
    C = (cd >> 28) & _MASK28
    D = cd & _MASK28
    rks = []
    for i in range(rounds):
        rot = _DES_ROTATIONS[i]
        C = ((C << rot) | (C >> (28 - rot))) & _MASK28
        D = ((D << rot) | (D >> (28 - rot))) & _MASK28
        rks.append(_des_permute((C << 28) | D, _DES_PC2, 56, 48))
    return rks


def _des_feistel(R, rk):
    expanded = _des_permute(R, _DES_E, 32, 48)
    x = expanded ^ rk
    s_out = 0
    for box in range(8):
        six = (x >> ((7 - box) * 6)) & 0x3F
        row = ((six >> 5) << 1) | (six & 1)
        col = (six >> 1) & 0xF
        s_out = (s_out << 4) | _DES_SBOX[box][row * 16 + col]
    return _des_permute(s_out, _DES_P, 32, 32)


def _des_encrypt(block, rks, decrypt=False):
    state = _des_permute(block, _DES_IP, 64, 64)
    L = (state >> 32) & _BF_MASK32
    R = state & _BF_MASK32
    keys = list(reversed(rks)) if decrypt else rks
    for rk in keys:
        L, R = R, (L ^ _des_feistel(R, rk)) & _BF_MASK32
    return _des_permute(((R << 32) | L) & 0xFFFFFFFFFFFFFFFF, _DES_FP, 64, 64)


def generate_tdes_stream(count, rounds=16, seed=42):
    rng = np.random.RandomState(seed)
    k1 = int.from_bytes(rng.randint(0, 256, size=8, dtype=np.uint8).tobytes(), 'big')
    k2 = int.from_bytes(rng.randint(0, 256, size=8, dtype=np.uint8).tobytes(), 'big')
    k3 = int.from_bytes(rng.randint(0, 256, size=8, dtype=np.uint8).tobytes(), 'big')
    rk1 = _des_key_schedule(k1, rounds)
    rk2 = _des_key_schedule(k2, rounds)
    rk3 = _des_key_schedule(k3, rounds)

    n_blocks = count * 4
    out = bytearray()
    for i in range(n_blocks):
        x = _des_encrypt(i, rk1, False)
        x = _des_encrypt(x, rk2, True)
        x = _des_encrypt(x, rk3, False)
        out.extend(x.to_bytes(8, 'big'))
    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# RC4 (byte-oriented stream cipher)
# ═══════════════════════════════════════════════════════════════

def generate_rc4_stream(count, rounds=256, seed=42):
    """Generate RC4 keystream output.
    'rounds' controls KSA iterations (full=256). Reduced KSA = weak key schedule.
    Each unique key produces 32 bytes of PRGA output."""
    rng = np.random.RandomState(seed)
    n_keys = count
    out = bytearray()

    for _ in range(n_keys):
        # Random 16-byte key
        key = rng.randint(0, 256, size=16, dtype=np.uint8)
        key_len = len(key)

        # KSA (Key Scheduling Algorithm) — 'rounds' iterations (full=256)
        S = list(range(256))
        j = 0
        ksa_rounds = min(rounds, 256)
        for i in range(ksa_rounds):
            j = (j + S[i] + key[i % key_len]) & 0xFF
            S[i], S[j] = S[j], S[i]

        # If reduced KSA, remaining S entries are still identity
        # PRGA — generate 32 bytes of keystream
        i = j = 0
        for _ in range(32):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(S[(S[i] + S[j]) & 0xFF])

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# Camellia-128 (SPN + Feistel hybrid block cipher)
# ═══════════════════════════════════════════════════════════════

# Camellia S-boxes (from RFC 3713)
_CAM_SP1 = np.array([
    112,130, 44,236,179, 39,192,229,228,136,  4,153, 62, 12,235,230,
     75, 52,190, 26, 45,174, 19,240,182,121,154,143,235, 11, 59,186,
    200, 47,141, 22,105,222, 51,227, 11,  0, 91, 88,246,239,214, 75,
     34,177, 73, 23,144, 85,125,174, 25,233, 69, 39, 60, 30, 28, 51,
    247, 67, 84, 80, 90, 69, 60, 62, 33, 16,238, 16, 15, 69,216,158,
     83,124,142, 81, 95, 56, 41,115,207,107, 80,149, 46,198, 93,  7,
    199, 27,200,184,100,162, 84, 80, 29,224, 66,179, 75, 74,190, 37,
    151,181, 61, 29,215, 58,209,149, 62, 43, 68,  6, 25, 26,147,195,
    164,147,224,196,136, 36, 10,117,  1, 85, 37, 63, 88, 86, 80, 59,
    237,159,175, 81, 10, 35, 18,237,175,  7, 30,125, 45, 76, 91, 35,
    159, 46,185,156, 51, 58,211,136, 50, 90, 54,216, 89, 91, 85, 56,
    154,  7, 22,129,  3,126, 97,100, 52,  0, 43, 66, 37, 75,  0, 45,
     75,126,146, 37, 57, 71,223,218, 16,144, 98,168,123, 70, 50,133,
    130,216, 65, 50,129,  7,228, 56, 74,142,149, 13, 22,110,187, 41,
     26,108,188, 43,165,242, 97,167, 94,131, 80,254, 23, 40, 26, 54,
    204,117,110, 25,248,  1,222, 54,197, 87,204, 36,254,206, 76,212,
], dtype=np.uint8)

def _cam_sp(x):
    """Camellia S-function: applies S-box with rotations."""
    # Simplified: use single S-box with bit rotation variants
    return _CAM_SP1[x & 0xFF]

def _cam_fl(x_hi, x_lo, k_hi, k_lo):
    """FL function: x_lo ^= (x_hi & k_hi) <<< 1; x_hi ^= (x_lo | k_lo)"""
    t = (x_hi & k_hi) & 0xFFFFFFFF
    x_lo ^= ((t << 1) | (t >> 31)) & 0xFFFFFFFF
    x_hi ^= (x_lo | k_lo) & 0xFFFFFFFF
    return x_hi & 0xFFFFFFFF, x_lo & 0xFFFFFFFF

def _cam_flinv(y_hi, y_lo, k_hi, k_lo):
    """FL^-1 function (inverse of FL)."""
    y_hi ^= (y_lo | k_lo) & 0xFFFFFFFF
    y_hi &= 0xFFFFFFFF
    t = (y_hi & k_hi) & 0xFFFFFFFF
    y_lo ^= ((t << 1) | (t >> 31)) & 0xFFFFFFFF
    return y_hi, y_lo & 0xFFFFFFFF

def _cam_f(x_hi, x_lo, k_hi, k_lo):
    """Camellia F function: XOR with subkey, then S-box + P-layer."""
    x_hi ^= k_hi
    x_lo ^= k_lo
    # Pack into 8 bytes, apply S-boxes
    b = [(x_hi >> 24) & 0xFF, (x_hi >> 16) & 0xFF,
         (x_hi >> 8) & 0xFF, x_hi & 0xFF,
         (x_lo >> 24) & 0xFF, (x_lo >> 16) & 0xFF,
         (x_lo >> 8) & 0xFF, x_lo & 0xFF]
    # S-box layer (4 different S-boxes via rotation)
    t = [_CAM_SP1[b[0]], _CAM_SP1[(b[1] << 1 | b[1] >> 7) & 0xFF],
         _CAM_SP1[(b[2] << 7 | b[2] >> 1) & 0xFF], _CAM_SP1[b[3]],
         _CAM_SP1[(b[4] << 1 | b[4] >> 7) & 0xFF], _CAM_SP1[b[5]],
         _CAM_SP1[b[6]], _CAM_SP1[(b[7] << 7 | b[7] >> 1) & 0xFF]]
    # P-layer (byte mixing)
    t[1] ^= t[0]; t[2] ^= t[3]; t[3] ^= t[1]; t[0] ^= t[2]
    t[5] ^= t[4]; t[6] ^= t[7]; t[7] ^= t[5]; t[4] ^= t[6]
    t[2] ^= t[5]; t[3] ^= t[4]; t[0] ^= t[7]; t[1] ^= t[6]
    r_hi = (int(t[0]) << 24) | (int(t[1]) << 16) | (int(t[2]) << 8) | int(t[3])
    r_lo = (int(t[4]) << 24) | (int(t[5]) << 16) | (int(t[6]) << 8) | int(t[7])
    return r_hi, r_lo


def generate_camellia_stream(count, rounds=18, seed=42):
    """Generate Camellia-128 encrypted output with configurable rounds.
    Camellia-128 uses 18 rounds with FL/FL^-1 layers after rounds 6 and 12.
    Block size: 16 bytes, two blocks per 32-byte key."""
    rng = np.random.RandomState(seed)
    n_keys = count
    n_blocks = n_keys * 2  # 2 blocks per key

    # Generate 128-bit key + round keys (simplified key schedule)
    master_key = rng.randint(0, 256, size=16, dtype=np.uint8)
    mk_hi = int.from_bytes(master_key[:4], 'big')
    mk_lo = int.from_bytes(master_key[4:8], 'big')
    mk2_hi = int.from_bytes(master_key[8:12], 'big')
    mk2_lo = int.from_bytes(master_key[12:16], 'big')

    # Generate subkeys via rotation of key material (simplified schedule)
    kl_hi, kl_lo = mk_hi, mk_lo
    kr_hi, kr_lo = mk2_hi, mk2_lo

    # Derive 24 subkey halves by rotating the key
    subkeys = []
    state = (kl_hi << 96) | (kl_lo << 64) | (kr_hi << 32) | kr_lo
    for i in range(24):
        rot = (i * 15 + 7) % 128
        rotated = ((state << rot) | (state >> (128 - rot))) & ((1 << 128) - 1)
        sk_hi = (rotated >> 96) & 0xFFFFFFFF
        sk_lo = (rotated >> 64) & 0xFFFFFFFF
        subkeys.append((sk_hi, sk_lo))

    out = bytearray()
    for blk_idx in range(n_blocks):
        # Counter-mode plaintext
        pt = blk_idx.to_bytes(16, 'big')
        d1_hi = int.from_bytes(pt[:4], 'big')
        d1_lo = int.from_bytes(pt[4:8], 'big')
        d2_hi = int.from_bytes(pt[8:12], 'big')
        d2_lo = int.from_bytes(pt[12:16], 'big')

        # Pre-whitening
        d1_hi ^= subkeys[0][0]; d1_lo ^= subkeys[0][1]
        d2_hi ^= subkeys[1][0]; d2_lo ^= subkeys[1][1]

        # Feistel rounds
        actual_rounds = min(rounds, 18)
        for r in range(actual_rounds):
            sk_idx = (r + 2) % len(subkeys)
            f_hi, f_lo = _cam_f(d1_hi, d1_lo, subkeys[sk_idx][0], subkeys[sk_idx][1])
            d2_hi ^= f_hi; d2_lo ^= f_lo
            # Swap halves
            d1_hi, d1_lo, d2_hi, d2_lo = d2_hi, d2_lo, d1_hi, d1_lo

            # FL/FL^-1 layers after rounds 6 and 12
            if r == 5 and actual_rounds > 6:
                fl_idx = (r + 3) % len(subkeys)
                d1_hi, d1_lo = _cam_fl(d1_hi, d1_lo, subkeys[fl_idx][0], subkeys[fl_idx][1])
                d2_hi, d2_lo = _cam_flinv(d2_hi, d2_lo, subkeys[(fl_idx+1)%len(subkeys)][0],
                                           subkeys[(fl_idx+1)%len(subkeys)][1])
            elif r == 11 and actual_rounds > 12:
                fl_idx = (r + 3) % len(subkeys)
                d1_hi, d1_lo = _cam_fl(d1_hi, d1_lo, subkeys[fl_idx][0], subkeys[fl_idx][1])
                d2_hi, d2_lo = _cam_flinv(d2_hi, d2_lo, subkeys[(fl_idx+1)%len(subkeys)][0],
                                           subkeys[(fl_idx+1)%len(subkeys)][1])

        # Post-whitening (swap back last round's swap)
        d1_hi, d1_lo, d2_hi, d2_lo = d2_hi, d2_lo, d1_hi, d1_lo
        pw_idx = len(subkeys) - 2
        d1_hi ^= subkeys[pw_idx][0]; d1_lo ^= subkeys[pw_idx][1]
        d2_hi ^= subkeys[(pw_idx+1)%len(subkeys)][0]; d2_lo ^= subkeys[(pw_idx+1)%len(subkeys)][1]

        # Emit 16 bytes
        out.extend(d1_hi.to_bytes(4, 'big'))
        out.extend(d1_lo.to_bytes(4, 'big'))
        out.extend(d2_hi.to_bytes(4, 'big'))
        out.extend(d2_lo.to_bytes(4, 'big'))

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# ASCON (NIST SP 800-232 Lightweight Crypto Standard)
# Sponge-based AEAD, 320-bit state, 12/8 round permutation
# ═══════════════════════════════════════════════════════════════

def _ascon_round(x, rconst):
    """Single ASCON permutation round on 5 x 64-bit state words."""
    M64 = 0xFFFFFFFFFFFFFFFF
    # Addition of round constant
    x[2] ^= rconst
    # Substitution layer (5-bit S-box applied bitwise across all 64 positions)
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
    t = [(x[i] ^ M64) & x[(i + 1) % 5] for i in range(5)]
    for i in range(5):
        x[i] ^= t[(i + 1) % 5]
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] ^= M64
    # Linear diffusion layer
    def _rotr64(v, n):
        return ((v >> n) | (v << (64 - n))) & M64
    x[0] ^= _rotr64(x[0], 19) ^ _rotr64(x[0], 28)
    x[1] ^= _rotr64(x[1], 61) ^ _rotr64(x[1], 39)
    x[2] ^= _rotr64(x[2],  1) ^ _rotr64(x[2],  6)
    x[3] ^= _rotr64(x[3], 10) ^ _rotr64(x[3], 17)
    x[4] ^= _rotr64(x[4],  7) ^ _rotr64(x[4], 41)


# ASCON round constants (12 rounds max: 0xf0 down to 0x4b)
_ASCON_RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]


def _ascon_permutation(state, rounds=12):
    """Apply ASCON permutation p^rounds to 320-bit state."""
    x = list(state)
    start = 12 - rounds
    for i in range(rounds):
        _ascon_round(x, _ASCON_RC[start + i])
    return x


def generate_ascon_stream(count, rounds=12, seed=42):
    """Generate ASCON-based output with configurable permutation rounds.
    ASCON-128 uses a=12 rounds for initialization, b=8 for squeezing.
    We use 'rounds' for the squeeze permutation (full=12).
    Counter-mode: increment rate part, squeeze after each permutation."""
    rng = np.random.RandomState(seed)
    M64 = 0xFFFFFFFFFFFFFFFF

    # 128-bit key + 128-bit nonce
    key_bytes = rng.bytes(16)
    nonce_bytes = rng.bytes(16)
    K0 = int.from_bytes(key_bytes[:8], 'big')
    K1 = int.from_bytes(key_bytes[8:], 'big')
    N0 = int.from_bytes(nonce_bytes[:8], 'big')
    N1 = int.from_bytes(nonce_bytes[8:], 'big')

    # IV for ASCON-128: key size || rate || a || b || 0...
    # Simplified: 0x80400c0800000000 for ASCON-128 (128-bit key, 64-bit rate, a=12, b=8 originally)
    IV = 0x80400c0800000000

    # Initialize state: IV || K0 || K1 || N0 || N1
    state = [IV, K0, K1, N0, N1]
    state = _ascon_permutation(state, 12)  # Always 12 rounds for init
    state[3] ^= K0
    state[4] ^= K1

    out = bytearray()
    ctr = 0
    # Squeeze: rate = 64 bits (8 bytes), apply permutation with configurable rounds
    while len(out) < count * 32:
        # XOR counter into rate
        state[0] ^= ctr & M64
        state = _ascon_permutation(state, rounds)
        # Extract 8 bytes from rate
        out.extend(state[0].to_bytes(8, 'big'))
        ctr += 1

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# PRESENT (ISO/IEC 29167-11, ultra-lightweight SPN, 1000 GE)
# 64-bit block, 80-bit key, 31 rounds
# ═══════════════════════════════════════════════════════════════

_PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

_PRESENT_PERM = [
     0,16,32,48, 1,17,33,49, 2,18,34,50, 3,19,35,51,
     4,20,36,52, 5,21,37,53, 6,22,38,54, 7,23,39,55,
     8,24,40,56, 9,25,41,57,10,26,42,58,11,27,43,59,
    12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63,
]


def _present_key_schedule_80(key_80bit, rounds=31):
    """PRESENT-80 key schedule: 80-bit key register, extract 64 MSB per round."""
    rks = []
    reg = key_80bit & ((1 << 80) - 1)
    for i in range(rounds + 1):
        rks.append((reg >> 16) & 0xFFFFFFFFFFFFFFFF)
        # Rotate left 61
        reg = ((reg << 61) | (reg >> 19)) & ((1 << 80) - 1)
        # S-box on top 4 bits
        top4 = (reg >> 76) & 0xF
        reg = (reg & ((1 << 76) - 1)) | (_PRESENT_SBOX[top4] << 76)
        # XOR round counter into bits 19..15
        reg ^= ((i + 1) & 0x1F) << 15
    return rks


def _present_encrypt(block_64, rks, rounds=31):
    """PRESENT encryption: rounds of addRoundKey, sBoxLayer, pLayer."""
    state = block_64 & 0xFFFFFFFFFFFFFFFF
    for r in range(rounds):
        state ^= rks[r]
        # S-box layer: 16 nibbles
        new_state = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            new_state |= _PRESENT_SBOX[nibble] << (4 * i)
        state = new_state
        # Permutation layer
        pstate = 0
        for i in range(64):
            if state & (1 << i):
                pstate |= 1 << _PRESENT_PERM[i]
        state = pstate
    # Final addRoundKey
    state ^= rks[rounds]
    return state


def generate_present_stream(count, rounds=31, seed=42):
    """Generate PRESENT-80 encrypted output with configurable rounds.
    PRESENT uses 31 rounds (full). Block size: 64 bits."""
    rng = np.random.RandomState(seed)
    key_bytes = rng.bytes(10)  # 80-bit key
    key_80 = int.from_bytes(key_bytes, 'big')
    rks = _present_key_schedule_80(key_80, rounds)

    n_blocks = count * 4  # 8 bytes per block, 32 bytes per sample
    out = bytearray()
    for i in range(n_blocks):
        ct = _present_encrypt(i, rks, rounds)
        out.extend(ct.to_bytes(8, 'big'))

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# LEA (Lightweight Encryption Algorithm, Korean standard)
# ARX block cipher, 128-bit block, 128-bit key, 24 rounds
# ═══════════════════════════════════════════════════════════════

_LEA_DELTA = [
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7ae6631,
]

_M32 = 0xFFFFFFFF


def _lea_rol32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & _M32


def _lea_ror32(v, n):
    n = n % 32
    return ((v >> n) | (v << (32 - n))) & _M32


def _lea_key_schedule_128(key_u32, rounds=24):
    """LEA-128 key schedule: 4 x 32-bit key words, produces round keys."""
    T = list(key_u32)
    rks = []
    for i in range(rounds):
        delta = _LEA_DELTA[i % 4]
        rot_delta = _lea_rol32(delta, i)
        T[0] = _lea_rol32((T[0] + rot_delta) & _M32, 1)
        T[1] = _lea_rol32((T[1] + _lea_rol32(delta, i + 1)) & _M32, 3)
        T[2] = _lea_rol32((T[2] + _lea_rol32(delta, i + 2)) & _M32, 6)
        T[3] = _lea_rol32((T[3] + _lea_rol32(delta, i + 3)) & _M32, 11)
        rks.append((T[0], T[1], T[2], T[3]))
    return rks


def _lea_encrypt_128(block_u32, rks, rounds=24):
    """LEA-128 encryption: 4 x 32-bit block words."""
    X = list(block_u32)
    for i in range(rounds):
        rk = rks[i]
        tmp = [0, 0, 0, 0]
        tmp[0] = _lea_rol32(((X[0] ^ rk[0]) + (X[1] ^ rk[1])) & _M32, 9)
        tmp[1] = _lea_ror32(((X[1] ^ rk[2]) + (X[2] ^ rk[1])) & _M32, 5)
        tmp[2] = _lea_ror32(((X[2] ^ rk[3]) + (X[3] ^ rk[1])) & _M32, 3)
        tmp[3] = X[0]
        X = tmp
    return X


def generate_lea_stream(count, rounds=24, seed=42):
    """Generate LEA-128 encrypted output with configurable rounds.
    LEA-128 uses 24 rounds (full). Block size: 128 bits (16 bytes)."""
    rng = np.random.RandomState(seed)
    key_u32 = rng.randint(0, 2**32, size=4, dtype=np.uint32).tolist()
    rks = _lea_key_schedule_128([int(k) for k in key_u32], rounds)

    n_blocks = count * 2  # 16 bytes per block, 32 bytes per sample
    out = bytearray()
    for i in range(n_blocks):
        # Counter-mode plaintext
        pt = [
            (i >> 96) & _M32,
            (i >> 64) & _M32,
            (i >> 32) & _M32,
            i & _M32,
        ]
        ct = _lea_encrypt_128(pt, rks, rounds)
        for w in ct:
            out.extend(struct.pack('<I', w & _M32))

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# SIMON 32/64 (ISO/IEC 29167-21, Feistel, hardware-optimized)
# 32-bit block, 64-bit key, 32 rounds
# ═══════════════════════════════════════════════════════════════

_SIMON_Z = 0b11111010001001010110000111001101111101000100101011000011100110

def _simon_lshift16(v, n):
    return ((v << n) | (v >> (16 - n))) & 0xFFFF


def _simon_key_schedule_32_64(key_u16, rounds=32):
    """SIMON 32/64 key schedule: 4 x 16-bit key words, 32 rounds."""
    m = 4  # key words
    k = list(key_u16)  # k[0] = LSW
    for i in range(m, rounds):
        tmp = _simon_lshift16(k[i - 1], 16 - 3)  # ROR 3
        tmp ^= k[i - 3]
        tmp ^= _simon_lshift16(tmp, 16 - 1)  # ROR 1
        z_bit = (_SIMON_Z >> (61 - ((i - m) % 62))) & 1
        k.append(k[i - m] ^ tmp ^ 0xFFFC ^ z_bit)
    return k[:rounds]


def _simon_encrypt_32_64(block_l, block_r, rks, rounds=32):
    """SIMON 32/64 encryption: 2 x 16-bit halves."""
    x = block_l & 0xFFFF
    y = block_r & 0xFFFF
    for i in range(rounds):
        tmp = x
        f = (_simon_lshift16(x, 1) & _simon_lshift16(x, 8)) ^ _simon_lshift16(x, 2)
        x = (y ^ f ^ rks[i]) & 0xFFFF
        y = tmp
    return x, y


def generate_simon_stream(count, rounds=32, seed=42):
    """Generate SIMON 32/64 encrypted output with configurable rounds.
    SIMON 32/64 uses 32 rounds (full). Block size: 32 bits (4 bytes)."""
    rng = np.random.RandomState(seed)
    key_u16 = rng.randint(0, 2**16, size=4, dtype=np.uint16).tolist()
    rks = _simon_key_schedule_32_64([int(k) for k in key_u16], rounds)

    n_blocks = count * 8  # 4 bytes per block, 32 bytes per sample
    out = bytearray()
    for i in range(n_blocks):
        pt_l = (i >> 16) & 0xFFFF
        pt_r = i & 0xFFFF
        ct_l, ct_r = _simon_encrypt_32_64(pt_l, pt_r, rks, rounds)
        out.extend(struct.pack('>HH', ct_l, ct_r))

    return bytes(out[:count * 32])


# ═══════════════════════════════════════════════════════════════
# Grain-128a (LFSR+NFSR stream cipher, RFID deployment)
# 128-bit key, 96-bit IV, 256 init rounds + keystream
# ═══════════════════════════════════════════════════════════════

def _grain_bit(s, pos):
    return (s >> pos) & 1


def generate_grain128a_stream(count, rounds=256, seed=42):
    """Generate Grain-128a keystream with configurable init rounds.
    Full Grain-128a: 256 initialization rounds, then free-running.
    'rounds' controls the number of initialization clocks (full=256).
    Reduced init = weaker key/IV mixing."""
    rng = np.random.RandomState(seed)
    M128 = (1 << 128) - 1

    key_bytes = rng.bytes(16)
    iv_bytes = rng.bytes(12)  # 96-bit IV

    key_bits = int.from_bytes(key_bytes, 'big')
    iv_bits = int.from_bytes(iv_bytes, 'big')

    # LFSR: 128 bits, initialized with IV || 1...1 (32 ones)
    lfsr = (iv_bits << 32) | 0xFFFFFFFF
    # NFSR: 128 bits, initialized with key
    nfsr = key_bits

    def _lfsr_fb(s):
        """Grain-128a LFSR feedback: x^128 + x^96 + x^81 + x^70 + x^38 + x^7 + 1"""
        return _grain_bit(s, 0) ^ _grain_bit(s, 7) ^ _grain_bit(s, 38) ^ \
               _grain_bit(s, 70) ^ _grain_bit(s, 81) ^ _grain_bit(s, 96)

    def _nfsr_fb(s, lfsr_bit):
        """Grain-128a NFSR feedback (simplified — captures nonlinear mixing)."""
        fb = _grain_bit(s, 0) ^ _grain_bit(s, 26) ^ _grain_bit(s, 56) ^ \
             _grain_bit(s, 91) ^ _grain_bit(s, 96) ^ lfsr_bit
        # Nonlinear terms
        fb ^= _grain_bit(s, 3) & _grain_bit(s, 67)
        fb ^= _grain_bit(s, 11) & _grain_bit(s, 13)
        fb ^= _grain_bit(s, 17) & _grain_bit(s, 18)
        fb ^= _grain_bit(s, 27) & _grain_bit(s, 59)
        fb ^= _grain_bit(s, 40) & _grain_bit(s, 48)
        fb ^= _grain_bit(s, 61) & _grain_bit(s, 65)
        fb ^= _grain_bit(s, 68) & _grain_bit(s, 84)
        return fb & 1

    def _output_bit(nfsr, lfsr):
        """Grain-128a output function h(x) (simplified)."""
        # Filter function using NFSR and LFSR bits
        x0 = _grain_bit(nfsr, 2)
        x1 = _grain_bit(nfsr, 15)
        x2 = _grain_bit(nfsr, 36)
        x3 = _grain_bit(nfsr, 45)
        x4 = _grain_bit(nfsr, 64)
        x5 = _grain_bit(nfsr, 73)
        x6 = _grain_bit(nfsr, 89)
        # h function
        h = x0 & x1 ^ x2 & x3 ^ x4 & x5 ^ x6
        h ^= _grain_bit(lfsr, 93)
        # Additional XOR from NFSR
        h ^= _grain_bit(nfsr, 12) ^ _grain_bit(nfsr, 31) ^ _grain_bit(nfsr, 79) ^ _grain_bit(nfsr, 95)
        return h & 1

    def _clock(nfsr, lfsr, init=False):
        """Clock the cipher once. During init, output feeds back."""
        lfsr_fb = _lfsr_fb(lfsr)
        nfsr_fb = _nfsr_fb(nfsr, _grain_bit(lfsr, 0))
        z = _output_bit(nfsr, lfsr)

        if init:
            lfsr_fb ^= z
            nfsr_fb ^= z

        new_lfsr = ((lfsr >> 1) | (lfsr_fb << 127)) & M128
        new_nfsr = ((nfsr >> 1) | (nfsr_fb << 127)) & M128
        return new_nfsr, new_lfsr, z

    # Initialization phase
    init_rounds = min(rounds, 256)
    for _ in range(init_rounds):
        nfsr, lfsr, _ = _clock(nfsr, lfsr, init=True)

    # Generate keystream
    out = bytearray()
    needed = count * 32
    while len(out) < needed:
        byte_val = 0
        for bit in range(8):
            nfsr, lfsr, z = _clock(nfsr, lfsr, init=False)
            byte_val |= (z << bit)
        out.append(byte_val)

    return bytes(out[:needed])


# ═══════════════════════════════════════════════════════════════
# CIPHER REGISTRY
# ═══════════════════════════════════════════════════════════════

CIPHERS = {
    'chacha': {
        'name': 'ChaCha20',
        'family': 'ARX-stream',
        'full_rounds': 20,
        'generator': generate_chacha_stream,
        'frontier': 3,  # v0.6: R3 detectable via deep scoring (avalanche+differential)
        'demo_sequence': [
            (1,  'ChaCha20 R1 \u2014 no mixing'),
            (2,  'ChaCha20 R2 \u2014 partial ARX'),
            (3,  'ChaCha20 R3 \u2014 CASI frontier'),
            (20, 'ChaCha20 R20 \u2014 full security'),
        ],
        'test_rounds': [1, 3, 20],
        'slow': False,
    },
    'salsa': {
        'name': 'Salsa20',
        'family': 'ARX-stream',
        'full_rounds': 20,
        'generator': generate_salsa_stream,
        'frontier': 4,  # v0.6.1: R4 detectable via causal amplification (9/10 seeds at N=50K)
        'demo_sequence': [
            (1,  'Salsa20 R1 \u2014 no mixing'),
            (3,  'Salsa20 R3 \u2014 standard CASI frontier'),
            (4,  'Salsa20 R4 \u2014 amplified CASI frontier'),
            (20, 'Salsa20 R20 \u2014 full security'),
        ],
        'test_rounds': [1, 4, 20],
        'slow': False,
    },
    'aes': {
        'name': 'AES-128',
        'family': 'SPN-block',
        'full_rounds': 10,
        'generator': generate_aes_stream,
        'frontier': 3,
        'demo_sequence': [
            (1,  'AES-128 R1 \u2014 SubBytes only'),
            (2,  'AES-128 R2 \u2014 two rounds'),
            (3,  'AES-128 R3 \u2014 CASI frontier'),
            (10, 'AES-128 R10 \u2014 full security'),
        ],
        'test_rounds': [1, 3, 10],
        'slow': False,
    },
    'speck': {
        'name': 'Speck 32/64',
        'family': 'ARX-Feistel',
        'full_rounds': 22,
        'generator': generate_speck_stream,
        'frontier': 7,  # v0.6.2: R7 via chosen-plaintext rotational differential (0x2800,0x0010), 10/10 @ N=100K
        'demo_sequence': [
            (1,  'Speck R1 \u2014 trivial'),
            (3,  'Speck R3 \u2014 weak ARX'),
            (5,  'Speck R5 \u2014 standard CASI frontier'),
            (6,  'Speck R6 \u2014 amplified CASI frontier'),
            (7,  'Speck R7 \u2014 chosen-differential frontier'),
            (22, 'Speck R22 \u2014 full security'),
        ],
        'test_rounds': [1, 7, 22],
        'slow': False,
    },
    'blowfish': {
        'name': 'Blowfish',
        'family': 'Feistel-keydep',
        'full_rounds': 16,
        'generator': generate_blowfish_stream,
        'frontier': 3,  # v0.6: R3 detectable via deep scoring (avalanche+differential)
        'demo_sequence': [
            (1,  'Blowfish R1 \u2014 no diffusion'),
            (2,  'Blowfish R2 \u2014 classic frontier'),
            (3,  'Blowfish R3 \u2014 CASI deep frontier'),
            (16, 'Blowfish R16 \u2014 full security'),
        ],
        'test_rounds': [1, 3, 16],
        'slow': False,
    },
    'tdes': {
        'name': '3DES EDE',
        'family': 'Feistel-fixed',
        'full_rounds': 16,
        'generator': generate_tdes_stream,
        'frontier': 2,  # v0.6: R2 detectable (5/5 seeds), R3 drops to noise
        'demo_sequence': [
            (1,  '3DES R1 \u2014 trivial Feistel'),
            (2,  '3DES R2 \u2014 CASI frontier'),
            (3,  '3DES R3 \u2014 undetectable'),
            (16, '3DES R16 \u2014 full security'),
        ],
        'test_rounds': [1, 2, 16],
        'slow': True,  # pure Python, ~100x slower
    },
    'rc4': {
        'name': 'RC4',
        'family': 'byte-stream',
        'full_rounds': 256,
        'generator': generate_rc4_stream,
        'frontier': 64,
        'demo_sequence': [
            (8,   'RC4 KSA-8 \u2014 trivial schedule'),
            (32,  'RC4 KSA-32 \u2014 partial schedule'),
            (64,  'RC4 KSA-64 \u2014 quarter schedule'),
            (128, 'RC4 KSA-128 \u2014 half schedule'),
            (256, 'RC4 KSA-256 \u2014 full schedule'),
        ],
        'test_rounds': [8, 64, 256],
        'slow': True,  # per-byte Python loop
    },
    'camellia': {
        'name': 'Camellia-128',
        'family': 'SPN-Feistel',
        'full_rounds': 18,
        'generator': generate_camellia_stream,
        'frontier': 6,  # v0.6.1: R6 detectable via causal amplification (10/10 seeds at N=50K)
        'demo_sequence': [
            (1,  'Camellia R1 \u2014 single F-round'),
            (3,  'Camellia R3 \u2014 partial diffusion'),
            (5,  'Camellia R5 \u2014 standard CASI frontier'),
            (6,  'Camellia R6 \u2014 amplified CASI frontier'),
            (18, 'Camellia R18 \u2014 full security'),
        ],
        'test_rounds': [1, 6, 18],
        'slow': True,  # per-block Python loop
    },
    # ── Nano-IoT Ciphers (v0.10) ──────────────────────────────
    'ascon': {
        'name': 'ASCON',
        'family': 'Sponge-LWC',
        'full_rounds': 12,
        'generator': generate_ascon_stream,
        'frontier': None,  # TBD — first CASI characterization
        'nano_deployment': 'NIST SP 800-232, 2500 GE, nano-medical/WSN/RFID',
        'demo_sequence': [
            (1,  'ASCON R1 \u2014 single permutation'),
            (3,  'ASCON R3 \u2014 partial diffusion'),
            (6,  'ASCON R6 \u2014 half rounds'),
            (8,  'ASCON R8 \u2014 standard b-rounds'),
            (12, 'ASCON R12 \u2014 full permutation'),
        ],
        'test_rounds': [1, 2, 3, 4, 6, 8, 12],
        'slow': False,
    },
    'present': {
        'name': 'PRESENT-80',
        'family': 'SPN-ultralight',
        'full_rounds': 31,
        'generator': generate_present_stream,
        'frontier': None,  # TBD
        'nano_deployment': 'ISO/IEC 29167-11 RFID, 1000 GE, NFC nano-tags',
        'demo_sequence': [
            (1,  'PRESENT R1 \u2014 single SPN round'),
            (4,  'PRESENT R4 \u2014 partial diffusion'),
            (8,  'PRESENT R8 \u2014 mid-range'),
            (16, 'PRESENT R16 \u2014 half rounds'),
            (31, 'PRESENT R31 \u2014 full security'),
        ],
        'test_rounds': [1, 2, 4, 8, 16, 31],
        'slow': True,  # per-block bitwise Python
    },
    'lea': {
        'name': 'LEA-128',
        'family': 'ARX-block',
        'full_rounds': 24,
        'generator': generate_lea_stream,
        'frontier': None,  # TBD — ARX cipher, CASI's core competency
        'nano_deployment': 'Korean WBAN e-Health standard, body area networks',
        'demo_sequence': [
            (1,  'LEA R1 \u2014 single ARX round'),
            (4,  'LEA R4 \u2014 partial mixing'),
            (8,  'LEA R8 \u2014 mid-range'),
            (12, 'LEA R12 \u2014 half rounds'),
            (24, 'LEA R24 \u2014 full security'),
        ],
        'test_rounds': [1, 2, 4, 8, 12, 24],
        'slow': True,  # per-block Python
    },
    'simon': {
        'name': 'SIMON 32/64',
        'family': 'Feistel-LWC',
        'full_rounds': 32,
        'generator': generate_simon_stream,
        'frontier': None,  # TBD — Speck's sister cipher
        'nano_deployment': 'ISO/IEC 29167-21 RFID, hardware-optimized',
        'demo_sequence': [
            (1,  'SIMON R1 \u2014 single Feistel'),
            (4,  'SIMON R4 \u2014 partial diffusion'),
            (8,  'SIMON R8 \u2014 quarter rounds'),
            (16, 'SIMON R16 \u2014 half rounds'),
            (32, 'SIMON R32 \u2014 full security'),
        ],
        'test_rounds': [1, 2, 4, 8, 16, 32],
        'slow': True,  # per-block Python
    },
    'grain': {
        'name': 'Grain-128a',
        'family': 'LFSR-NFSR-stream',
        'full_rounds': 256,
        'generator': generate_grain128a_stream,
        'frontier': None,  # TBD — only commercial RFID stream cipher
        'nano_deployment': 'Honeywell IT70 RFID, automotive passive tags',
        'demo_sequence': [
            (16,  'Grain-128a Init-16 \u2014 minimal mixing'),
            (64,  'Grain-128a Init-64 \u2014 quarter init'),
            (128, 'Grain-128a Init-128 \u2014 half init'),
            (256, 'Grain-128a Init-256 \u2014 full init'),
        ],
        'test_rounds': [16, 64, 128, 256],
        'slow': True,  # bit-serial Python
    },
}
