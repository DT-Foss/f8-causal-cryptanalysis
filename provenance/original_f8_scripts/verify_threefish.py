#!/usr/bin/env python3
"""Verify Threefish-256 implementation against pyskein reference."""
import struct

mask64 = (1 << 64) - 1
C240 = 0x1BD11BDAA9FC1A22

TF256_ROTATIONS = [
    [14, 16], [52, 57], [23, 40], [5, 37],
    [25, 33], [46, 12], [58, 22], [32, 32],
]

def threefish256_encrypt(pt_words, key_words, tweak_words, n_rounds=72):
    ks = list(key_words) + [0]
    ks[4] = C240
    for i in range(4):
        ks[4] ^= ks[i]

    tw = list(tweak_words) + [0]
    tw[2] = tw[0] ^ tw[1]

    v = list(pt_words)

    # Initial key injection (s=0)
    v[0] = (v[0] + ks[0]) & mask64
    v[1] = (v[1] + ks[1] + tw[0]) & mask64
    v[2] = (v[2] + ks[2] + tw[1]) & mask64
    v[3] = (v[3] + ks[3]) & mask64

    for r in range(n_rounds):
        d = r % 8
        rot = TF256_ROTATIONS[d]

        # MIX(0,1)
        v[0] = (v[0] + v[1]) & mask64
        v[1] = ((v[1] << rot[0]) | (v[1] >> (64 - rot[0]))) & mask64
        v[1] ^= v[0]

        # MIX(2,3)
        v[2] = (v[2] + v[3]) & mask64
        v[3] = ((v[3] << rot[1]) | (v[3] >> (64 - rot[1]))) & mask64
        v[3] ^= v[2]

        # Word permutation: swap words 1 and 3
        v[1], v[3] = v[3], v[1]

        # Key injection every 4 rounds
        if (r + 1) % 4 == 0:
            s = (r + 1) // 4
            v[0] = (v[0] + ks[s % 5]) & mask64
            v[1] = (v[1] + ks[(s + 1) % 5] + tw[s % 3]) & mask64
            v[2] = (v[2] + ks[(s + 2) % 5] + tw[(s + 1) % 3]) & mask64
            v[3] = (v[3] + ks[(s + 3) % 5] + s) & mask64

    return v


# Test 1: All zeros
pt = [0, 0, 0, 0]
key = [0, 0, 0, 0]
tweak = [0, 0]

result = threefish256_encrypt(pt, key, tweak)
expected = [0x94eeea8b1f2ada84, 0xadf103313eae6670, 0x952419a1f4b16d53, 0xd83f13e63c9f6b11]

print("Test 1: All zeros (72 rounds)")
print("My implementation:")
for i, w in enumerate(result):
    print(f"  v[{i}] = 0x{w:016x}")
print("Expected (pyskein):")
for i, w in enumerate(expected):
    print(f"  v[{i}] = 0x{w:016x}")

match = all(result[i] == expected[i] for i in range(4))
print(f"MATCH: {match}")

if not match:
    for i in range(4):
        status = "OK" if result[i] == expected[i] else "MISMATCH"
        print(f"  v[{i}]: {status}")

# Test 2: Sequential key
key2_bytes = bytes(range(1, 33))
key2_words = list(struct.unpack('<4Q', key2_bytes))
result2 = threefish256_encrypt(pt, key2_words, tweak)
expected2 = [0xe894160e827bb3d4, 0xde12213be83d70ba, 0x2b035298135ccaff, 0xa7dfcaa344fc69f1]

print("\nTest 2: Sequential key (72 rounds)")
print("My implementation:")
for i, w in enumerate(result2):
    print(f"  v[{i}] = 0x{w:016x}")
print("Expected (pyskein):")
for i, w in enumerate(expected2):
    print(f"  v[{i}] = 0x{w:016x}")

match2 = all(result2[i] == expected2[i] for i in range(4))
print(f"MATCH: {match2}")

if not match and not match2:
    print("\nBOTH TESTS FAILED — implementation is WRONG")
elif match and match2:
    print("\nBOTH TESTS PASSED — implementation is CORRECT")
