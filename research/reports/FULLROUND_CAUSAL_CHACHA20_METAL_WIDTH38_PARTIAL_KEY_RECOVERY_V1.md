# ChaCha20 Metal Full-Round 38-Bit Partial-Key Recovery v1

## Result

A183 performs a genuinely fresh, prospectively frozen, exhaustive 38-bit
partial-key recovery against the standard ChaCha20 block function. Key word 0
and the low six bits of key word 1 are unknown; the other 218 key bits,
counter, nonce, and complete 512-bit block output are public.

The native Apple M4 Metal Reader executes every one of the `2^38` assignments
through all 20 rounds plus standard feedforward and returns one exact model:

| Quantity | Result |
|---|---:|
| unknown key bits | 38 |
| known key bits | 218 |
| logical assignments | 274,877,906,944 |
| outer key-word-1 low-bit slices | 64 |
| key-word-0 candidates per slice | 4,294,967,296 |
| Metal batches per slice | 16 |
| total Metal batches | 1,024 |
| resumed assignments | 0 |
| combined assignment | **112,033,414,660 (`0x1a15b63e04`)** |
| recovered key word 0 | **364,264,964 (`0x15b63e04`)** |
| recovered key word 1 low six bits | **26 (`0x1a`)** |
| control matches | 0 |
| independent confirmation | all 512 bits exact |

This is complete exhaustive fullround 38-bit partial-key recovery in the exact
declared scope. It is not a claim of full 256-bit ChaCha20 key recovery.

## Fresh prospective challenge

The A183 protocol was frozen before any candidate execution. Its SHA-256 is:

```text
91b7c70a9849b3c1e39ea51fe806b2e488db811b6672de7e7046a6319c155dcd
```

The new public challenge has canonical SHA-256:

```text
6130449831103acf9f34dcf74ce9b24f6f24cc0273c271351fcbc9c5121af9d4
```

It is a new A183 target whose known-material derivation is domain-separated
and anchored to the retained A182 result. The derivation uses SHAKE256 over:

```text
f8-causal:A183:chacha20:known-material:8450a334209f7bb78610439d604c6bc9ac69213f4f0d6c7f6068dfd07cd708e3
```

The 44 derived bytes reproduce exactly:

- the upper 26 known bits of key word 1;
- all six key words 2 through 7;
- the 32-bit counter;
- all three nonce words.

Their byte digest is
`115c80b7de288e9e3c1aef9024a060ad5ec33fe075426d6dcb95de049f4479ec`.

The unknown 38-bit assignment is generated once from operating-system
cryptographic randomness, used only to create the public target, and discarded
before runner construction. The combined assignment, recovered word 0, and
their hexadecimal spellings are absent from the protocol, runner, and unchanged
Metal source. The pre-execution grep gate verifies that absence.

The complete factual target digest is:

```text
d18e7c82b4aa873282c65b7ea22c436597865264048a18cf72253640078a1f09
```

The control flips only bit zero of output word zero and has digest:

```text
4e7d7aa7221e1b25a1937d8c448f39a33c7967ec13d1d1f8984c454993c5530c
```

The predeclared prediction is one complete-block assignment and zero control
assignments after exhaustive `2^38` enumeration.

## Exact assignment encoding

A183 decomposes the 38-bit domain into 64 complete 32-bit slices:

```text
combined = (key_word1_low_value << 32) | key_word0
```

For each six-bit value from 0 through 63, the persistent Metal host is
reconfigured with that value in initial lane 5, while lane 4 traverses every
unsigned 32-bit word. The mapping is bijective over all 274,877,906,944
assignments.

The frozen execution plan has SHA-256:

```text
0464807aaa9dcb1641587bd70295ae2ce4ac99973ce7d4fb78d7cd60e1b3cc31
```

## Unchanged Metal host and mapping qualification

A183 reuses the exact A181/A182 Swift/Metal source without modification,
SHA-256:

```text
ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816
```

Swift compilation retains optimization, whole-module optimization, and
`-warnings-as-errors`. The host identity gate requires version
`chacha20-metal-native-v1`, device `Apple M4`, Metal execution width 32, and
runtime shader compilation.

Before any public-target candidate execution, the two-word assignment mapping
is tested synthetically at outer values 0, 31, and 63. Each slice evaluates 256
word-0 candidates starting at 183,032 and compares complete 512-bit Metal
blocks with the independent NumPy RFC implementation. The gate covers:

- 768 logical assignments;
- 393,216 complete output bits;
- the first, interior, and final outer-slice regions;
- exact combined-assignment reconstruction;
- empty one-bit-flipped controls.

Every block and assignment mapping agrees exactly.

## Complete `2^38` execution

The persistent Metal process evaluates 268,435,456 candidates per batch. Each
outer low-bit slice therefore contains 16 batches, giving 1,024 batches over
the complete domain. One GPU logical thread executes one standard ChaCha20
block; the first two output words provide the 64-bit factual/control filter.

All 274,877,906,944 assignments execute freshly. No assignment is resumed and
there is no early stop. The filter returns exactly combined assignment
112,033,414,660. A separate NumPy implementation reconstructs word 0 and the
word-1 low six-bit value, executes all 20 rounds plus feedforward, and compares
all 16 output words. All 512 bits match the public target.

The canonical execution digest is:

```text
e29673909dd5c36b31b91771379eef1cb6535cde8be42f67eb6a7669d29765a2
```

The canonical factual/control confirmation digest is:

```text
a62ebadd0deb550ac35808d15559244deb60cfec1dee824be84a937d02c12e9c
```

The control target returns no filter or full-block match. The completed
checkpoint is removed after final JSON and Causal validation.

## Causal Reader chain

The retained Causal artifact contains five explicit edges:

1. A182 verified fresh 36-bit recovery anchor;
2. fresh prospectively frozen A183 38-bit public challenge;
3. three-slice 393,216-bit assignment-mapping gate;
4. complete 64-slice, 1,024-batch `2^38` execution;
5. independent 512-bit recovery confirmation.

The edges form one direct provenance chain with no inferred edges.
`CryptoCausalReader` verifies:

- result JSON:
  `68d4396e8c064baa2385467cfd5dd7d9aee06014d40f87ee6dfdb8c3d253be7d`;
- Causal artifact:
  `2f82b26e85595f50895f159db95562fa872d373b10e5f303f73ca2947ba51688`;
- canonical Causal graph:
  `c96230676d20de6d3b791cfc4d6a3436a17ee7e9047bd38ff62a8ca146265f6f`;
- A182 result anchor:
  `8450a334209f7bb78610439d604c6bc9ac69213f4f0d6c7f6068dfd07cd708e3`;
- A182 Causal anchor:
  `aad208518d6718cac73937c198d0919c0e6305a56ac8a43345d02155eefdb110`.

## Timing provenance

The observed local end-to-end command wall-clock was 189.66 seconds. It covers
Swift compilation, runtime Metal shader compilation, host gates, all 1,024
complete-domain batches, checkpoint writes, independent 512-bit confirmation,
and final artifact construction and reopen checks.

This is volatile, noncanonical local execution context. It is excluded from
the canonical result and is not a cross-machine benchmark guarantee.

## Reproduction

Fast hash, analyze, public-derivation, secret-absence, Swift warnings-as-errors,
host-identity, synthetic three-slice mapping, retained-result, and Causal gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width38_partial_key_recovery.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_metal_width38_partial_key_recovery.py
```

Fresh checkpointable exhaustive `2^38` execution on the bound Apple M4 host:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width38_partial_key_recovery.py
```

## Consequence

A183 advances the fresh prospective partial-key frontier from 36 to 38 unknown
bits under standard fullround ChaCha20 semantics. It exhausts
274,877,906,944 assignments, recovers one exact two-word partial assignment,
rejects the control, and independently confirms all 512 output bits. The result
is exhaustive 38-bit partial-key recovery with 218 key bits known, not full-key
recovery.
