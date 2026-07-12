# ChaCha20 Metal Full-Round 36-Bit Partial-Key Recovery v1

## Result

A182 performs a genuinely fresh, prospectively frozen, exhaustive 36-bit
partial-key recovery against the standard ChaCha20 block function.  Key word 0
and the low nibble of key word 1 are unknown; the other 220 key bits, counter,
nonce, and complete 512-bit block output are public.

The native Apple M4 Metal Reader executes every one of the `2^36` assignments
through all 20 rounds plus standard feedforward and returns one exact model:

| Quantity | Result |
|---|---:|
| unknown key bits | 36 |
| known key bits | 220 |
| logical assignments | 68,719,476,736 |
| outer key-word-1 nibble slices | 16 |
| key-word-0 candidates per slice | 4,294,967,296 |
| Metal batches per slice | 16 |
| total Metal batches | 256 |
| resumed assignments | 0 |
| combined assignment | **12,995,408,051 (`0x3069630b3`)** |
| recovered key word 0 | **110,506,163 (`0x069630b3`)** |
| recovered key word 1 low nibble | **3** |
| control matches | 0 |
| independent confirmation | all 512 bits exact |

This is complete exhaustive fullround 36-bit partial-key recovery in the exact
declared scope.  It is not a claim of full 256-bit ChaCha20 key recovery.

## Fresh prospective challenge

The A182 protocol was frozen before any candidate execution.  Its SHA-256 is:

```text
8c69a87b101f7f7e718b1c162a96798484f1bc6f252775c69f197c2770c72bfc
```

The new public challenge has canonical SHA-256:

```text
b129968a51b2b1693181038da390b5d50c665e60b4721c65b7e81a84f81af27e
```

It is derived independently from the A181 result anchor and is not the A178
target replayed again.  The known material derivation uses SHAKE256 over:

```text
f8-causal:A182:chacha20:known-material:f58e24cdb76a90ce8cd0ea2a14adce98ffa8f760707f9ea169d5a8d2748bacee
```

The 44 derived bytes reproduce exactly:

- the upper 28 known bits of key word 1;
- all six key words 2 through 7;
- the 32-bit counter;
- all three nonce words.

Their byte digest is
`7a3b211ff000f9887612e64c03af199f76aaed5e836296a08673622ec1ebc591`.

The unknown 36-bit assignment is generated once from operating-system
cryptographic randomness, used only to create the public target, and discarded
before runner construction.  The combined assignment, recovered word 0, and
hexadecimal spellings are absent from the protocol, runner, and unchanged Metal
source.  The pre-execution grep gate verifies that absence.

The complete factual target digest is:

```text
b1de7d354eb0c3707a37cefac54f8ede5233310a245f6d69e6c0e112d02de509
```

The control flips only bit zero of output word zero and has digest:

```text
ebe207cfa4c7baae79be17bcaac3106c2b333915bc623095a06862f6a498f951
```

The predeclared prediction is one complete-rate assignment and zero control
assignments after exhaustive `2^36` enumeration.

## Exact assignment encoding

A182 decomposes the 36-bit domain into 16 complete 32-bit slices:

```text
combined = (key_word1_low_nibble << 32) | key_word0
```

For each nibble from 0 through 15, the persistent Metal host is reconfigured
with that nibble in initial lane 5, while lane 4 traverses every unsigned
32-bit word.  The mapping is bijective over all 68,719,476,736 assignments.

The frozen execution plan has SHA-256:

```text
d38b357697268ec6e953b0ddc62f975040205dd5e6a987e618b810ab4a0fb028
```

## Unchanged Metal host and mapping qualification

A182 reuses the exact A181 Swift/Metal source without modification, SHA-256:

```text
ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816
```

Swift compilation retains optimization, whole-module optimization, and
`-warnings-as-errors`.  The host identity gate requires version
`chacha20-metal-native-v1`, device `Apple M4`, Metal execution width 32, and
runtime shader compilation.

Before any public-target candidate execution, the two-word assignment mapping
is tested synthetically at outer nibbles 0, 7, and 15.  Each slice evaluates 256
word-0 candidates starting at 182,032 and compares complete 512-bit Metal blocks
with the independent NumPy RFC implementation.  The gate covers:

- 768 logical assignments;
- 393,216 complete output bits;
- the first, interior, and final outer-nibble regions;
- exact combined-assignment reconstruction;
- empty one-bit-flipped controls.

Every block and assignment mapping agrees exactly.

## Complete `2^36` execution

The persistent Metal process evaluates 268,435,456 candidates per batch.  Each
outer nibble slice therefore contains 16 batches, giving 256 batches over the
complete domain.  One GPU logical thread executes one standard ChaCha20 block;
the first two output words provide the 64-bit factual/control filter.

All 68,719,476,736 assignments execute freshly.  No assignment is resumed and
there is no early stop.  The filter returns exactly combined assignment
12,995,408,051.  A separate NumPy implementation reconstructs word 0 and the
word-1 low nibble, executes all 20 rounds plus feedforward, and compares all 16
output words.  All 512 bits match the public target.

The canonical execution digest is:

```text
bbff0b5f615e41b9397b61a2324451df1f61780576e928a41f71df05412c4c26
```

The canonical factual/control confirmation digest is:

```text
81baeb0ab4d6e8182a717ad08aa85c052cac84c61adc25ab23af041a084b9893
```

The control target returns no filter or full-block match.  The completed
checkpoint is removed after final JSON and Causal validation.

## Causal Reader chain

The retained Causal artifact contains five explicit edges:

1. A181 verified Metal complete-domain anchor;
2. fresh prospectively frozen A182 36-bit public challenge;
3. three-slice 393,216-bit assignment-mapping gate;
4. complete 16-slice, 256-batch `2^36` execution;
5. independent 512-bit recovery confirmation.

The edges form one direct provenance chain with no inferred edges.
`CryptoCausalReader` verifies:

- result JSON:
  `8450a334209f7bb78610439d604c6bc9ac69213f4f0d6c7f6068dfd07cd708e3`;
- Causal artifact:
  `aad208518d6718cac73937c198d0919c0e6305a56ac8a43345d02155eefdb110`;
- canonical Causal graph:
  `be83fdf5fc214cc21230c08c51178e2a4290814d94db62fc100766e75dd6db86`;
- A181 result anchor:
  `f58e24cdb76a90ce8cd0ea2a14adce98ffa8f760707f9ea169d5a8d2748bacee`;
- A181 Causal anchor:
  `b16a7a2fc0fc78084443ee5ada8fb9a2c6fa9149f5b6333d98764401a07f662e`.

## Timing provenance

The observed local end-to-end command wall-clock was 48.72 seconds.  It covers
Swift compilation, runtime Metal shader compilation, host gates, all 256
complete-domain batches, checkpoint writes, independent 512-bit confirmation,
and final artifact construction and reopen checks.

This is volatile, noncanonical local execution context.  It is excluded from
the canonical result and is not a cross-machine benchmark guarantee.

## Reproduction

Fast hash, analyze, public-derivation, secret-absence, Swift warnings-as-errors,
host-identity, synthetic three-slice mapping, retained-result, and Causal gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width36_partial_key_recovery.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_metal_width36_partial_key_recovery.py
```

Fresh checkpointable exhaustive `2^36` execution on the bound Apple M4 host:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width36_partial_key_recovery.py
```

## Consequence

A182 advances the fresh prospective partial-key frontier from 32 to 36 unknown
bits under standard fullround ChaCha20 semantics.  It exhausts 68,719,476,736
assignments, recovers one exact two-word partial assignment, rejects the control,
and independently confirms all 512 output bits.  The result is exhaustive
36-bit partial-key recovery with 220 key bits known, not full-key recovery.
