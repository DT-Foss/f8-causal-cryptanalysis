# ChaCha20 Metal Full-Round Complete-Domain Replay v1

## Result

A181 prospectively freezes an Apple M4 Metal execution path and replays the
complete known A178/A179 ChaCha20 challenge.  The persistent GPU host executes
all `2^32` candidate key words through the standard 20-round block function
plus feedforward in 16 batches, returns the exact retained word `0x903db747`,
rejects the bit-flipped control, and independently confirms all 512 output
bits.

| Quantity | Result |
|---|---:|
| logical candidates | 4,294,967,296 |
| Metal logical threads | 4,294,967,296 |
| candidates per batch | 268,435,456 |
| complete batches | 16 |
| resumed candidates | 0 |
| freshly executed candidates | 4,294,967,296 |
| factual filter/full match | **2,419,963,719 (`0x903db747`)** |
| control filter/full matches | 0 |
| independent confirmation | 512 bits exact |

A181 is a prospectively frozen Metal complete-domain equivalence and execution
acceleration on a known challenge.  It is not a new blind partial-key recovery:
the A179 result is known at protocol freeze, is never used to prune or stop GPU
enumeration, and is compared only after the complete domain has executed.

## Frozen protocol

The A181 protocol SHA-256 is:

```text
9bc042c28256d3da46b9c1f5cf0b7d81b52035d0df67d40d7d32848492eaef2d
```

It is frozen after small semantic and throughput qualification gates and before
any A181 complete-domain execution.  The predeclared success rule requires:

- execution of all `2^32` assignments;
- exact identity with the A179 recovered word;
- no bit-flipped-control model;
- independent confirmation over all 512 output bits;
- no early stopping.

The challenge remains byte-for-byte the A178 public relation, SHA-256
`58f9244e4a41f2e04f7d6350c628c40feafa252affdcdb25b0a2699862a57b48`.
It contains 224 known key bits, counter, nonce, and complete block output while
key word 0 remains the enumerated 32-bit coordinate.

The retained A179 anchors are:

- result JSON:
  `73874897bf3747a0c640e00e5325f9c0502d2db7b77f6fe01590c87494f7fb93`;
- Causal artifact:
  `ab627294751d40647d3b1c9d5f20d852195d64fa449dea761b8cad15b24291a1`;
- canonical graph:
  `1681bf6f2647e7545a2f56163774ac7e4220fc0df171dbc9569e7eda63c5957d`.

## Swift/Metal native host

The native host source SHA-256 is:

```text
ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816
```

Swift compiles with optimization, whole-module optimization, and
`-warnings-as-errors`.  The persistent process runtime-compiles its Metal
shader, exposes JSON request/response operations for block and filter calls,
and is accepted only when its identity reports:

- version `chacha20-metal-native-v1`;
- device `Apple M4`;
- Metal filter execution width 32;
- at least 256 threads per threadgroup;
- runtime shader compilation enabled.

The shader executes the RFC 8439 ChaCha20 layout, rotation tuple
`(16, 12, 8, 7)`, ten double rounds, and wordwise initial-state feedforward.
The retained RFC known-answer test matches byte-for-byte.

## Pre-freeze semantic gates

Two exact small-domain gates qualify the Metal path before the protocol freeze:

1. **256-block cross gate.**  Starting at candidate 123,456,789, Metal and the
   independent NumPy RFC implementation agree on all 4,096 words and 131,072
   output bits.  The fixed output digest is
   `eacb62b978ae444278f0034793ce5ad9c31bfdbed02735053f1b2697d9e8600c`.
2. **Three boundary filters.**  The first 256 candidates, the 256-candidate
   interval containing `0x903db747`, and the final 256 candidates through
   `0xffffffff` return exactly the frozen factual/control sets.  Across all 768
   checked candidates, only the middle interval contains the factual word and
   every control set is empty.

The host identity, Swift warnings-as-errors compilation, 256-block cross gate,
and three boundary filters are repeated by the retained test suite without
starting the complete-domain runner.

## Pre-freeze throughput qualification

The protocol records a five-repetition qualification probe over 268,435,456
candidates with a stable local median of approximately
1.469 billion candidates per second.  This number is explicitly volatile and
is not part of the prospective success rule or canonical result.  Its role is
implementation qualification before committing to the complete-domain run.

## Complete-domain execution

The frozen execution plan uses one logical GPU thread per candidate, 256 threads
per threadgroup, and 16 batches of 268,435,456 candidates.  A persistent host
keeps the runtime-compiled shader and configured public challenge alive across
all batches.  The factual and control filters compare the first two block words,
or 64 bits, and every survivor is independently checked over all 16 output words.

The execution-plan digest is:

```text
49607cf3600a9f59bc41984094a5ee33bea30511817056f1543735ab72737cda
```

All 4,294,967,296 candidates execute freshly with no early stop.  The factual
filter and independent complete-block confirmation return only
2,419,963,719 (`0x903db747`).  Its complete block digest is the frozen target:

```text
0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae
```

The control returns no filter or full match.  The canonical execution digest is:

```text
9e51013009ae313ee00ea624cd4a81e0e4fe3e8ef319cd4daf2a8e9cd66cf3a6
```

The canonical A179/A181 equivalence digest is:

```text
e02b59ec226de5cf37792b0ca03b3b4e1695c3396ad83eb9a4485eb960577004
```

Checkpoint/resume binds protocol, source, public relation, target/control,
unknown lane, width, batch size, and result capacity.  The retained run resumes
zero candidates, and its completed checkpoint is removed after final artifact
validation.

## Causal Reader chain

The retained Causal artifact contains five explicit edges:

1. A179 complete-domain anchor;
2. A181 Metal protocol freeze;
3. native host identity and small semantic gates;
4. complete 16-batch Metal replay;
5. exact A179 recovery identity, control rejection, and 512-bit confirmation.

The edges form one direct provenance chain with no inferred edges.
`CryptoCausalReader` verifies:

- result JSON:
  `f58e24cdb76a90ce8cd0ea2a14adce98ffa8f760707f9ea169d5a8d2748bacee`;
- Causal artifact:
  `b16a7a2fc0fc78084443ee5ada8fb9a2c6fa9149f5b6333d98764401a07f662e`;
- canonical Causal graph:
  `00e13f58cdb6382c390a978401dc3a6217d98dcc1fa608f96fc6cec37fa5c1a8`.

## Timing provenance

The observed local full command wall-clock was 4.66 seconds.  This includes
Swift compilation, runtime Metal shader compilation, host identity and semantic
gates, all 16 complete-domain batches, checkpoint writes, independent
confirmation, and final JSON/Causal construction and reopen checks.

The 4.66-second observation is volatile and noncanonical.  It is retained as
local execution context, not as a cross-machine benchmark guarantee.  The
scientific object is the prospectively frozen complete-domain Metal equivalence;
the timing is excluded from its canonical digest.

## Reproduction

Fast hash, analyze, Swift warnings-as-errors, host identity, 256-block,
three-boundary, synthetic-resume, retained-result, and Causal gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_fullround_replay.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_metal_fullround_replay.py
```

Fresh checkpointable complete-domain Metal replay on the bound Apple M4 host:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_fullround_replay.py
```

## Consequence

A181 establishes exact complete-domain equivalence between the retained A179
result and the native Apple M4 Metal execution path.  It covers every 32-bit key
word, preserves the exact factual and control sets, and independently confirms
the full 512-bit output while completing the entire integrated command in the
observed local 4.66-second run.
