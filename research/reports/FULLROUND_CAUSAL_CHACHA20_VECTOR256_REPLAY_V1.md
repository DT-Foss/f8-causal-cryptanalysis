# ChaCha20 Vector-256 Full-Round Complete-Domain Replay v1

## Result

A179 prospectively freezes and executes a four-sublane vector representation
for the complete A178 ChaCha20 challenge.  It replays all `2^32` candidate key
words through the standard 20-round block function plus feedforward, reproduces
the exact A178 match `0x903db747`, rejects the bit-flipped control, and reduces
the number of native vector states exactly fourfold.

| Quantity | A178 uint64 Reader | A179 vector-256 Reader |
|---|---:|---:|
| logical candidates | 4,294,967,296 | 4,294,967,296 |
| candidates per native state | 64 | 256 |
| native states | 67,108,864 | 16,777,216 |
| stream batches | 64 | 64 |
| resumed states | 0 | 0 |
| factual filter/full match | `0x903db747` | `0x903db747` |
| control matches | 0 | 0 |

The exact structural reduction is:

```text
67,108,864 / 16,777,216 = 4
```

A179 is a prospectively frozen complete-domain equivalence and packing advance
on the already known A178 challenge.  It is not presented as a new blind
partial-key recovery: the A178 recovered word is known when the A179 protocol
is frozen, is never used to prune or stop enumeration, and enters only after
complete execution for the equivalence gate.

## Frozen protocol and information boundary

The A179 protocol SHA-256 is:

```text
fc552a21f14a827293996cdff6707dd7b31ac6ffdcc18cc55ac45b624d784e40
```

It was frozen after small implementation-qualification gates and before any
A179 complete-domain execution.  The predeclared success rule requires:

- complete execution of all `2^32` assignments;
- exact recovery identity with A178;
- rejection of the identical A178 bit-flipped control;
- exactly fourfold reduction in vector-state count;
- no early stopping.

The public challenge is byte-for-byte the A178 challenge with canonical digest
`58f9244e4a41f2e04f7d6350c628c40feafa252affdcdb25b0a2699862a57b48`.
It remains the standard ChaCha20 setting with one 32-bit key word unknown, the
other 224 key bits plus counter and nonce known, and the complete 512-bit block
output public.

The A178 anchors are:

- result JSON:
  `80fee52a0a2222efab161d74eb7ee124f6d94b56ca0cf759c5ffc4ca2881bea1`;
- Causal artifact:
  `94c651c6ea5432f482c054ae6d839c84563e8eae81e98625beb158344da16995`;
- uint64 native source:
  `ec2759fc66e86b7b50ea7fece66b2994d1961bb5b84d9081aff3514f25cacb8e`.

## Vector-256 native representation

The A179 C11 kernel represents 256 logical candidates as four `uint64_t`
sublanes inside one 256-bit compiler vector.  Candidate bits 0 through 5 vary
within each sublane, bits 6 and 7 select the four sublanes, and bits 8 through
31 come from the vector-state index.  This covers every unsigned 32-bit value
exactly once.

The vector source SHA-256 is:

```text
4b4807911580831d0f7925cd74c886694d3d6b19e30be2f0e21a602a6e6ba9dc
```

Compilation is fail-closed under C11/POSIX threads with `-Wall`, `-Wextra`,
`-Wpedantic`, and `-Werror`.  The kernel executes the standard ChaCha20
rotation tuple `(16, 12, 8, 7)`, ten double rounds, and full initial-state
feedforward.

## Pre-freeze implementation qualification

Three independent gates bind the new representation before complete-domain
execution:

1. **256-block scalar gate.**  The native vector kernel and independent NumPy
   RFC 8439 implementation agree on 256 arbitrary initial states, all 4,096
   output words, and all 131,072 output bits.  The fixed output digest is
   `6c52fa41d8c972bd016af82afdbb4084ffe9177f9fd2b27eff4c64d8f4800947`.
2. **Boundary-mask gate.**  Vector packs 0, 1, 257, and 16,777,215 are checked
   against scalar execution.  These cover the beginning, adjacent-pack
   transition, an interior high-bit transition, and the final 256 candidates
   through `0xffffffff`.  All 1,024 candidate mask bits agree exactly.
3. **A178-v1/A179-v2 gate.**  Vector packs 0, 9,452,983, and 16,777,215 are
   compared with the four corresponding A178 uint64 packs.  The middle pack
   contains `0x903db747`.  Factual and control masks are identical for all 768
   checked candidates.

The RFC 8439 known-answer test remains exact and is retained in the final
artifact.

## Complete-domain execution

The frozen execution plan contains:

- 4,294,967,296 logical candidates;
- 256 candidates per vector state;
- 16,777,216 vector states;
- four uint64 sublanes per vector state;
- 262,144 vector states per batch;
- 64 complete batches;
- ten native threads;
- a 64-bit factual/control filter;
- independent 512-bit confirmation of every filter survivor;
- checkpoint/resume and no early stop.

The execution-plan digest is:

```text
0fbeaf04432d70f81aa2c4f144b43f8c61ec6c74199a683495c0e10c22a66f63
```

All 16,777,216 vector states execute freshly.  Zero states are resumed.  The
factual filter and independent full-block confirmation return only
2,419,963,719 (`0x903db747`); the control returns no filter or full match.  The
independent candidate block digest equals the A178 target:

```text
0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae
```

The canonical complete execution digest is:

```text
caec14a08dc9798b8a5230bb94f97727ba413ad1963cbd1bae06194b304b5e1e
```

The canonical A178/A179 equivalence digest is:

```text
ab44522328a109f8089b801c09b4515257c0a89d2373c49963c439998a5a0b45
```

The completed checkpoint is removed after final artifact validation.

## Causal Reader chain

The retained Causal artifact contains five explicit edges:

1. A178 complete-domain recovery anchor;
2. A179 vector-256 protocol freeze;
3. scalar, boundary, and A178-v1/A179-v2 equivalence gates;
4. complete vectorized `2^32` replay;
5. exact recovery/control identity and fourfold packing advance.

The edges form one direct provenance chain with no inferred edges.
`CryptoCausalReader` verifies both the file and graph digests:

- result JSON:
  `73874897bf3747a0c640e00e5325f9c0502d2db7b77f6fe01590c87494f7fb93`;
- Causal artifact:
  `ab627294751d40647d3b1c9d5f20d852195d64fa449dea761b8cad15b24291a1`;
- canonical Causal graph:
  `1681bf6f2647e7545a2f56163774ac7e4220fc0df171dbc9569e7eda63c5957d`.

## Timing provenance

The local production invocation was observed at 71.11 seconds.  That value is
volatile operational context, not a canonical measurement or benchmark claim.
It is excluded from the retained JSON.  The exact scientific advance is the
representation-level reduction from 67,108,864 uint64 packs to 16,777,216
vector states; no wall-clock speedup is inferred from one local observation.

## Reproduction

Fast protocol, hash, source, strict-build, 256-block, boundary-mask,
A178-v1/A179-v2, synthetic-resume, retained-result, and Causal gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_vector256_fullround_replay.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_vector256_fullround_replay.py
```

Fresh checkpointable complete-domain replay:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_vector256_fullround_replay.py
```

## Consequence

A179 proves exact complete-domain equivalence between the retained A178 uint64
Reader and a four-sublane vector-256 Reader on the same known challenge.  It
preserves the fullround ChaCha20 result and control while reducing the native
state count exactly fourfold.  This is a concrete packing advance with complete
semantic, boundary, and retained-artifact gates.
