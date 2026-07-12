# ChaCha20 Native Full-Round 32-Bit Partial-Key Recovery v1

## Result

A178 performs fullround 32-bit partial-key recovery against the standard
ChaCha20 block function.  Key word 0 is unknown; the other 224 key bits,
32-bit counter, 96-bit nonce, and complete 512-bit block output are public.
The native Causal Reader executes every one of the `2^32` possible values for
the missing word through all 20 ChaCha20 rounds and the standard feedforward.

The complete result is:

| Quantity | Result |
|---|---:|
| unknown key word | word 0 / initial lane 4 |
| known key material | 224 bits |
| logical candidates | 4,294,967,296 |
| native 64-candidate packs | 67,108,864 |
| stream batches | 64 |
| freshly executed packs | 67,108,864 |
| resumed packs | 0 |
| 64-bit filter matches | 1 |
| independent 512-bit full matches | 1 |
| recovered key word | **2,419,963,719 (`0x903db747`)** |
| bit-flipped-control filter matches | 0 |
| bit-flipped-control full matches | 0 |

The enumeration completes without early stopping.  The unique 64-bit filter
survivor is independently evaluated over the complete standard block function
and matches all 512 target bits.  The recovered value is first revealed only
after complete-domain execution.

## Exact partial-key-recovery scope

The retained claim is fullround 32-bit partial-key recovery in this exact
standard ChaCha20 block-function setting:

- all 20 ChaCha20 rounds execute;
- the final modular feedforward into all 16 words executes;
- key word 0, a full 32-bit word at initial lane 4, is unknown;
- key words 1 through 7, or 224 key bits, are known;
- the 32-bit counter and 96-bit nonce are known;
- all 512 output bits of one block are known;
- the complete `2^32` unknown-word domain is evaluated.

This is a direct complete-domain key-word recovery result rather than a
distinguisher or reduced-round projection.

## Frozen prospective challenge

The protocol was frozen before any A178 candidate execution at
`research/configs/chacha20_native_fullround_partial_key_recovery_v1.json`,
SHA-256:

```text
4fb2d61f104d5aa424b7ba269fad446e086025fe40dcf4091d1335b71f729573
```

The public challenge has canonical SHA-256:

```text
58f9244e4a41f2e04f7d6350c628c40feafa252affdcdb25b0a2699862a57b48
```

It contains the seven known key words, counter, three nonce words, complete
target block, one-bit-flipped control block, and public derivation metadata.
It does not contain the unknown word.  The runner builds lane 4 as zero and
replaces it only with enumerated candidates.

The public known material is hash-derived from the retained A177 result.  Its
derivation digest is
`ce551fd4a3dbf291a36933c17fe81cb01da278546473532639c35abbebaa63d3`,
and the corresponding public seed is 1,314,201,556.  The seven known words,
counter, and nonce reproduce exactly from that derivation.

The unknown word was generated once from operating-system cryptographic
randomness, used only to form the public target, and discarded before runner
construction.  Its value is absent from the protocol, Python runner, native C
source, and pre-execution artifacts.  The first retained value is the recovered
result after the complete search.

The factual target block SHA-256 is:

```text
0e6d649e11ef271fbd2505f6d707f20ee4857b2b81ef7f296be9ec8c5853d3ae
```

The control flips only bit zero of output word zero and has SHA-256:

```text
5e346bbcce4f88533f842f53c638d68a6c3b60d07a132ed1b01ae309dd7d6cce
```

## Standard ChaCha20 semantics

A178 anchors the standard block semantics to A119's retained Causal Reader and
RFC 8439 known-answer test.  The implementation uses constants in lanes 0--3,
eight key words in lanes 4--11, the counter in lane 12, and the three nonce
words in lanes 13--15.  Ten column-plus-diagonal double rounds execute the
standard rotation tuple `(16, 12, 8, 7)`, followed by wordwise addition of the
initial state.

The RFC 8439 block-function vector for key bytes `00..1f`, counter 1, and nonce
`000000090000004a00000000` matches byte-for-byte.  A119's retained JSON and
Causal artifacts are hash-gated before the challenge is opened.

## Native candidate-axis Reader

The C11 kernel stores the same bit coordinate from 64 independent candidate
states in one `uint64_t`.  Its retained source SHA-256 is:

```text
ec2759fc66e86b7b50ea7fece66b2994d1961bb5b84d9081aff3514f25cacb8e
```

Before complete-domain execution, two independent gates validate it:

- 64 arbitrary 16-word initial states are compared with the NumPy reference;
  all 1,024 words, or 32,768 output bits, match exactly;
- four candidate packs covering assignments 0 through 255 are compared with a
  scalar reference for both factual and control masks; every mask bit matches.

The production plan uses ten native threads and 64 batches of 1,048,576 packs.
Each machine word evaluates 64 candidate key words, reducing 4,294,967,296
logical block evaluations to 67,108,864 packed states.  The native filter
compares the first two output words, or 64 output bits, for the factual and
control targets in the same traversal.

The canonical execution-plan digest is:

```text
d386bc846e4098fddd104431e23aa1f59d434ea8e1b68f8495b3459567e019be
```

The complete-domain execution digest is:

```text
2cd7a5c3eda73eb7b467b6dd7ce57bdb139da9d679b680c9bef72ddeec07993c
```

## Checkpoint and completion gates

Checkpoint/resume binds the protocol, public challenge, target and control
digests, native source, unknown lane, window width, thread count, and batch
size.  Resumed progress must be batch-aligned; retained candidates must be
unique and confined to the already executed prefix.

The retained production run starts at pack zero, resumes no work, executes all
67,108,864 packs, and records `early_stop_used=false`.  The runner refuses to
construct a retained result unless the complete candidate domain has executed.
After the final JSON and Causal artifacts are written and reopened, the
checkpoint is removed.

## Independent 512-bit confirmation and control

The 64-bit native filter returns one candidate:

```text
2419963719 = 0x903db747
```

A separate NumPy RFC 8439 implementation inserts that word into lane 4,
executes all 20 rounds plus feedforward, and compares every one of the 16 output
words.  All 512 bits match and the candidate block digest equals the frozen
target digest exactly.

The bit-flipped control returns no 64-bit filter candidate and no full-block
match.  The canonical factual/control confirmation digest is:

```text
3f1d3d4e33c21b093c7b76d962e3d0f3defe4ac310c840fdaa10dd3ecc98b8a4
```

## Causal Reader chain

The retained `.causal` artifact contains exactly five explicit edges:

1. A119's retained standard 20-round block/feedforward anchor;
2. the prospectively frozen public partial-key challenge;
3. the compiled and cross-validated native candidate Reader;
4. complete execution of all 67,108,864 candidate packs;
5. independent full-block confirmation and partial-key recovery.

Each edge names its direct predecessor, every predecessor outcome equals the
next trigger, there are no inferred edges, and `CryptoCausalReader` verifies the
complete provenance chain.

Retained hashes:

- A178 result JSON:
  `80fee52a0a2222efab161d74eb7ee124f6d94b56ca0cf759c5ffc4ca2881bea1`;
- A178 Causal artifact:
  `94c651c6ea5432f482c054ae6d839c84563e8eae81e98625beb158344da16995`;
- canonical A178 Causal graph:
  `cea6f5b1c277a875be22f5e76744a2a42cbe73aa1e042a8018201bf4416a156a`;
- A177 complete-domain anchor:
  `d6b85ca7f15bc198513cd05100187f2ccc0ab97d1f22a906383ccd4a62eda544`;
- A119 retained result anchor:
  `af1a7199c5eb45daf415246565b9bf2f4e0eb6a723ffc92bba8f8d7452a3c3e2`;
- A119 retained Causal anchor:
  `ed86f9b3fcae2e06a099d841aece72b896b86a3611ced1f10314fc66d72ed302`.

## Timing provenance

The interactive production invocation was observed at roughly 73 seconds.
This is operational context, not a controlled benchmark.  Volatile wall-clock
timing and machine metadata are excluded from the canonical artifact, and no
performance claim is derived from that observation.

## Reproduction

Fast protocol, anchor, RFC-vector, warning-clean C build, native cross-gates,
synthetic resume, retained-artifact, and Causal Reader checks:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_native_fullround_partial_key_recovery.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_native_fullround_partial_key_recovery.py
```

Fresh checkpointable complete-domain execution:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_native_fullround_partial_key_recovery.py
```

## Consequence

A178 establishes fullround 32-bit partial-key recovery for its prospectively
frozen standard ChaCha20 challenge.  It converts a complete `2^32` key-word
domain into 67,108,864 native candidate packs, recovers `0x903db747` uniquely,
confirms the complete 512-bit block independently, and rejects the one-bit
control over the same exhaustive domain.
