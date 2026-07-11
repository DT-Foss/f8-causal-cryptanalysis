# Direct Output-Causal Compression: ChaCha Counter Traversals

## Question

Does a direct cipher-output causal graph retain a reduced-round distinction
when the same ChaCha counter values are presented through different ordered
input geometries, rather than only through the familiar sequential order?

## Codec

For each traversal, consecutive 64-byte cipher outputs are factual pairs. The
codec computes their XOR-delta's 64 per-byte entropy deficits, subtracts the
mean profile from 16 BvN repairing bijections, and writes the resulting class
mean/standard-deviation nodes to a dedicated `.causal` file. Each file is then
re-opened through `CryptoCausalReader`; only its reconstructed nodes classify
the five held-out key batches.

The five traversal families are sequential counters, Gray code, 32-bit
bit-reversal, an odd affine permutation of the uint32 ring, and a random
permutation of the sequential counter set. The last one is the input-geometry
control: it preserves the sampled counter multiset while removing local
counter order.

## Independent 5k confirmation

The confirmation uses new ten-key blocks, five train/five held-out keys,
5,000 counters per key and 16 BvN routes. Three-way chance is 33.3%.

| traversal | R2 | R3 | R20 |
|---|---:|---:|---:|
| sequential | 5/5 | 4/5 | 3/5 |
| Gray | 5/5 | 4/5 | 2/5 |
| bit-reversal | 5/5 | 5/5 | 2/5 |
| affine | 5/5 | 4/5 | 1/5 |
| random-order control | 5/5 | 2/5 | 1/5 |

R2 is separated in every traversal, including randomized order. R3 is high
under all four structured counter geometries (4--5/5) but drops to 2/5 under
the same-set random-order control; R20 is 1--3/5. This identifies a concrete
next mechanism question: the R3 adjacent-output profile is sensitive to
structured counter geometry, while the stronger R2 profile is not.

## Boundary

This is a known-input, reduced-round output-class inference experiment. It
does not recover a ChaCha key, distinguish ChaCha20 from random in the
standard security game, or claim a full-round attack. The R20 column is a
control class within this particular three-class reader query, not evidence of
a full-round weakness.

## Artifacts

- Experiment: `experiments/chacha_traversal_causal_signature.py`.
- Discovery JSON: `results/v1/chacha_traversal_causal_signature_v1.json`,
  SHA-256 `fca55f5cb8bb4220259c2e9edd3207b5ef0176409bac259ac6f23ea54c5f7749`.
- Independent confirmation JSON:
  `results/v1/chacha_traversal_causal_signature_confirm_v1.json`, SHA-256
  `5e4cc964dc199fafa2ab306d291b84795a49b71baee7d4cc900b369d457375ad`.
- Five confirmation graphs are in `results/v1/traversal_confirm/`; the reader
  validation gate opened all five alongside the rest of the repository.
