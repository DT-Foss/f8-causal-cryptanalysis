# SHAKE Full-Round Affine-Hull Reader v1

## Result

Under the declared known-complement model, one complete deterministic
16-coordinate window truth space per SHAKE variant is partitioned by assignment
prefix, and the first 128 rate coordinates of every branch are represented by
their exact GF(2) affine hull. Target membership produces the same sharp
transition in SHAKE128 and SHAKE256:

| fixed prefix coordinates | suffix assignments per branch | prefix branches | branches containing the target |
|---:|---:|---:|---:|
| 8 | 256 | 256 | 256 |
| 9 | 128 | 512 | 195 |
| 10 | 64 | 1,024 | **1** |
| 11 | 32 | 2,048 | **1** |
| 12 | 16 | 4,096 | **1** |

At prefix width 10, the sole surviving branch is the actual prefix in both
variants.  The remaining six coordinates are then the only suffix assignments
inside that branch.

## Exact rank mechanism

The actual full-round branch has the maximum affine rank permitted by its point
count:

| fixed prefix | branch points | affine rank | independent affine relations |
|---:|---:|---:|---:|
| 7 | 512 | 128 | 0 |
| 8 | 256 | 128 | 0 |
| 9 | 128 | 127 | 1 |
| 10 | 64 | 63 | 65 |
| 11 | 32 | 31 | 97 |
| 12 | 16 | 15 | 113 |

This explains the membership transition.  With 256 points, every branch spans
the complete 128-coordinate space and therefore contains every target.  With
128 points, rank is 125--127 and one to three relations appear.  With 64
points, every branch has rank 63, so a nonmatching target would need to satisfy
65 independent affine conditions.

## Random-space agreement

The observed false-branch counts match the values predicted directly from each
measured rank histogram:

| prefix | SHAKE128 observed / expected false branches | SHAKE256 observed / expected false branches |
|---:|---:|---:|
| 8 | 255 / 255.0 | 255 / 255.0 |
| 9 | 194 / 194.625 | 194 / 195.875 |
| 10 | 0 / `2.77e-17` | 0 / `2.77e-17` |
| 11 | 0 / `1.29e-26` | 0 / `1.29e-26` |
| 12 | 0 / `3.94e-31` | 0 / `3.94e-31` |

The full-round hulls therefore behave like maximum-rank point sets rather than
retaining a low-rank global affine relation.

## What changed relative to coordinate constancy

The earlier prefix Reader showed that no individual rate coordinate is fixed
until only about three suffix coordinates remain.  The affine Reader uses joint
relations instead: at ten fixed prefix coordinates, 65 independent parity
conditions identify the actual prefix even though every individual coordinate
still varies within its 64-point branch.

This is a genuine representation gain.  It does not yet reduce the total truth
space needed to construct all branch hulls: the current implementation evaluates
all `2^16` assignments once, then performs exact branch elimination.  The next
mechanistic target is to derive those branch relations without materializing
every suffix point.

## Independent gates

- Candidate-axis conversion is exact over 8,192 coordinate values.
- The round-by-round composition gate matches 102,400 scalar state bits.
- Every rank and membership count uses complete branch point sets.
- The four-edge `.causal` artifact is reopened with `CryptoCausalReader` and
  passes provenance validation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_affine_hull_frontier.py \
  --window-bits 16 \
  --output research/results/v1/shake_affine_hull_frontier_v1.json \
  --causal-output research/results/v1/shake_affine_hull_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_affine_hull_frontier.py
```

## Artifact hashes

- result JSON:
  `3b9674533fe019145a71f3cb0fd48662d118322f8f2590a37fcfb6650098c82e`
- four-edge `.causal`:
  `e4bb952b4c786110c393bef0f759ad8b49e86623478f9f360e0722c23382ca4f`
