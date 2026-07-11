# SHAKE Full-Round Boolean-Influence Frontier v1

## Result

Under the declared known-complement model, every one of 16 capacity-window
coordinates has been intervened on over each complete `2^16` assignment space,
and its exact Boolean influence has been measured on all 1,600 Keccak state
coordinates. Three independent deterministic windows per SHAKE variant give
the same transition across six complete trials:

| round | SHAKE128 nonzero cells | SHAKE256 nonzero cells | fully coupled state coordinates |
|---:|---:|---:|---:|
| 0 | 16 | 16 | 0 |
| 1 | 346--367 | 354--388 | 0 |
| 2 | 8,436--8,927 | 8,308--8,823 | 0 |
| 3 | 25,597--25,600 | 25,597--25,600 | 1,597--1,600 |
| 4 | **25,600** | **25,600** | **1,600** |
| 5 | **25,600** | **25,600** | **1,600** |
| 24 | **25,600** | **25,600** | **1,600** |

There are exactly `16 x 1,600 = 25,600` intervention cells per observation.
Round 4 is the first measured round at which every window coordinate affects
every state coordinate in all six complete trials.

## Influence balance

Support saturation and influence balance occur together at round 4.  Each cell
is based on all `2^15 = 32,768` paired assignments.

| stage | maximum absolute deviation from influence 0.5, all six trials |
|---:|---:|
| round 3 | 0.500000 |
| round 4 | 0.013062 |
| round 5 | 0.011932 |
| round 24 | 0.012054 |

Thus every round-4 influence lies inside `[0.486938, 0.513062]`, and every
full-round influence lies inside `[0.487946, 0.512054]`.  All 153,600 cells
across the six round-4 matrices, and again all 153,600 full-round cells, are
within 0.02 of one half.

The production artifact contains 42 complete matrices: seven round positions,
three windows and two variants.  That is 35,232,153,600 logically complete
Boolean paired-cell comparisons, evaluated in a bit-sliced representation.

## Relation to the algebraic frontier

The ANF frontier established that round-3 coordinate functions remain only
about 1.34--1.40% dense and have maximum degree 7/6.  The intervention frontier
now shows that this sparsity is not a variable partition: at round 3, between
1,597 and 1,600 of the 1,600 state coordinates already depend on all 16 window
coordinates.

Round 2 is therefore the last measured factorable support layer. Round 3 is a
sparse-polynomial but nearly all-to-all layer; round 4 is the first measured
all-to-all and influence-balanced layer; round 5 adds maximum-degree,
random-density ANFs. A
round-split Reader intended to preserve a sparse dependency graph must split at
the R2->R3 boundary.  Keeping R3 ANFs can still preserve low algebraic degree,
but it cannot decompose the variables into independent components.

## Independent gates

- Exact Boolean derivatives of `0`, `x0`, `x0 xor x1`, and `x0 and x1` match
  their complete paired-assignment counts.
- Candidate-axis conversion matches 8,192 independently extracted coordinate
  values.
- Round composition matches 102,400 scalar Keccak state bits.
- Every influence cell uses all 32,768 paired assignments; matrix and support
  hashes are serialized for every trial and round.
- The six-edge `.causal` artifact is reopened with `CryptoCausalReader` and
  passes provenance validation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_boolean_influence_frontier.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,5,24 \
  --seeds 3 \
  --output research/results/v1/shake_boolean_influence_frontier_v1.json \
  --causal-output research/results/v1/shake_boolean_influence_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_boolean_influence_frontier.py
```

## Artifact hashes

- result JSON:
  `171ab39a043a1d94398635c681e7a2618ef95323bbd463632c427cfdb322dfdb`
- six-edge `.causal`:
  `e8fca821d7c0d114b748fbedd281f0fa0897fd38d886da985897b578abf07575`
