# SHAKE Consecutive-Block Capacity-Window Inference v1

## Result

The first SHAKE squeeze block supplies the complete post-permutation rate.  In
this experiment the remaining capacity is known except for one declared
contiguous window.  The next complete rate block supplies the reverse-query
constraint:

```text
candidate full state
  -> Keccak-f[1600], 24 rounds
  -> predicted next rate
  -> exact equality with observed next rate.
```

The Reader re-opens a six-edge `.causal` artifact, enumerates the capacity
window in ascending order, applies the full permutation to every candidate,
and confirms survivors against the complete next rate.

| variant | unknown bits | candidates | exact survivors | recovered assignment | wrong-target survivors |
|---|---:|---:|---:|---:|---:|
| SHAKE128 | 8 | 256 | 1 | 73 | 0 |
| SHAKE128 | 12 | 4,096 | 1 | 1,191 | 0 |
| SHAKE128 | 16 | 65,536 | 1 | 50,567 | 0 |
| SHAKE128 | 20 | 1,048,576 | 1 | 537,654 | 0 |
| SHAKE256 | 8 | 256 | 1 | 224 | 0 |
| SHAKE256 | 12 | 4,096 | 1 | 1,985 | 0 |
| SHAKE256 | 16 | 65,536 | 1 | 1,883 | 0 |
| SHAKE256 | 20 | 1,048,576 | 1 | 193,202 | 0 |

All eight recovered assignments equal the instrumented ground truth.  The
windows begin at different capacity positions (`6,23,88,98,166,200,238,310`),
so the result is not confined to one lane or low-order bits.

Across the full run, 2,236,928 complete 24-round candidate permutations are
evaluated.  Comparing only the first two next-rate lanes leaves exactly one
candidate in every run; complete-rate equality then confirms the same unique
candidate.  Independent wrong-message next-rate targets leave zero candidates
already at the two-lane filter.

## Scaling boundary

The algorithmic work is exactly

```text
candidate_count(k) = 2^k.
```

The retained candidate counts rise `256 -> 4,096 -> 65,536 -> 1,048,576`, a
factor of sixteen for every additional four unknown bits.  The 20-bit result
is therefore a real exact reverse inference on this machine, while merely
extending the same enumeration to 24 bits would add no new mechanism and cost
sixteen times as many full permutations.

## Scope

This is consecutive-block inference with a known capacity complement.  It
does not assert reconstruction of the complete 256- or 512-bit capacity from
ordinary output alone.  Its value is the executable reverse-query baseline:
it proves that the next full-round rate block uniquely constrains every tested
window and quantifies the exact exponential boundary that a stronger solver
would need to beat.

Correctness inherits the zero-state Keccak, FIPS 202, and `hashlib` gates from
the SHAKE rate Reader.  Specification source:
[NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_capacity_window_inference.py \
  --output research/results/v1/shake_capacity_window_inference_v1.json \
  --causal-output research/results/v1/shake_capacity_window_inference_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_capacity_window_inference.py
```

## Artifact hashes

- result JSON:
  `80b084b8d24b953d7d61e785170e1c2dc95256dfdaf38019bf00a650780c2aa0`
- six-edge executable `.causal`:
  `79c48d2754e593cf4de07f17f1b2fb707eb3b2f3df84a606f435fe6cbb09ee2b`
