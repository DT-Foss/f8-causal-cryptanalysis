# SHAKE Bit-Sliced State-Window Consistency v1

## Result

Keccak-f[1600] uses Boolean lane operations.  Transposing the candidate axis
into the 64 bits of each machine word lets one full bit-sliced permutation
evaluate 64 state-window assignments at once:

```text
scalar representation:    one uint64 lane per candidate
bit-sliced representation: one uint64 bit-plane for 64 candidates
```

The six-edge `.causal` artifact stores the lossless candidate packing, the
24-round bit-sliced permutation, and the exact next-rate consistency Reader.

| variant | variable coordinates | logical candidates | packed states | exact consistent assignment | wrong-target matches |
|---|---:|---:|---:|---:|---:|
| SHAKE128 | 20 | 1,048,576 | 16,384 | 438,348 | 0 |
| SHAKE128 | 24 | 16,777,216 | 262,144 | 8,647,961 | 0 |
| SHAKE256 | 20 | 1,048,576 | 16,384 | 932,712 | 0 |
| SHAKE256 | 24 | 16,777,216 | 262,144 | 5,723,038 | 0 |

All four assignments equal the instrumented ground truth.  In each run the
first two next-rate lanes leave exactly one candidate, and complete-rate
equality confirms it.  Independent target states leave zero candidates.

Across the production run, 35,651,584 logical candidates are represented by
557,056 packed states, an exact factor-64 reduction in machine-word state
evaluations.  The 24-coordinate cases extend the deterministic consistency
frontier by sixteen times the logical candidate count of the scalar 20-bit
baseline.

## Independent implementation gate

Before any window run, 64 random 1,600-bit states are evaluated by both:

1. the standard vectorized Keccak-f[1600] implementation;
2. the candidate-axis bit-sliced implementation.

All `102,400/102,400` output bits match exactly.  The gate covers candidate
packing, Theta, Rho, Pi, Chi, Iota, all lane rotations, and all 24 round
constants.

## Solver representation boundary

A generic QF_BV formulation was tested first on one 20-coordinate SHAKE128
instance with a fixed 60-second Z3 limit and one constrained output lane.  It
reached the limit without returning the assignment, while the deterministic
candidate evaluator had already resolved the same-width class in seconds.

This selected the Keccak-specific Boolean representation over generic
bit-vector solving.  Bit slicing improves the constant factor by 64; it does
not change the logical `2^k` candidate-space exponent.  That distinction is
retained explicitly in the causal metadata.

## Scope

The benchmark fixes the rate and all state coordinates outside the declared
window, then checks the next full-round rate block.  It is a mathematical
state-consistency result, not a claim about unrestricted 256-/512-coordinate
state determination.

Correctness inherits the Keccak zero-state, FIPS 202, and `hashlib` gates.
Specification source: [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_bitsliced_window_solver.py \
  --output research/results/v1/shake_bitsliced_window_solver_v1.json \
  --causal-output research/results/v1/shake_bitsliced_window_solver_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_bitsliced_window_solver.py
```

## Artifact hashes

- result JSON:
  `7eb7350100b27d3fe9f3382d233798cc8bdd88861d66872135cce49ea9b5629f`
- six-edge executable `.causal`:
  `70aac76d2829f2ea7f76b31decbfc4d3c2b10b82782c158609e17a9af1b5de11`
