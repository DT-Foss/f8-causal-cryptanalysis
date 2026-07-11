# SHAKE Full-Round Algebraic-Degree Frontier v1

## Result

Under the declared known-complement model, the exact algebraic normal forms
(ANFs) of the first 128 SHAKE rate coordinates have been computed over every
assignment of one deterministic 16-coordinate capacity window per variant.
Both tested SHAKE128 and SHAKE256 windows reach the maximum possible degree 16
at round 5, and their ANF coefficient density reaches the random-function
baseline at the same round.

| round | SHAKE128 max degree | SHAKE128 mean monomials | SHAKE256 max degree | SHAKE256 mean monomials |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0.57 | 0 | 0.46 |
| 1 | 1 | 0.77 | 1 | 0.71 |
| 2 | 3 | 9.04 | 3 | 8.09 |
| 3 | 7 | 876.57 | 6 | 920.17 |
| 4 | 14 | 30,836.43 | 12 | 30,930.67 |
| 5 | **16** | **32,768.09** | **16** | **32,773.56** |
| 24 | **16** | **32,782.16** | **16** | **32,785.36** |

There are `2^16 = 65,536` possible ANF monomials.  A uniformly random Boolean
function therefore has expected coefficient count 32,768.  At round 5 the
measured means differ from that baseline by only 0.0083 standard errors for
SHAKE128 and 0.492 standard errors for SHAKE256.

## Exact saturation transition

The coefficient-density transition is concentrated between rounds 3 and 5:

| round | SHAKE128 coefficient density | SHAKE256 coefficient density |
|---:|---:|---:|
| 3 | 0.013375 | 0.014041 |
| 4 | 0.470527 | 0.471965 |
| 5 | 0.500001 | 0.500085 |
| 24 | 0.500216 | 0.500265 |

At round 3 the coordinate truth tables are already balanced to about one half,
yet their ANFs remain sparse and have degree at most 7/6.  Balance, absence of
fixed coordinates, and algebraic saturation are therefore three distinct
events: coordinate constancy disappears by round 3, while dense maximum-degree
ANFs appear at round 5.

At the full 24 rounds, SHAKE128 has 58 degree-16 coordinates and SHAKE256 has
69.  The random-function expectation is 64 out of 128; the deviations are
-1.061 and +0.884 standard deviations.  Every remaining coordinate has degree
15.  Full-round direct ANF expansion is consequently dense rather than a
sparse representation of the state-window relation.

## Mechanistic consequence

The exact sparse algebraic zone ends at round 3.  Expanding the complete
24-round composition into ANF destroys that sparsity by round 5.  The Boolean
influence follow-up further establishes that R3 is already nearly all-to-all in
variable support.  The shared-dictionary follow-up then places the complete
monomial interaction graph one round earlier at R2.  Independent variable
components end at R1; R2 remains compact only through extensive reuse of 275 or
277 shared low-degree monomials.  R4--R24 must remain a separate constraint
component rather than being substituted into a dense full-round ANF.

This frontier also explains why the full-round affine-hull branches behave as
maximum-rank point sets: by round 5 the restricted coordinate functions already
have random-like coefficient density, and rounds 6--24 preserve that saturated
regime.

## Independent gates

- A four-function Möbius gate recovers exact declared degrees 0, 1, 2 and 3.
- Candidate-axis conversion matches 8,192 independently extracted coordinate
  values.
- Round composition matches 102,400 scalar Keccak state bits.
- Every ANF uses the complete `2^16` truth table; no coordinate is sampled.
- The four-edge `.causal` artifact is reopened with `CryptoCausalReader` and
  passes provenance validation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_algebraic_degree_frontier.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,5,6,8,12,24 \
  --output research/results/v1/shake_algebraic_degree_frontier_v1.json \
  --causal-output research/results/v1/shake_algebraic_degree_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_algebraic_degree_frontier.py
```

## Artifact hashes

- result JSON:
  `a8b94f4df2b50bd50246c7b35c9d3bbd4a6a9464f51fffed8ecfa2ed6a3c5c0f`
- four-edge `.causal`:
  `b99b5c401f06fc4f257c59e95b93f7adbc6893be5b7418d1e7ac4170ecef021b`
