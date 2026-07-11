# SHAKE Symbolic R2 ANF Frontier v1

## Result

The complete Keccak state after two rounds is now compiled directly in the
Boolean polynomial ring from variable SHAKE capacity coordinates.  The compiler
does not construct a `2^k` truth table.  It represents each of the 1,600 state
coordinates as an exact ANF and scales through the complete 256-bit SHAKE128
capacity and the complete 512-bit SHAKE256 capacity.

| variant | variable capacity coordinates | R2 shared monomials | R2 coordinate coefficients | symbolic bytes | log2(raw/symbolic) |
|---|---:|---:|---:|---:|---:|
| SHAKE128 | 16 | 275 | 13,789 | 55,614 | 7.881 |
| SHAKE128 | 32 | 1,063 | 35,525 | 216,916 | 21.917 |
| SHAKE128 | 64 | 12,176 | 166,549 | 2,532,672 | 50.372 |
| SHAKE128 | 128 | 227,916 | 1,027,637 | 49,229,920 | 110.091 |
| SHAKE128 | **256 (complete)** | **2,467,023** | **6,918,733** | **572,349,400** | **234.552** |
| SHAKE256 | 16 | 277 | 14,505 | 56,018 | 7.870 |
| SHAKE256 | 32 | 1,956 | 43,802 | 399,088 | 21.038 |
| SHAKE256 | 64 | 21,234 | 191,946 | 4,416,736 | 49.569 |
| SHAKE256 | 128 | 230,711 | 1,040,150 | 49,833,640 | 110.073 |
| SHAKE256 | 256 | 2,544,615 | 7,086,635 | 590,350,744 | 234.507 |
| SHAKE256 | **512 (complete)** | coordinate-local | **64,724,568** | **4,142,385,224** | **487.696** |

Every R2 polynomial has degree at most four.  For the complete SHAKE256
capacity, the mean coordinate contains 40,452.855 monomials and the largest
contains 53,084.  The coordinate-local sparse representation is about
`2^487.696` times smaller than the corresponding complete truth table.

The 512-bit row intentionally does not build one global Python set of unique
monomials.  That duplicate-elimination representation is unnecessary for exact
coordinate evaluation and reached a 13.3 GB transient peak.  The retained
format stores every exact coordinate-local polynomial, its deterministic state
hash, total coefficient counts, degree distribution, and complete interaction
graph while keeping the run bounded.

## Symbolic compiler

The compiler works in
`GF(2)[x_0,...,x_(k-1)] / (x_i^2 + x_i)`:

- XOR is symmetric difference of monomial sets;
- multiplication unions the variable masks and cancels duplicate monomials by
  parity;
- idempotence gives `p * p = p`;
- Theta, Rho, Pi and Iota are compiled exactly;
- Chi is compiled as `a xor c xor b*c`, equivalent to
  `a xor ((not b) and c)`.

No approximation, sampling, truncation, fitted model, or truth-table
interpolation enters the formulas.

## Complete gates

The 16-coordinate compiler output is compared with the exhaustive A133
Möbius artifacts.  For SHAKE128 and SHAKE256, the global basis hash and complete
`basis x 1600` coefficient-matrix hash match exactly at R0, R1 and R2.  Those
six hash equalities cover the complete `2^16` Boolean functions, not selected
assignments.

Every wider interface is then evaluated independently through the real
bit-sliced Keccak core:

- widths 16/32/64: eight complete 1,600-bit states per variant and width;
- widths 128/256: two complete states plus six random assignments on 64
  deterministic state coordinates per variant and width;
- SHAKE256 width 512: two complete states plus six random 512-bit assignments
  on 64 deterministic state coordinates.

In total, 94,720 independently computed state bits match.  The 512-bit random
gate includes coordinates across the complete 1,600-bit state, and the exact
assignment and coordinate schedules are serialized in the JSON artifact.

## What changed

A133 showed that an exhaustive R2 truth space compresses because all 1,600
formulas reuse a small low-degree feature set.  A134 removes the exhaustive
truth space itself.  The compact interface is derived directly from the round
equations and remains finite even when `2^256` or `2^512` assignment rows cannot
exist as an executable dataset.

The monomial primal graph is complete at R2 for every tested width.  This is not
independent-component factorization.  The retained mechanism is exact symbolic
feature reuse.  The next solver target is to connect this R2 interface to a
separate R3--R24 constraint component without substituting the suffix into a
dense full-round ANF.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_anf_frontier.py \
  --window-bits 16,32,64,128,256,512 \
  --assignment-samples 8 \
  --output research/results/v1/shake_symbolic_anf_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_anf_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_anf_frontier.py
```

## Artifact hashes

- result JSON:
  `a6a9889a5fbcb9da65bfa6c9802bd182fafcc65c542f12320688a54894da4543`
- six-edge `.causal`:
  `df8b81ce1d15dd8f4b7b42cb6c13b7233370b844d67a47e4ab93b77390f10c5c`
