# SHAKE Symbolic-R2 Exact Affine-Gauge Reader v1

## Result

A160 evaluates every one of the 16,777,216 affine shifts of the exact A155
24-variable R2 interface.  The globally minimal total linear-coefficient
incidence is unique:

| Gauge | Shift | Linear incidences | Change from zero |
|---|---:|---:|---:|
| zero control | `0x000000` | 8,698 | 0 |
| A154 systematic-R1 constants | `0xb8faad` | 8,665 | -33 |
| A160 global minimum | `0x8e26db` | 8,413 | -285 |
| A160 global maximum | `0xe6a19c` | 8,938 | +240 |

The minimum removes 285 of 8,698 original linear incidences, a 3.2766%
reduction.  It has Hamming weight 13 and is not the gauge obtained by merely
absorbing A154's selected R1 constants.  Both the global minimum and maximum
are unique over the complete domain.

Every per-coordinate quadratic coefficient is unchanged by construction and
verified after substitution.  The shifted interface still contains all 276
quadratic monomials, exactly 15,972 quadratic coefficient incidences, and the
same K24 interaction graph.  Constant incidences fall from 831 to 823, so the
complete R2 coefficient count falls from 25,501 to 25,208.

## Exact Walsh objective

For R2 output coordinate `k`, let `l[k,i]` be the coefficient of input `x_i`
and let `q[k,i]` be the 24-bit mask of variables coupled quadratically to
`x_i`.  Under the affine gauge

```text
x_i = y_i XOR s_i
```

the new linear coefficient is exactly

```text
l'[k,i] = l[k,i] XOR parity(q[k,i] AND s).
```

There are 1,600 x 24 = 38,400 such coefficient positions.  Grouping them by
neighbor mask gives the signed spectrum

```text
C[m] = sum_(k,i : q[k,i]=m) (-1)^l[k,i].
```

Its Walsh transform is

```text
W[s] = sum_m C[m] (-1)^parity(m AND s),
L[s] = (38,400 - W[s]) / 2,
```

where `L[s]` is the exact linear-incidence objective.  A160 computes the full
integer transform in mask order; no search heuristic, optimizer seed, target
bit, model, or instrumented assignment is involved.

The signed spectrum has 1,133 nonzero bins.  Its hash is
`747a3153f75d589a9b74f3148e04e7e083f0894f435963d19fd782515ded8aec`;
the complete 16,777,216-entry Walsh score vector hashes to
`39e31bcf1b37548f9be98e646d57b03fee186307cc245d5bfa882952222e7a95`.
The coefficient energy is 443,955,142, and exact Parseval equality holds:

```text
sum_s W[s]^2
= 2^24 * sum_m C[m]^2
= 7,448,331,311,644,672.
```

Sixty-six deterministic masks, including both extrema and the zero/all-one
controls, are also evaluated directly from all 38,400 coefficient equations and
match their transform entries.

## Semantic and structural gates

The selected shift is substituted explicitly into all 1,600 Boolean-ring R2
polynomials.  The shifted polynomial-state hash is
`cc5e540d6650a78c607ef5a1c0071894be61cc32f711aecf75f1277ab9d68dda`.
For 64 deterministic shifted assignments, A160 compares:

1. the original R2 ANFs at `x = y XOR 0x8e26db`;
2. the shifted R2 ANFs at `y`;
3. two independent bitsliced Keccak-f[1600] rounds.

All three representations agree on 307,200 checked state bits.  The exact list
of quadratic monomials is additionally compared per output coordinate, not
only as a global union.

## Retained bindings

- A155 result anchor:
  `ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80`;
- original R2 polynomial state:
  `d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752`;
- A160 result JSON:
  `725d5fcddba7ff4ba4e1a90fac5dd90d34990f4b9f62bf7cfe06e56396de73aa`;
- A160 Causal artifact:
  `48e899901f73be9954267d403bd9bfc1ad53d0561fd0a5446d9edabc62eeef61`;
- canonical Causal graph:
  `b23853988b0db99b614b10313247fe81335defb39c16d6a28c12324c6a2478e2`.

The four-triplet Causal chain is reopened with `CryptoCausalReader`; its exact
explicit provenance sequence is verified.  The Reader-visible graph links the
A155 polynomial anchor, complete Walsh objective, certified global optimum,
and independent semantic gate.

## Reproduction

The full `2^24` transform, artifact generation, and tests are directly
executable on the local CPU:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_affine_gauge_reader.py

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_affine_gauge_reader.py
```

The test independently checks the FWHT definition and involution on small
complete domains, explicit polynomial substitution, the full retained optimum,
all hashes, and the Causal Reader chain.

## Consequence

A160 supplies a unique, globally optimal, assignment-free polarity gauge for
the exact R2 handover.  The next experiment should compile
`x = y XOR 0x8e26db` into each of the four frozen A158 input orders, map every
complete model back through both the permutation and affine shift, and replay
the formulas with A159's fixed resource protocol.  This isolates affine gauge
from order, quadratic graph, suffix, target, and resource budget in one
factorial transfer.
