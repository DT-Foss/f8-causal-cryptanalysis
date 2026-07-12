# SHAKE Symbolic-R2 Four-Gauge Factorial Frontier v1

## Result

A164 completes the frozen Cartesian product of A158's four input orders and
A162's four unique affine gauges.  It executes exactly the eight cells absent
from A163, so no expensive query is repeated.  Every new formula receives the
same one-thread Z3 4.15.4 budget of 500,000,000 resource units and the same
independent affine/permutation model-recovery gate.

The complete fixed-resource decision matrix is:

| Input order | `0x498a92` | `0x4e1e28` | `0x8c161b` | `0x954b3c` | Order mean |
|---|---:|---:|---:|---:|---:|
| weighted-degree descending | 6,785 | **5,339** | 9,800 | 13,930 | 8,963.50 |
| weighted-degree ascending | 10,687 | **4,402** | 5,462 | 9,781 | **7,583.00** |
| greedy maximum remaining weight | 8,311 | **6,870** | 9,521 | 9,694 | 8,599.00 |
| greedy minimum remaining weight | 12,607 | **6,505** | 12,528 | 9,512 | 10,288.00 |
| Gauge mean | 9,597.50 | **5,779.00** | 9,327.75 | 10,729.25 | 8,858.375 |

The result is decisive: gauge `0x4e1e28` has the lowest decision count in all
four orders.  It is not the unweighted minimum-incidence gauge and it was
selected by A162 only as the greedy-max/back-loaded optimum.  Completing the
factorial reveals that it carries a transferable gauge main effect hidden by
A163's generating-pair design.

The new best cell is weighted-degree ascending with `0x4e1e28` at 4,402
decisions and 2,189 conflicts.  Relative to exact fixed-resource controls it
reduces decisions by:

- 9,984 or 69.4% from the same-order zero gauge at 14,386;
- 6,091 or 58.0% from the same-order A160 gauge at 10,493;
- 1,422 or 24.4% from the previous global minimum, A161's
  greedy-max/`0x8e26db` cell at 5,824.

All 16 matrix cells, including the eight new A164 cells, exhaust the common
resource cap as `unknown`; none emits a model.  The result is therefore an
exact full-round traversal improvement and a resolved structural factor, not a
model claim.

## Exact factor decomposition

For decision count `y[o,s]`, A164 records exact rational order, gauge and
interaction components.  With row sum `R[o]`, column sum `C[s]`, and total
`T`, the interaction residual is stored as

```text
I[o,s] = (16*y[o,s] - 4*R[o] - 4*C[s] + T) / 16.
```

Every row and column of the interaction matrix sums exactly to zero.  The
grand mean is `141734/16 = 8858.375` decisions.

Gauge `0x4e1e28` has main effect `-49270/16 = -3079.375` decisions from the
grand mean, far larger than the other gauge effects.  Weighted-degree ascending
is the best order on average with effect `-20406/16 = -1275.375`.

The largest absolute interaction is `49530/16 = 3095.625` decisions for the
descending/`0x954b3c` cell.  Thus A164 resolves both parts of the mechanism:
`0x4e1e28` is a strong cross-order main effect, while order-specific coupling
remains large enough to determine individual extremes.

Structurally, `0x4e1e28` has 796 constant, 8,452 linear, and 15,972 quadratic
coefficient incidences with four exact R2 aliases.  A160's `0x8e26db` has fewer
linear incidences but more constants and only two aliases.  The universal
factorial win therefore removes unweighted linear count as the explanation and
focuses the next algebraic Reader on the combined constant/alias/elimination
structure and its suffix cones.

## Frozen nonrepeating protocol

Before any A164 solver execution, the protocol was stored at
`research/configs/shake_symbolic_r2_four_gauge_factorial_completion_v1.json`
with SHA-256
`84355ca6b5d3b871d82d82ed1fa7c0a38819776ad291c8cd5a931ac40de2f3fb`.

Its three exact plan bindings are:

- complete 16-cell product:
  `91c0ffb122d42731a192cef73b79fd0ef4df14df91ecff6dd53738b10ed814d7`;
- eight-cell complement of the A162 generating pairs:
  `65ed6a97f06325dcb1538b5601f650aa462135697b43575caf844474a70afb2e`;
- eight rendered full-round formulas:
  `4c68011dd6173883900828bf7f6510918c3f30776ed9b6211fb17579087e49ff`.

The missing-cell rule uses only the four A158 orders, the four unique A162
semantic gauges, and set subtraction of A162's eight generating pairs.  It does
not use an A163 decision count, rank, target bit, or instrumented assignment.
An independent preflight audit confirmed that the eight A163 cells and eight
A164 cells are disjoint and together equal the complete product.

## Eight new observations

| Missing cell | Decisions | Conflicts | `rlimit-count` |
|---|---:|---:|---:|
| descending / `0x4e1e28` | 5,339 | 2,222 | 501,080,369 |
| descending / `0x8c161b` | 9,800 | 2,536 | 501,080,291 |
| ascending / `0x4e1e28` | 4,402 | 2,189 | 501,079,875 |
| ascending / `0x8c161b` | 5,462 | 2,250 | 501,079,819 |
| greedy-max / `0x8c161b` | 9,521 | 3,959 | 501,080,203 |
| greedy-max / `0x954b3c` | 9,694 | 2,458 | 501,080,205 |
| greedy-min / `0x498a92` | 12,607 | 3,577 | 501,079,806 |
| greedy-min / `0x4e1e28` | 6,505 | 3,292 | 501,079,923 |

All eight have return code 1 and the verified termination marker
`fixed_rlimit_exhausted`.  Volatile timing, memory, allocation, stdout, and
stderr fields are excluded from canonical observations.  Formula, solver-basis
polynomial, observation, matrix, and decomposition hashes are pinned by the
focused retained-artifact test.

## Model and Causal gates

Every solver assignment is mapped from solver order to shifted input order,
then XORed with its cell's affine shift, then evaluated by the independent
NumPy lane core over all 24 rounds and all 1,344 rate bits.  All eight known
witness mappings pass before production; a corrupted model is rejected.  The
instrumented assignment 9,279,571 is extracted only after every A164 execution
and never enters design, formula, order, gauge, or solver execution.

The five-edge Causal chain records the frozen product, eight missing formulas,
eight observations, complete 4x4 join, and exact factor decomposition.
`CryptoCausalReader` reopens it and verifies every explicit provenance edge.

## Retained bindings

- A164 result JSON:
  `c8b4f7446b3e78b3914f90e5fbbc201d00771a917c7fafe16eba6e134e0f55ab`;
- complete factorial matrix:
  `b049c248886b5eba988c9be19510b4d24b735f5b176045b60d0578e5cf63611b`;
- exact factor decomposition:
  `a78dbdcfa838f86a1f0884c22fb078412e0623a98bd882126e61df6f74a9d0d4`;
- A164 Causal artifact:
  `8935ebb8678ea545e122283d44bc4d3f1462ee8ffad7ace1905cbceb6dfc20d8`;
- canonical Causal graph:
  `561ce3b8ea09721a5210b8d70f0ef53fa07dc87647e2e3f7f7ae6705c26f8d90`.

## Reproduction

Fast protocol, formula, mapping, resource-adapter, artifact, decomposition,
and Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_four_gauge_factorial_completion.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_four_gauge_factorial_completion.py
```

Full sequential execution of only the eight missing cells:

```bash
rm -rf build/shake-r2-a164
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_four_gauge_factorial_completion.py \
  --work-dir "$PWD/build/shake-r2-a164"
```

## Consequence

A164 converts A163's order-weighted breadcrumb into a cross-order structural
result: `0x4e1e28` wins every frozen order and produces the lowest full-round
fixed-resource traversal observed in this line.  The next mechanism Reader can
now target one concrete object rather than search arbitrary gauges: explain
and predict the `0x4e1e28` advantage from constant polarity, exact aliases,
elimination order and suffix-cone pressure.  In parallel, the already verified
native candidate-axis Reader can be transferred to the same prospective A152
instance to turn the unresolved symbolic traversal into direct full-domain
model reconstruction on consumer hardware.
