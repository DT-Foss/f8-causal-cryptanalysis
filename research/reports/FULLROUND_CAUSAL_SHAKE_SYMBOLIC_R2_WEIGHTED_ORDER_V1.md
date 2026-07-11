# SHAKE Symbolic-R2 Weighted Input-Order Frontier v1

## Result

A158 derives four solver-input permutations only from the exact weighted K24
matrix of A155's R2 interface.  The weight of an edge is the number of R2 state
coordinates containing that quadratic monomial.  No final-rate target,
assignment, model, or prior projection participates in order derivation.

All four orders use the same frequency-ordered 301-monomial R2 representation,
the same R3--R24 suffix, all 1,344 target bits, one Z3 4.15.4 thread, and a
uniform 120-second cap.

| Order | Derivation | Formula bytes | Status | Decisions | Conflicts |
|---|---|---:|---|---:|---:|
| `weighted_degree_descending` | static weighted degree, high first | 8,900,978 | `unknown` | 10,990 | 6,118 |
| `weighted_degree_ascending` | static weighted degree, low first | 8,901,450 | `unknown` | 18,485 | 6,681 |
| `greedy_max_remaining_weight` | repeatedly choose highest remaining weighted connectivity | 8,900,967 | `unknown` | 17,799 | 6,891 |
| `greedy_min_remaining_weight` | repeatedly choose lowest remaining weighted connectivity | 8,901,423 | `unknown` | 23,097 | 6,084 |

Every run returns code zero without an external timeout, assignment, or model.
Because all four outcomes are `unknown`, no order is labeled a solver winner.
The retained finding is the traversal separation: the identical semantic
relation records between 10,990 and 23,097 decisions solely under four
assignment-free weighted input permutations.

## Weighted K24 object

The 276 edge weights range from 35 to 88 and sum to 15,972.  The weighted
degree vector is

```text
[1358,1122,1505,1371,1415,1291,1250,1426,
 1375,1372,1280,1528,1358,1219,1237,1452,
 1425,1243,1292,1276,1321,1330,1339,1159]
```

Its symmetric `24 x 24` matrix hash is
`bd7e5fbf292b0912dc143fbfbc8c7a8f9aec13a7ac29633f86835306c4004c1b`.
The runner directly hash-gates both this matrix and the original R2 polynomial
state
`d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752`
before deriving an order or formula.

The four exact orders are stored in the result JSON; their joint canonical hash
is `f92fbe97375e284626ed4632bdd7b064b2f04531b8a87fbb59375bd33823208e`.
Static orders sort by weighted degree with coordinate index as tie-break.
Dynamic orders recompute each remaining coordinate's incident weight after
every removal and again break ties by coordinate index.  All four are distinct
complete permutations.

## Frozen formulas

The complete pre-execution plan hash is
`aca15c4f43d960814f86a58d459f9f1a38714dab8152483eeb68f4c58eb08911`.
Its formulas are:

- `weighted_degree_descending`:
  `742fafd690f71aa93ec98a9b24f84fa51d4715103eecea03843d9bd46c977295`;
- `weighted_degree_ascending`:
  `7b64ba9a3509fff7b28026e2c07af35da0ee9609fed9f163842b39ddf4f1ea66`;
- `greedy_max_remaining_weight`:
  `81e97db7caa37668f070b1348be25868f6525269fa1bd5f7744610f1bdd67581`;
- `greedy_min_remaining_weight`:
  `a6c2041dfe0cf6d1dcb48870c96798902fd21e36e40f781a5ee607f8819ad1d2`.

Each contains 121,578 declared variables, 122,898 assertions, the exact 301
shared R2 monomials, 1,598 R2 state definitions, 22 explicit suffix rounds, and
the complete target relation.  Any solver-basis model is mapped back through
its declared permutation and must independently reproduce all rate bits.

## Scope and retained bindings

A158 is motivated by A157's observed original-versus-pivot traversal split and
hash-gates its artifact
`682c9c70e79702f15e54972c04a26372539e3b3e3473fa6230e053dd898c6ea4`.
It does not import an A157 model, assignment, or target projection.  The
instrumented assignment 9,279,571 is extracted only after all four executions.

- result JSON:
  `f8852a160b11094a5d5b3a2a4c193575a849f15c4e6f489527df391566ff9382`;
- Causal artifact:
  `ff063a9e225c135aa7972bf8b18b3d6241633526316baca11ef61a1b6598bf51`;
- canonical Causal graph:
  `6df9ddf1d65b86a6295f87476a9ee26271c4b76040f39a23057403022acb8d8d`.

The four-triplet Causal chain is reopened with `CryptoCausalReader` and links
A157's order sensitivity through the exact weighted object, four frozen
formulas, and uniform execution.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_weighted_input_order_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_weighted_input_order_frontier.py
```

Full sequential execution:

```bash
rm -rf build/shake-r2-a158
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_weighted_input_order_frontier.py \
  --work-dir "$PWD/build/shake-r2-a158"
```

## Consequence

The direction of the decision counter is not an outcome certificate when every
run ends at a wall-clock boundary.  A159 should therefore replay each of the
four retained formulas byte-for-byte under one fixed Z3 `rlimit`, not another
time limit.  That converts the large traversal split into a deterministic
resource-unit comparison before any further order is selected.
