# SHAKE Symbolic Prefix-Split Frontier v1

## Result

The exact symbolic-prefix frontier selects **R1**, not R2, as the
minimum-decision interface for the complete SHAKE128 state-window Reader.  The
comparison holds the later observation, input state, variable coordinates,
remaining round equations, solver version, thread count, and model gate fixed;
only the round at which symbolic formulas hand over to explicit Boolean round
equations changes.

| window condition | symbolic split | shared monomials | coordinate coefficients | first-query decisions | complete-rate model |
|---|---:|---:|---:|---:|---|
| 12 coordinates, monolithic | **R1** | **13** | 1,082 | **2,986** | exact |
| 12 coordinates, monolithic | R2 | 79 | retained A135 | 35,088 | exact |
| 12 coordinates, monolithic | R3 | 794 | 439,656 | 4,441 | exact |
| 16 coordinates, fixed A136 model branch | **R1** | **27** | 1,196 | **1,909** | exact |
| 16 coordinates, fixed A136 model branch | R2 | 274 | retained A136 | 5,967 | exact |
| 16 coordinates, fixed A136 model branch | R3 | 7,512 | 1,521,940 | configured boundary | -- |

At 12 coordinates, R1 uses 11.75 times fewer decisions than R2 and 1.49 times
fewer than R3.  Against the canonical 586,636-decision CNF result, the R1
Reader uses only 0.509% of the decisions, a **196.46-fold reduction**.  On the
verified 16-coordinate model branch, R1 reduces the retained R2 count from
5,967 to 1,909, a further **3.13-fold reduction**.

Every returned assignment equals the posthoc instrumented coordinates and is
independently injected into the 24-round Keccak implementation.  Every one of
the 1,344 next-rate bits matches.

## Mechanism selected by the frontier

The pre-measurement prediction selected R2 because it minimizes the number of
explicit suffix rounds while retaining a compact symbolic dictionary.  The
measurement identifies a different optimum:

- R1 keeps the symbolic interface almost affine: 13/27 shared monomials and
  1,082/1,196 total coordinate coefficients in the two conditions;
- the second round remains an explicit network of local XOR/AND equations,
  preserving intermediate variables that support direct propagation;
- R2 removes that explicit network but replaces it with longer coordinate
  formulas and 79/274 shared monomials;
- R3 grows to 794/7,512 shared monomials and 439,656/1,521,940 coordinate
  coefficients.  It remains executable at width 12 but reaches the configured
  boundary in the width-16 comparison.

The retained mechanism is therefore not "symbolize as many sparse rounds as
possible."  The Reader optimum is the handover point that balances formula
reuse against local constraint propagation.  For these complete-round queries,
that point is one symbolic round.

This also separates two notions that had previously been coupled: A133/A134
correctly identify R2 as a highly compact storage interface, while A137
identifies R1 as the best measured decision interface.  Compression optimum
and Reader optimum are distinct properties.

## Reuse of established anchors

The R2 measurements are not rerun.  A137 accepts A135 and A136 only at their
complete SHA-256 hashes, imports the matching R2 rows, and independently checks
their returned models through the complete-rate evaluator.  New computation is
restricted to the R1 and R3 interfaces needed to decide the split frontier.

The two width-16 comparisons intentionally use the already verified A136 model
branch.  This is a controlled representation comparison, not a branch search;
it determines which split is carried into the subsequent monolithic scaling
Reader.

## Causal Reader artifact

The `.causal` file stores three provenance-linked operations:

- compile exact R1/R2/R3 symbolic prefix interfaces;
- attach the exact remaining round equations and complete next-rate
  constraints;
- retain the minimum-decision split among independently verified exact models.

The artifact is reopened through `CryptoCausalReader`, and provenance plus the
three-triplet recipe are checked during production.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_split_frontier.py \
  --prefix-rounds 1,2,3 \
  --timeout-seconds 60 \
  --output research/results/v1/shake_symbolic_split_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_split_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_split_frontier.py
```

## Artifact hashes

- result JSON:
  `19cc21bb0b60943182ac8d0c927e9090ac881c24fba04a9f646ae4972fe84583`
- three-edge `.causal`:
  `c9ae6a8f89b614274a39ef03b84a6d13157aef8ee9da6e3cfc61511a3f19f074`
