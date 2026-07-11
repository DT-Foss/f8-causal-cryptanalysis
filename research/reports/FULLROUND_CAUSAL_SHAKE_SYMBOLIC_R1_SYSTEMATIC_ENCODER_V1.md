# SHAKE Symbolic-R1 Systematic Full-Round Encoder Frontier v1

## Result

A156 turns A154's systematic R1 basis into four exact encoders for the same
prospective A152 full-round relation.  All four remove known constants and
single-variable aliases before compiling the unchanged 23-round suffix and all
1,344 final rate constraints.  The formulas are frozen before execution and
run sequentially with one Z3 4.15.4 thread and the same 120-second cap.

| Encoder | Variable order | Multi-term R1 rows | Formula bytes | Removed prefix definitions | Status | Decisions |
|---|---|---|---:|---:|---|---:|
| `original_alias` | original input | define 27 | 9,087,150 | 1,573 | `unknown` | 13,428 |
| `original_inline` | original input | inline 27 | 9,085,737 | 1,600 | `unknown` | 14,876 |
| `pivot_alias` | A154 pivot order | define 27 | 9,087,142 | 1,573 | `unknown` | 13,947 |
| `pivot_inline` | A154 pivot order | inline 27 | 9,085,733 | 1,600 | `unknown` | 15,482 |

The smallest formula removes 101,268 bytes, or 1.1023%, from the exact
9,187,001-byte A152 formula.  Every run returns code zero without an external
timeout; there are four `unknown`, zero `sat`, zero `unsat`, and zero errors.
No model or partial assignment is accepted.  The instrumented assignment is
extracted only after all four executions and is not used for formula
construction, ordering, or solver input.

This maps an encoder boundary, not a failed duplicate of A152.  The exact
systematic structure eliminates all 1,600 R1 prefix definitions in the inline
representation, yet alias removal and the A154 variable permutation alone do
not resolve the monolithic 24-variable full-round relation under the declared
budget.

## Frozen formula frontier

The retained A152 formula is rebuilt byte-for-byte but not rerun:

```text
bytes   9,187,001
SHA-256 8dc549599b1d699d632be37312b0efacd43f73e073a16f5829ddc42f0c4f23c7
status  unknown at 120 seconds, retained from A152
```

The four A156 formula hashes are:

- `original_alias`:
  `af38e924b195c04d9d1fa1f10cc44fa1cd7164dd6d3fcb5ed8974f74ac585547`;
- `original_inline`:
  `c557019c695ce6943ab4065aa4337c4f5d653828793039b8d95afcdbc577201d`;
- `pivot_alias`:
  `7848bfccac9199c6b0dedf66cdc2f4c05ecdeab8b4433d03f8c9ab6bbd62516c`;
- `pivot_inline`:
  `7f442c229fe15448dfbc6902f70c66a9d547a83a1e7d0f2f56111348fcb56326`.

Their complete pre-execution plan hash is
`9d5747707fbd99bb9a6766a0a1e1939bc9fe9350f1034e7a2243ae140e3c94af`.
The solver-output hashes and complete counters for every run are retained in
the JSON; wall-clock measurements are excluded.

## Anchor and model boundaries

A156 hash-gates:

- A152 prospective result:
  `0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561`;
- A154 systematic affine basis:
  `108cbcadcbd7cfc3831712b8d2073aab42d42cca098db162d1d63627882d21dd`;
- A155 R2 K24 transition:
  `ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80`.

Solver variables in pivot order are mapped back through the exact declared
permutation before independent checking.  A `sat` result without all 24 input
values fails closed.  Any complete model must independently reproduce all
1,344 rate bits before it can be retained; no encoder produced such a model in
this frontier.

## Retained bindings

- result JSON:
  `703e8c5c68882a144f60e29867e99f37b5b8bba42ffa70b0aee922d0cb2551ae`;
- Causal artifact:
  `9465ac3f3d5381ce8bec44b9a00cafe0ecbe3e17e72ecfbd453ece0394db7189`;
- canonical Causal graph:
  `da18e2fccb4fbfcde796e23ba7e745d6552db461cd981a47767c5daf671309e2`.

The five-triplet chain is reopened with `CryptoCausalReader` and proves the
path A152 full-round boundary -> A154 systematic basis -> A155 R2 saturation
boundary -> four frozen encoders -> uniform full-round execution.

## Reproduction

Static formula reconstruction and retained-artifact checks:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_systematic_encoder_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_systematic_encoder_frontier.py
```

Full sequential execution:

```bash
rm -rf build/shake-r1-a156
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_systematic_encoder_frontier.py \
  --work-dir "$PWD/build/shake-r1-a156"
```

## Consequence

A155 shows that R2 cover partitioning would fix 23 variables, while A156 shows
that pure R1 alias elimination does not cross the resource boundary.  The next
distinct encoder replaces the first generic suffix round with A155's exact
shared R2 dictionary: one constant, 24 linear variables, and 276 quadratic
monomials defined once.  This changes the representation and removes a complete
generic round block; it is not another variable-order replay.
