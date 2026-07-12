# SHAKE Symbolic-R2 Center-Alias Partner Transfer v1

## Result

A174 prospectively tests whether A173's positive central alias-position
direction transfers when partner coordinate `0` is replaced by coordinate
`22`, the alias coordinate `12`'s original right neighbor in the
Weighted-Descending order.

The direction transfers:

| Central pair | Alias solver position | Inline decisions | Materialized decisions | Materialization effect |
|---|---:|---:|---:|---:|
| `22,12` | 12 | 10,816 | 6,837 | **-3,979** |
| `12,22` | 11 | 7,772 | 5,989 | **-1,783** |

Effects are `materialized decisions - inline decisions`.  The prospectively
frozen statistic is

`effect(alias at 11) - effect(alias at 12) = -1,783 - (-3,979) = +2,196`.

The confirmation rule required a positive value.  A174 therefore returns
`central_alias_boundary_transfers`, and the prospective prediction is
confirmed.  A173's coordinate-0 partner delta was +10,955; both partner choices
have the same positive direction at the identical solver positions 11/12.

This is an exact partner transfer within the retained solver graph: the
direction survives the specific substitution `0 → 22` under the same
Weighted-Descending family, affine gauge, compiler arms and fixed-resource
protocol.  It does not assert partner independence beyond the two tested
coordinates or beyond this fixed full-round relation.

Both A174 materialization effects remain negative.  Retaining the connected
alias reduces decisions in both pair orientations, while moving the alias from
solver position 12 to 11 reduces the magnitude of that benefit by 2,196
decisions.

All four formulas exhaust the 500,000,000-unit Z3 cap as `unknown`.  None emits
a model, so A174 makes no model-recovery claim.

## Prospective partner contrast

The source is the frozen Weighted-Descending order.  Coordinate `22` is
verified as the original immediate right neighbor of alias coordinate `12`.
A174 removes `12` and `22`, preserves the relative order of all remaining 22
coordinates, and inserts the pair at the same zero-based positions 11/12 used
by A173:

```text
partner before alias (`22,12`):
[11,2,15,7,16,4,8,9,3,0,21,22,12,20,18,5,10,19,6,17,14,13,23,1]

alias before partner (`12,22`):
[11,2,15,7,16,4,8,9,3,0,21,12,22,20,18,5,10,19,6,17,14,13,23,1]
```

The two orders differ only at positions 11/12.  Both are complete
24-coordinate permutations.  The partner-plan digest is
`4fd8d79ef6581ad82303b96a2432f6f933fe55fc38e1e4e0b726f3d1508ffb46`.

No SHAKE semantics change.  The affine gauge remains `0x4e1e28`; the shared R2
prefix, 22 suffix rounds, all 1,344 rate constraints and model mapping remain
unchanged.  Each order receives two compiler arms:

- **inline:** 121,575 variables and 122,895 assertions;
- **materialized:** 121,576 variables and 122,896 assertions.

## Frozen formulas

| Central pair / arm | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `22,12` / inline | 8,899,711 | `8d5554b488a3f6edebac7fe512b506a897e0d3a9f0ca091f7273da928350fe4b` |
| `22,12` / materialized | 8,899,767 | `cbcb738e87abefd57264762b1bc39ff2ab779e7e3983eb252e263107c604b214` |
| `12,22` / inline | 8,899,711 | `9c733d671b5f270e53ce2798ace93038af406338426bf259c5af854b2ea8be88` |
| `12,22` / materialized | 8,899,767 | `07c6f29091c51fc83a8af45d092e69949b30cf5cd9cc147fe24baa635c66fce6` |

The complete formula-plan digest is
`7aeb5ae8e759affecfed70292223460d30281481aeb49e955c74507719fcdb39`.
All four inverse-permutation/affine model maps independently accept the known
complete-rate witness across all 1,344 bits and reject a corrupted assignment.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Central pair / arm | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| `22,12` / inline | 10,816 | 3,254 | 7 | 501,080,358 | 445,011,981 | 116,972,499 |
| `22,12` / materialized | 6,837 | 2,448 | 8 | 501,080,363 | 444,884,491 | 118,298,028 |
| `12,22` / inline | 7,772 | 2,709 | 11 | 501,080,360 | 444,962,807 | 117,401,951 |
| `12,22` / materialized | 5,989 | 2,294 | 10 | 501,080,365 | 444,843,918 | 118,839,272 |

The canonical observation digests, in table order, are:

- `853a9f7869ebbea665673516846a950b52311a447631618e6b16db07ad99e76c`;
- `f1c75c74b3b1fa8cd25f5185903e69cbebf4be5372af66b9b840a0684a263ccc`;
- `7b455072d1093fe14f170f7814c2ae3f4c792ba71efc449851643f7f78937633`;
- `4c42ebd4fdd0c1184aefe3f05377c0e018cfae0645837cb302f38525ccf53d7c`.

The canonical partner-transfer result digest is
`a874c0d51d7eb38bb97e1a997113021b69af2aa5da3e087250a18868df11b3c0`.

## Frozen classifier

Before execution, A174 fixed three exhaustive outcomes for
`effect(alias at 11) - effect(alias at 12)`:

- positive: `central_alias_boundary_transfers`;
- zero: `exact_partner_boundary`;
- negative: `coordinate_0_specific_direction`.

The observed +2,196 selects the positive branch.  Its sign matches A173's
+10,955 coordinate-0 partner result.  Thus the direction transfers from
partner `0` to the prospectively selected original neighbor `22` at this
solvergraph boundary.

## Frozen information boundary

The protocol was frozen before any A174 solver execution at
`research/configs/shake_symbolic_r2_center_alias_partner_transfer_v1.json`,
SHA-256
`e34edf19f6a4d3193aac3ef4f9df6df742b910d9340cb2238860fc1b61862a15`.

A173's positive central result selected the partner-transfer question.  It did
not select an A174 formula arm, execution outcome or resource limit.
Coordinate `22` was selected structurally as coordinate `12`'s original right
neighbor.  Neither the target rate nor the instrumented assignment selected
the partner.  Assignment 9,279,571 is extracted only after all four executions;
every model-match field is `null` because all four outcomes are `unknown`.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A173's
central x11/x12 direction, the original-neighbor partner choice, four
hash-bound formulas, their fixed-resource observations, and the prospective
partner-transfer result.  The edges form one provenance chain with no inferred
edges.  `CryptoCausalReader` verifies provenance and both retained digests:

- Causal file SHA-256:
  `0525ec8b6030f567d8ff7573560c17a8c51b39f726b1ba70aca576ed931646b2`;
- canonical graph SHA-256:
  `cf79cb25c0d55ec7f0790bbceeadd01ef7757f47961724b492a6076be157d94f`.

## Retained bindings

- A174 result JSON:
  `e1683380ec9f5714d2c75a700b8dd2bf50f3b9cd5ee8106c48bb21f7c1b45eae`;
- A173 result JSON:
  `b3ae48350a75430b1b1aea55ebe59442949dd6b5fe19f30453583ede6da6d01b`;
- A170 result JSON:
  `f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f`.

## Reproduction

Fast protocol, partner-plan, formula, model-map, retained-artifact and Causal
Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_center_alias_partner_transfer.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_center_alias_partner_transfer.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a174
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_center_alias_partner_transfer.py \
  --work-dir "$PWD/build/shake-r2-a174"
```

## Consequence

A174 confirms the prospectively frozen partner transfer.  The positive central
alias-position direction is present with partner `0` in A173 and with original
neighbor `22` in A174.  This removes coordinate `0` as a necessary condition
for that direction in the tested solver graph.  The retained boundary is
specific and exact: two partner coordinates, one Weighted-Descending family,
one central x11/x12 crossing, one affine gauge and one fixed-resource protocol.
