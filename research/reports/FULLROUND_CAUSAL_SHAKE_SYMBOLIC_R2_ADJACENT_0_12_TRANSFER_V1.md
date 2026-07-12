# SHAKE Symbolic-R2 Adjacent 0/12 Transfer Frontier v1

## Result: transfer failed, new condition identified

A172 prospectively tests the local rule discovered in A170's two matched
weighted contexts: placing coordinate `12` immediately before coordinate `0`
should produce a strictly lower connected-alias materialization effect than
placing `0` immediately before `12`.

The prospective direction reverses in the new central Greedy-Max context:

| Central orientation | Inline decisions | Materialized decisions | Materialization effect |
|---|---:|---:|---:|
| `0` before `12` | 4,870 | 4,289 | **-581** |
| `12` before `0` | 5,790 | 5,665 | **-125** |

Effects are `materialized decisions - inline decisions`.  The frozen test
statistic is therefore

`effect(12 before 0) - effect(0 before 12) = -125 - (-581) = +456`.

The prospective confirmation condition required a negative value.  The
observed value is positive, so the cross-family transfer failed and the
direction is reversed.  Both individual effects remain negative: retaining
the connected alias uses fewer decisions in both central orientations.  What
fails is the predicted ordering between those two effects.

This result identifies the missing condition directly: adjacent `0/12`
orientation does not determine the materialization-effect direction by itself.
The surrounding order family and insertion context condition that direction.
The weighted-context rule is real in both discovery pairs and does not transfer
as a context-free law to the central Greedy-Max pair.

All four formulas represent the same retained full-round SHAKE128 relation and
all four exhaust the 500,000,000-unit Z3 resource cap as `unknown`.  A172 is an
exact paired fixed-resource traversal result, not a model-recovery result.

## Frozen discovery evidence

A170 exposed two matched weighted pairs.  Within each pair the complete
24-coordinate vectors differ only by an adjacent swap of coordinates `0` and
`12`:

| Discovery context | Zero-based positions | Effect: `0,12` | Effect: `12,0` | Directional delta |
|---|---:|---:|---:|---:|
| late weighted | 13/14 | +977 | -1,281 | **-2,258** |
| early weighted | 9/10 | -2,008 | -2,898 | **-890** |

Both discovery deltas are negative.  Their canonical evidence digest is
`d74aada82dace4327f3820493eff50c704e32a6ebd27ccf7d1bc11b1a953b098`.
These retained outcomes selected the directional transfer question.  They did
not select an A172 outcome after formula freeze.

## Prospective cross-family construction

The transfer source is the Greedy-Max order, the first non-weighted order
family under the frozen selection rule.  Coordinates `0` and `12` are removed,
the relative order of the other 22 coordinates is preserved, and the pair is
inserted at the deterministic central zero-based positions 11 and 12.  The two
new orders are:

```text
0 before 12:
[11,2,15,7,4,16,3,9,22,20,8,0,12,21,10,5,6,18,19,17,14,1,13,23]

12 before 0:
[11,2,15,7,4,16,3,9,22,20,8,12,0,21,10,5,6,18,19,17,14,1,13,23]
```

They differ only at positions 11/12, are complete permutations of all 24
coordinates, and are absent from the prior four base and four reversed orders.
The transfer-plan digest is
`de15046300be637bcf4fa9de7183c1fbd4d619265455f8edc274f086920be424`.

No SHAKE semantics change.  The affine gauge remains `0x4e1e28`; the shared R2
prefix, all 22 suffix rounds, all 1,344 target-rate constraints, and every
model mapping remain unchanged.  Each orientation receives the same two
compiler arms:

- **inline:** 121,575 variables and 122,895 assertions;
- **materialized:** 121,576 variables and 122,896 assertions.

## Frozen formulas

| Orientation / arm | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `0,12` / inline | 8,899,715 | `e883450ba22cff021b4bd816375b89c5f652f1af78fa55d4e9705cfd61ea3fba` |
| `0,12` / materialized | 8,899,771 | `e846ab0386b692a1363724726c6e67575ecd333bf1a4b607433ce25e5fbe7a5e` |
| `12,0` / inline | 8,899,715 | `8d4ba9f22615e9c848e4d9901c9bcab9e74e26b9ec615a7b9dc92f547354fb93` |
| `12,0` / materialized | 8,899,771 | `6076d05cd2c15478af715e6c96045951cc1d89a9668e048d7db3de1f9240c5d5` |

The complete formula-plan digest is
`bedd957db8a405bdecd98a0f4742842362888eea58e02df8262d98e22eecdf95`.
All four inverse-permutation/affine model maps independently accept the known
complete-rate witness and reject a corrupted assignment before execution.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Orientation / arm | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| `0,12` / inline | 4,870 | 2,440 | 6 | 501,080,276 | 444,895,479 | 118,657,697 |
| `0,12` / materialized | 4,289 | 2,286 | 3 | 501,080,281 | 444,860,135 | 118,502,948 |
| `12,0` / inline | 5,790 | 2,400 | 11 | 501,080,272 | 444,879,535 | 118,672,810 |
| `12,0` / materialized | 5,665 | 2,253 | 5 | 501,080,277 | 444,837,453 | 118,539,888 |

The canonical observation digests, in table order, are:

- `89ecfd9f4a169d98e486ae2a1c155485c325970bc3d03907551c51cac7b65c26`;
- `63ad1f6649de967a0826fe55b1d550f522ae3987aa1900f0974cd7e3a2554f49`;
- `d42df17c79e3ea3e37ef840282832903ae62adce96b94085aa323f93db4a2eea`;
- `4a597cc93cce3eb441fa09b8e5664c085a944876f317e6529c918b3f39d10c61`.

The canonical transfer-result digest is
`7b20ad6787fb555b55239522a43977ac268a7423c0f5d067def935ca27b6a4fd`.

## Frozen information boundary

The protocol was frozen before any A172 solver execution at
`research/configs/shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json`,
SHA-256
`27be9da4897c9cde913db8a40aa169322a8a7c5dbec805878ec188dfec06c151`.

The prospective prediction, Greedy-Max source, central 11/12 boundary, two
orders, four formulas, execution sequence and resource limit were all fixed
before execution.  A170 outcomes were used to discover the two matched
weighted contexts but not to select the cross-family source or central
boundary.  Neither the target rate nor the instrumented assignment selected
the transfer construction.  Assignment 9,279,571 is extracted only after all
four executions; every model-match field is `null` because every solver result
is `unknown`.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: the two
A170 matched swaps, the prospective cross-family central pair, four hash-bound
formulas, their fixed-resource observations, and the directional transfer
result.  The edges form one provenance chain with no inferred edges.
`CryptoCausalReader` verifies provenance and both retained digests:

- Causal file SHA-256:
  `e4df47fe3657f5b0d785d3ee6f142ad807b05a5d27320ef2ed6e183e62a9f2e6`;
- canonical graph SHA-256:
  `652c5c0db4c9ef682a2f69d16ed8256c10fad7f252e5d854c2f3ea09a6896bd2`.

## Retained bindings

- A172 result JSON:
  `f1252babeb729f9b58102d24d522daa0fa337506e25f9f282b2b4fb9a4d693c3`;
- A170 result JSON:
  `f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f`;
- A169 result JSON:
  `b19c1b85bfad77c5e7aa909ba11a02821fce21f6603daa3174bfe5899a0c1334`.

## Reproduction

Fast protocol, discovery, transfer-plan, formula, model-map, retained-artifact
and Causal Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_adjacent_0_12_transfer_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_adjacent_0_12_transfer_frontier.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a172
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_adjacent_0_12_transfer_frontier.py \
  --work-dir "$PWD/build/shake-r2-a172"
```

## Consequence

The context-free transfer claim is closed: `12` before `0` is not universally
the lower materialization-effect orientation.  In both weighted discovery
contexts it is lower; in the prospective central Greedy-Max context it is 456
decisions higher.  At the same time, both new effects remain negative.  A172
therefore separates two facts that the discovery matrix had not separated:
connected-alias materialization remains beneficial in the new pair, while the
relative advantage of the two adjacent orientations reverses with context.
That order-family/insertion-context condition is the new retained mechanism
boundary.
