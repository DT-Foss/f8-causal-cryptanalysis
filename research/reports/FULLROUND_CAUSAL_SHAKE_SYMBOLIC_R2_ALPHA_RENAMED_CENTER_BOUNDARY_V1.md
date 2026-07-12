# SHAKE Symbolic-R2 Alpha-Renamed Center Boundary v1

## Result

A175 prospectively tests whether A174's positive central alias-position
direction survives an exact alpha-renaming of every declared SMT symbol.  The
transformation adds one to every numeric suffix, is bijective, and is byte
reversible to each original A174 formula.

The positive boundary direction survives:

| Central pair | A174 decisions | Alpha-renamed decisions | Decision change |
|---|---:|---:|---:|
| `22,12` / inline | 10,816 | 10,816 | 0 |
| `22,12` / materialized | 6,837 | 6,837 | 0 |
| `12,22` / inline | 7,772 | 7,772 | 0 |
| `12,22` / materialized | 5,989 | 6,387 | **+398** |

The first three decision counts reproduce A174 exactly.  The fourth changes by
398 decisions.  All four canonical observation hashes differ because the
retained internal counter observations are not bit-identical after renaming.
The result is therefore directional alpha robustness, not exact observation
invariance.

The renamed materialization effects are:

- alias at solver position 12 (`22,12`): `6,837 - 10,816 = -3,979`;
- alias at solver position 11 (`12,22`): `6,387 - 7,772 = -1,385`.

The prospectively frozen statistic becomes

`effect(position 11) - effect(position 12) = -1,385 - (-3,979) = +2,594`.

A174's original delta was +2,196, so alpha-renaming changes its magnitude by
+398 while preserving its positive sign.  A175 therefore returns
`central_boundary_alpha_robust`, and the prospective prediction is confirmed.

This isolates two exact facts.  Concrete numeric symbol identities modulate
one fixed-resource traversal trajectory, while the positive central boundary
direction transfers through the tested bijective renaming.  The conclusion is
limited to these four graphs, this `suffix+1` mapping, Z3 4.15.4 and the fixed
resource protocol.

All four formulas exhaust the 500,000,000-unit cap as `unknown`.  None emits a
model, so A175 makes no model-recovery claim.

## Byte-reversible alpha intervention

For every declared symbol `prefixN`, A175 applies

`prefixN → prefix(N + 1)`.

The transformation covers every declaration and every matching symbol token:

| Compiler arm | Declarations renamed | Symbol occurrences renamed | Mapping SHA-256 |
|---|---:|---:|---|
| inline | 121,575 | 529,945 | `cc680d0930e25c0305c249af5a5fc6d980e763fc0bbc0e07d24034002e3486c4` |
| materialized | 121,576 | 529,948 | `6c512161244eda8325d3f5f8155e774155e996e2b68f41a3021ec294aa3df585` |

Every image symbol is unique, prefixes are preserved, and the inverse mapping
recovers the exact original A174 bytes in all four cases.  Declaration order,
assertion order, graph topology, input-coordinate order, compiler arms,
variable/assertion counts, suffix rounds, target constraints and model mapping
are unchanged.  The solver input names change elementwise from `x0..x23` to
`x1..x24` without changing their order.

The complete alpha-plan digest is
`031193f031b90706fc20c2c05a55ec191fdbec234c3181212d23ddcfb3a7e6e9`.

## Frozen formulas

| Alpha-renamed graph | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `22,12` / inline | 8,900,139 | `5e767d72c8da66223a3e727c05d7c61918042db8835ce6871f5e389cce2788f7` |
| `22,12` / materialized | 8,900,196 | `e254879f000584b42824f9beb7ed26758fb6bf6aa0b03fcfca66f94d259d1137` |
| `12,22` / inline | 8,900,139 | `d0ba2dbf1e44f08b38b0f3c47dc444747ff9ab1e0b24568a0b0a727a40547332` |
| `12,22` / materialized | 8,900,196 | `bf9a845ef90d65fc59af65ef497c5410cbe4f924dfc25fb68215e84319b08028` |

The complete formula-plan digest is
`c9167fc6a6ec8056135c9cd512a9e87322118addc2575e2f6cdf4e5b278e56da`.
All four inverse-permutation/affine model maps independently accept the known
complete-rate witness across all 1,344 bits and reject a corrupted assignment.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Alpha-renamed graph | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| `22,12` / inline | 10,816 | 3,254 | 7 | 501,080,358 | 445,011,419 | 116,972,343 |
| `22,12` / materialized | 6,837 | 2,448 | 8 | 501,080,363 | 444,885,240 | 118,298,311 |
| `12,22` / inline | 7,772 | 2,709 | 11 | 501,080,360 | 444,962,977 | 117,401,961 |
| `12,22` / materialized | 6,387 | 2,320 | 8 | 501,080,365 | 444,834,876 | 118,363,006 |

The canonical observation digests, in table order, are:

- `9d1c035f45b7502ef8a013688b05a25f7833e99ccafbbb968e5564788aad2c99`;
- `fa1daba536a48077bec52bd1520c825615615f1cddfca041f2ef04b9b1792d13`;
- `f7118442c0741034b1dacdf02d9182760dabbf31f91dadd52c88162ba9da8649`;
- `e72f56544eca498fec19d377e89c8a010dd82fe4c61d228c0c077ad884e57105`.

Each differs from its A174 counterpart.  Decision-count equality in the first
three rows is therefore narrower than complete canonical-observation equality.

The canonical alpha-boundary result digest is
`d6f1f34041830e50b86f0481d9afed748c80880fba49f04d3aabcfbfbc52df07`.

## Frozen classifier

Before execution, A175 fixed four exhaustive outcomes:

- all four canonical observations equal A174:
  `exact_alpha_invariance`;
- observations differ but renamed delta remains positive:
  `central_boundary_alpha_robust`;
- renamed delta is zero: `alpha_renamed_exact_boundary`;
- renamed delta is negative: `numeric_symbol_identity_conditioned`.

All observations differ and the renamed delta is +2,594.  The retained branch
is therefore `central_boundary_alpha_robust`.  Numeric names influence the
trajectory but do not reverse the tested central-boundary direction.

## Frozen information boundary

The protocol was frozen before any A175 solver execution at
`research/configs/shake_symbolic_r2_alpha_renamed_center_boundary_v1.json`,
SHA-256
`c1f608902bf55a7dfbc3703164124d8dcd9f83c973dc175f6b89275b496f0eb6`.

A174 selected the alpha-renaming question but no A175 formula arm, outcome or
resource limit.  The mapping is derived only from the declared A174 symbols.
Neither the target rate nor the instrumented assignment enters the mapping.
All four formula bytes and mapping digests were frozen before execution.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A174's
prospective partner transfer, the bijective suffix shift, four hash-bound
alpha-isomorphic formulas, their fixed-resource observations, and the
alpha-boundary result.  The edges form one provenance chain with no inferred
edges.  `CryptoCausalReader` verifies provenance and both retained digests:

- Causal file SHA-256:
  `069b23251855af0a9bb325cb5ad7f2ba011b30c123884e84e6b285f749040935`;
- canonical graph SHA-256:
  `019fcdbbec35bab3d6a154bb242cf268e9ca8e53dad78c65c271cc9c8f6bbfb4`.

## Retained bindings

- A175 result JSON:
  `1c432037567c74397b95d0d75c84a0eac406d63398e57c7214bdf7c730cb2894`;
- A174 result JSON:
  `e1683380ec9f5714d2c75a700b8dd2bf50f3b9cd5ee8106c48bb21f7c1b45eae`;
- A173 result JSON:
  `b3ae48350a75430b1b1aea55ebe59442949dd6b5fe19f30453583ede6da6d01b`.

## Reproduction

Fast protocol, alpha-plan, byte-inverse, formula, model-map, retained-artifact
and Causal Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_alpha_renamed_center_boundary.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_alpha_renamed_center_boundary.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a175
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_alpha_renamed_center_boundary.py \
  --work-dir "$PWD/build/shake-r2-a175"
```

## Consequence

A175 rejects exact canonical-observation invariance: a byte-reversible
graph-isomorphic renaming changes internal counters in every arm and decisions
in one arm.  At the same time, it confirms directional robustness: the positive
central-boundary delta survives and increases from +2,196 to +2,594.  Concrete
numeric names modulate the fixed-resource traversal, while the tested boundary
direction remains stable under this exact alpha intervention.
