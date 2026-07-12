# SHAKE Symbolic-R2 Input-Declaration Swap Boundary v1

## Result

A176 prospectively tests whether A174's positive central alias-position
direction depends on the parser declaration order of `x11` and `x12`.  It swaps
only those two declaration lines and leaves every assertion, symbol spelling,
`get-value` request and graph edge unchanged.

All four complete canonical observations reproduce A174 bit-for-bit:

| Partner graph | A174 decisions | Swapped decisions | Decision change | Canonical observation |
|---|---:|---:|---:|---|
| `22,12` / inline | 10,816 | 10,816 | 0 | exact |
| `22,12` / materialized | 6,837 | 6,837 | 0 | exact |
| `12,22` / inline | 7,772 | 7,772 | 0 | exact |
| `12,22` / materialized | 5,989 | 5,989 | 0 | exact |

The swapped effects remain -3,979 and -1,783.  The directional delta remains
exactly +2,196, with zero change from A174.  A176 therefore returns
`exact_input_declaration_order_invariance`, the strongest predeclared branch,
and confirms the prospective positive-delta prediction.

This closes the concrete `x11`/`x12` declaration order as an explanation for
the tested boundary.  The result is exact for these four A174 formulas, Z3
4.15.4 and the fixed-resource protocol; it does not claim invariance for
arbitrary declaration permutations or other solver/parser configurations.

All four formulas exhaust the 500,000,000-unit cap as `unknown`.  None emits a
model, so A176 makes no model-recovery claim.

## Exact declaration-only intervention

The source SMT text has three preamble lines before its declarations.  Thus the
intervention changes:

- declaration-sequence indices **11 and 12**;
- physical zero-based SMT-text line indices **14 and 15**.

The only changed bytes are:

```text
(declare-fun x11 () Bool)
(declare-fun x12 () Bool)
```

becoming:

```text
(declare-fun x12 () Bool)
(declare-fun x11 () Bool)
```

For all four formulas:

- byte count is unchanged;
- declaration multiset is unchanged;
- every assertion byte is unchanged;
- every symbol name is unchanged;
- the `get-value (x0 ... x23)` order is unchanged;
- graph topology, semantics and model mapping are unchanged;
- a second swap recovers the exact original A174 bytes.

The declaration-swap digest is
`4825c92d507e2f06341ce01f170e206cf1a282bb777148142974d44eae409f1a`.
The complete declaration-plan digest is
`d52797f854631ebab0c2ce26bfc87d75cf62afa5f18e0d6289b3298f1f4753a9`.

## Frozen formulas

| Declaration-swapped graph | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `22,12` / inline | 8,899,711 | `dbdd463461907e309aa845a05668d3ef599acc861651009374fdc0f8af8464af` |
| `22,12` / materialized | 8,899,767 | `f51ea8bd7412fc4b0f8790a4fe7256b095b7de0ad886a5c416103ec47c705ed5` |
| `12,22` / inline | 8,899,711 | `f7c7eb8d643ff3027ce13623250d2d33cadb73076ed75e8bbf404d784d9c9253` |
| `12,22` / materialized | 8,899,767 | `3413f4208cd9b2470d0b31b13071985cda95831742515e1a51c0218a6241e7ee` |

The complete formula-plan digest is
`d7aaafcd4a03708f44b946172b28b7e0c7871f00b01f57c81972ec22de40c21d`.
All four inverse-permutation/affine model maps independently accept the known
complete-rate witness across all 1,344 bits and reject a corrupted assignment.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Swapped graph | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
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

Each is exactly equal to its A174 counterpart.  The canonical
declaration-boundary result digest is
`69055a782b8db1102d136004a7719a05fbd5c10fd918c2b8ff7a8f90321b727a`.

## Frozen classifier

Before execution, A176 fixed four exhaustive outcomes:

- all four canonical observations equal A174:
  `exact_input_declaration_order_invariance`;
- observations differ but swapped delta remains positive:
  `central_boundary_declaration_order_robust`;
- swapped delta is zero: `declaration_order_exact_boundary`;
- swapped delta is negative: `input_declaration_order_conditioned`.

All four observations are exact, so A176 selects the first branch before any
weaker directional rule is considered.

## Frozen information boundary

The protocol was frozen before any A176 solver execution at
`research/configs/shake_symbolic_r2_input_declaration_swap_boundary_v1.json`,
SHA-256
`3b8012e534608fdc3862100f219b19db035db082468f351dacd6998ce1354683`.

A175 selected the declaration-order question but no A176 formula arm, outcome
or resource limit.  The swap is derived only from the two A174 declaration
lines.  Neither the target rate nor the instrumented assignment enters the
transformation.  All four formula bytes were frozen before execution.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A175's
alpha-robust boundary, the x11/x12 declaration swap, four hash-bound
declaration-isomorphic formulas, their fixed-resource observations, and the
declaration-boundary result.  The edges form one provenance chain with no
inferred edges.  `CryptoCausalReader` verifies provenance and both retained
digests:

- Causal file SHA-256:
  `fbd04db4d0bb5a70924858308d69a9bf85dc679a605218adcdb406d052848e9a`;
- canonical graph SHA-256:
  `e0ef3a520cb0d02575cde8d40f9b2a04f1ab1d967371399763c6785d46022e90`.

## Retained bindings

- A176 result JSON:
  `4b609a6f4388c9a759625169aebe94309b808608e061b4f033c66a22cc992a60`;
- A175 result JSON:
  `1c432037567c74397b95d0d75c84a0eac406d63398e57c7214bdf7c730cb2894`;
- A174 result JSON:
  `e1683380ec9f5714d2c75a700b8dd2bf50f3b9cd5ee8106c48bb21f7c1b45eae`.

## Reproduction

Fast protocol, declaration-plan, byte-inverse, formula, model-map,
retained-artifact and Causal Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_input_declaration_swap_boundary.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_input_declaration_swap_boundary.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a176
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_input_declaration_swap_boundary.py \
  --work-dir "$PWD/build/shake-r2-a176"
```

## Consequence

A176 establishes exact input-declaration-order invariance for the tested
x11/x12 swap.  Reversing those two declarations changes neither the retained
solver counters nor the positive central-boundary direction.  Together with
A175, this separates two syntactic interventions: global numeric alpha names
can modulate one traversal, while this local declaration-order swap is fully
inert under the same fixed-resource solver protocol.
