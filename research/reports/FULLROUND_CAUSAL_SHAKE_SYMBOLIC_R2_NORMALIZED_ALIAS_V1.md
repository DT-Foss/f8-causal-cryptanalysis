# SHAKE Symbolic-R2 Normalized Materialized Alias Decomposition v1

## Result

A168 isolates the last syntax-level alternative left by A167.  It keeps the
negative R2 alias as the same connected state node, keeps every declaration ID
and every downstream assertion, and changes only its right-hand side from
`xor(true,x)` to the canonical `not(x)` spelling.  Exactly one assertion at
zero-based line 2,410 changes in each of the four full-round formulas.

All four A168 executions exhaust the frozen 500,000,000-unit Z3 resource cap
as `unknown`.  Decisions, conflicts, restarts and `rlimit-count` reproduce the
matched original A164/A163 controls exactly:

| Frozen input order | Original connected `xor(true,x)` | A168 connected `not(x)` | A166 inlined `not(x)` | RHS syntax effect, A168 - original | Connected-node removal, A166 - A168 |
|---|---:|---:|---:|---:|---:|
| weighted-degree descending | 5,339 | 5,339 | 7,347 | **0** | **+2,008** |
| weighted-degree ascending | 4,402 | 4,402 | 3,425 | **0** | **-977** |
| greedy maximum remaining weight | 6,870 | 6,870 | 5,247 | **0** | **-1,623** |
| greedy minimum remaining weight | 6,505 | 6,505 | 5,323 | **0** | **-1,182** |

The right-hand-side syntax effect has decision L1 magnitude zero.  Connected
node removal has decision L1 magnitude 5,790 and exactly reproduces A166's
complete order-dependent response: it helps three input orders and harms
descending.  Under this controlled intervention, the response comes from
removing the connected alias equality, not from spelling its Boolean
right-hand side as `xor(true,x)` rather than `not(x)`.

No run emits a model.  A168 is a deterministic full-round solver-component
decomposition, not a model-recovery claim.

## Single-assertion intervention

The three relevant representations now isolate every changed component:

1. **Original A164/A163 control:** coordinate 917 is a connected materialized
   alias `s1215 = xor(true,x_k)`, and all declarations use the original IDs.
2. **A168 syntax arm:** the same connected node is defined by
   `s1215 = not(x_k)`; every declaration and every other assertion is
   byte-identical to the original control.
3. **A166 node-removal arm:** the `not(x_k)` literal is inlined, the connected
   `s1215` definition disappears, and subsequent IDs shift by one.  A167 has
   already established that this ID shift contributes zero decisions.

For the four frozen input orders, the exact rewrites are:

| Order | Old assertion | New assertion | Rewrite SHA-256 |
|---|---|---|---|
| descending | `(assert (= s1215 (xor true x10)))` | `(assert (= s1215 (not x10)))` | `ece2e1c5a0bf46cd1b02e6084c712a313249108e5b4aacdd01a3561ae52bc955` |
| ascending | `(assert (= s1215 (xor true x14)))` | `(assert (= s1215 (not x14)))` | `9e0ec4c438cf69266fb6b922cb7e80f3d812908c69d83d83badb7f6988ff4a34` |
| greedy maximum | `(assert (= s1215 (xor true x8)))` | `(assert (= s1215 (not x8)))` | `7c2fe88c88928bb949fb81b8ebc0bd8b7d57eeb877695946183133d42a275300` |
| greedy minimum | `(assert (= s1215 (xor true x9)))` | `(assert (= s1215 (not x9)))` | `44ce0cdc5fcc98cb9d4f72eaf94ea08c25b6a87ea27d297af68c36bf3898c5a8` |

The declaration-sequence digest remains
`6ae51cff0ad3707df512db5933edd29dac9bf981b89b0201962ab1c1d79cfd61`.
Each formula still has 121,576 variables and 122,896 assertions.  The
connected node `s1215` occurs once as a declaration, once on the left-hand side
of its definition, and downstream wherever the original control used it.

The semantic relation is unchanged: the retained A152 SHAKE128 width-24
window, affine gauge `0x4e1e28`, four A158 input orders, shared R2 prefix, 22
unchanged Keccak suffix rounds and all 1,344 rate constraints.  The independent
pre-execution model-map gate recovers the complete known-rate witness in all
four representations and rejects a corrupted assignment.

## Frozen formulas

The complete intervention plan has SHA-256
`2c732672fdbe0ef5cb5549a3b5b73ac6c8042762d411032575cf54b1184c6944`.
The four exact formulas are:

| Frozen input order | Formula bytes | Formula SHA-256 | Original control source |
|---|---:|---|---|
| weighted-degree descending | 8,899,767 | `08c9b39e856abf5cfcb63b88b9f2170a218419aeb15ab7d50ff5590d3f463d8d` | A164 |
| weighted-degree ascending | 8,900,275 | `ef43719f879ffa43d79ef60deefdc9a4ef3854fc9cc6b17e4f2c9652bc7b5729` | A164 |
| greedy maximum remaining weight | 8,899,751 | `4dbe647c784bda9b81cc6f1dbc945a56d5e4903b5cfd3d699eebaa1c291a3162` | A163/A164 matrix cell |
| greedy minimum remaining weight | 8,900,254 | `3b65d808d948823f700e3c0868fedf8f22a1b49501cae73b87b17552b7da3a72` | A164 |

The complete formula-plan digest is
`ee4cad05d03be839c54034076272e71b1426b34975e943b66597479a9bb17db9`.

## Exact fixed-resource observations

The canonical result retains deterministic termination data and solver
counters while excluding volatile timing and memory fields:

| Order | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| descending | 5,339 | 2,222 | 2 | 501,080,369 | 444,833,576 | 119,108,978 |
| ascending | 4,402 | 2,189 | 6 | 501,079,875 | 446,080,239 | 119,185,158 |
| greedy maximum | 6,870 | 2,431 | 3 | 501,080,261 | 444,872,402 | 118,778,683 |
| greedy minimum | 6,505 | 3,292 | 4 | 501,079,923 | 446,410,890 | 117,961,641 |

The first three complete canonical observations are bit-identical to their
original controls.  Their observation digests are, in table order:

- `2642afbf9c2658785db4a3d59dd8174a02a76f2c8d324d9ea0a1300d6a84331d`;
- `bc3d35fc887cbf22849d38b04e5af82d69a110743bd84a54726af1d53be95d2a`;
- `0e00325f48483c82c2e42cfac54d84e581b165f7313011bd53d907fca0fa05bf`.

The greedy-minimum observation keeps the original decisions, conflicts,
restarts and resource count but differs by +78 propagations and -29 binary
propagations.  Its A168 observation digest is
`ed01a0daf54341fd2ead04360dbb645970e03a881bde8cef044385710a5326ad`;
the original digest is
`46d776f3609c0ac0c1334b918e15f8500bf73cf5de6ab02b46ac557eb031d445`.
The exact conclusion is therefore zero RHS-syntax effect on decisions in all
four orders, not identity of every internal solver counter in all four.

The additive identity

`A166 - original = (A168 - original) + (A166 - A168)`

holds independently in every order.  The canonical decomposition SHA-256 is
`138cfc343738d5d5ad4a52ebb7825c1932ad2ef314f0cdfbd7f228097b774f48`.

## Frozen information boundary

The protocol was frozen before every A168 execution at
`research/configs/shake_symbolic_r2_normalized_materialized_alias_frontier_v1.json`,
SHA-256
`b2f19699536817ed64ef31cf80015ab5ab7fb977b4f670a8682740ea99c0f7ab`.

A167's completed result selected the single-assertion syntax question.  It did
not select any A168 order, formula or resource limit after the formulas were
frozen.  No target rate, target value or instrumented assignment selected the
intervention.  Assignment 9,279,571 is read only after all four executions;
because every run is `unknown`, each posthoc model-match field is `null`.

Wall-clock, memory, allocation, stdout and stderr measurements are absent from
the canonical artifact.

## Causal Reader gate

The retained Causal file contains exactly five explicit edges: A167's
connected-node question, the one-line RHS rewrite, the four hash-bound
full-round formulas, their fixed-resource executions, and the exact
syntax-versus-node decomposition.  They form one provenance chain with no
inferred edges.  `CryptoCausalReader` verifies the file and graph digests:

- Causal file SHA-256:
  `a26f1fe696cc842a93e08d230c2d9707cf13b2670be359212f49e9e7685a2277`;
- canonical graph SHA-256:
  `c1fe0277fa2d792f0c9f72cf1b2d4c0ad4eb264b6dcc328edb3e619d8b66a2c0`.

## Retained bindings

- A168 result JSON:
  `becb3013cb079c2d45ee2a297d2847d5d85542843cb598e5b6288dc45b9eab76`;
- A167 result JSON:
  `24ad17ce715c3471bef30979a16e973f742163931e9cd9e4acae93562f00fcdc`;
- A166 result JSON:
  `e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db`;
- A164 result JSON:
  `c8b4f7446b3e78b3914f90e5fbbc201d00771a917c7fafe16eba6e134e0f55ab`.

## Reproduction

Fast protocol, one-line rewrite, formula, model-map, retained-artifact and
Causal Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_normalized_materialized_alias_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_normalized_materialized_alias_frontier.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a168
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_normalized_materialized_alias_frontier.py \
  --work-dir "$PWD/build/shake-r2-a168"
```

## Consequence

A168 closes the RHS-spelling explanation at the decision-count level for all
four frozen input orders.  Together A167 and A168 isolate A166's entire
decision response to the presence or absence of the connected negative-alias
equality: downstream ID renumbering contributes zero decisions, and
`xor(true,x)` versus `not(x)` contributes zero decisions while the node is
retained.  The remaining mechanism is the order-dependent solver graph effect
of that connected alias node itself.
