# SHAKE Symbolic-R2 Alias-Fanout Möbius Decomposition v1

## Result

A169 resolves the connected negative R2 alias from A168 into its two exact
first-suffix-round consumers.  For every frozen input order it preserves the
alias definition and exactly one consumer, while replacing the other consumer
with the equivalent direct negative input literal.  The two consumers are the
column node `c2173` and theta node `t3453`.  This creates the missing fanout-one
arms between A166's fanout-zero formulas and A168's fanout-two formulas without
changing the represented SHAKE relation.

All eight A169 formulas exhaust the same 500,000,000-unit Z3 resource cap as
`unknown`.  Joined with the hash-pinned A166 and A168 observations, they give
an exact two-factor Boolean-lattice Möbius decomposition of decision counts:

| Frozen input order | Fanout 0: inline | Fanout 1: column | Fanout 1: theta | Fanout 2: both | Column main | Theta main | Interaction | Total materialization |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| weighted-degree descending | 7,347 | 5,499 | 5,188 | 5,339 | **-1,848** | **-2,159** | **+1,999** | **-2,008** |
| weighted-degree ascending | 3,425 | 4,383 | 4,263 | 4,402 | **+958** | **+838** | **-819** | **+977** |
| greedy maximum remaining weight | 5,247 | 5,873 | 5,939 | 6,870 | **+626** | **+692** | **+305** | **+1,623** |
| greedy minimum remaining weight | 5,323 | 6,138 | 5,856 | 6,505 | **+815** | **+533** | **-166** | **+1,182** |

The component L1 magnitudes are 4,247 decisions for the column main effect,
4,222 for the theta main effect, and 3,289 for the interaction.  Every order
has a nonzero interaction.  The connected-alias response therefore does not
belong to one suffix consumer alone and is not the sum of two independent
single-consumer effects.  Both consumers contribute nearly equal aggregate
main-effect magnitude, and their joint solver-graph interaction is substantial
and changes sign by order.

No execution emits a model.  A169 is an exact fixed-resource decomposition of
full-round solver traversal, not a model-recovery result.

## Exact fanout intervention

The negative unit-affine R2 coordinate is retained as the connected equality
`s1215 = not(x_k)`.  In the original A168 formula, the node has exactly two
downstream uses in the first generic suffix round:

- column consumer: `c2173 = xor(s577,s895,s1215,s1534,s1853)`;
- theta consumer: `t3453 = xor(s1215,d2493)`.

Each A169 arm changes exactly one of those assertions:

1. **column-only materialization:** preserve the `s1215` use in `c2173` and
   inline `not(x_k)` into `t3453`;
2. **theta-only materialization:** preserve the `s1215` use in `t3453` and
   inline `not(x_k)` into `c2173`.

The `s1215` declaration and definition remain connected in both arms.  Every
formula still has 121,576 variables and 122,896 assertions.  Declaration
sequences are identical to A168, the changed-line count is exactly one, and
the complete shared-R2 prefix, 22 suffix rounds and 1,344 rate constraints are
unchanged.  The formula gates also verify the known complete-rate witness
through every model map and reject a corrupted assignment before execution.

The fanout plan digest is
`b1476bcf5eeb3a03cf22d8fa7e09391e96d3150027e191125bdd248650dc68c3`.
The complete formula-plan digest is
`c321e346f7edb78ff69c83bc1998b3156bfe0481236da6b775b29422760ea535`.

## Frozen formulas and rewrite gates

| Frozen input order | Retained consumer | Formula bytes | Formula SHA-256 | Rewrite line | Rewrite SHA-256 |
|---|---|---:|---|---:|---|
| descending | column | 8,899,771 | `77f2d234359d03c4a497ca86d28a9d1d9c95d375f39d5f14a4f94ac8435716a4` | 6,886 | `7f6592e3c47643729f07947309be9666b9fe73886c4516f006ac4113ecad152c` |
| descending | theta | 8,899,771 | `af34834afa430dba9a28ca92ff9d28f7cf203cb440657113ffdfcaeadf28edc7` | 4,326 | `d4b5c579036cc40176a5dc719e69b943107a55e6642ab963997455ba29f7c455` |
| ascending | column | 8,900,279 | `6ba909d46a0ebe60cced50a2e698061480c536daef8a9a1a0abcb3edde687d39` | 6,886 | `997d13841d8ca85230c3772029edee9f3f663adee083fcb776bb99c1925c3791` |
| ascending | theta | 8,900,279 | `37062d68a0110c8f4b930b69317bbdee4d3eb5bdc731823f77c33743e96e226d` | 4,326 | `8c5fb280a15bd8dd79b621392dead9edc152c5baa70730ee2cdfe09408014cc0` |
| greedy maximum | column | 8,899,754 | `051fde4f39816a35b0ecd997522315453e8aaeb4dfea5b022b4c49d41e976736` | 6,886 | `a7a399d6bde539e0f786b24155439841476539a0513f897bb24185379692fbde` |
| greedy maximum | theta | 8,899,754 | `9fcfb59924ad1cbfd98c74b0bdc85e30cf4cb910b2a8783e8478050a4c1d07c8` | 4,326 | `ffd20ed0385e896e7eff40684adc7cc443eb82c6c34e5752942aaac101d0e8cb` |
| greedy minimum | column | 8,900,257 | `c06e1267c3dd38cffd39beba655d2218bd8d69be7992a17854be452516130781` | 6,886 | `41e3aa8b09cdf85f27bdd1a8f56890fb2d1d919b7b6552c4e02f9b5c84700266` |
| greedy minimum | theta | 8,900,257 | `ed1cab808c1d3c24427d4bc5d92cce35e854365a0ffe58ff20650284c7c02a4c` | 4,326 | `8b925520c35fb2e7dd20cf336bfc59a1a2a5957f6a21ab440f487f371132bbe3` |

All line indices are zero-based.  Column-only arms change line 6,886 from
`t3453 = xor(s1215,d2493)` to the matching direct negative literal.  Theta-only
arms change line 4,326 from the `s1215` input of `c2173` to that same literal.
The input identifier is `x10`, `x14`, `x8` or `x9` in descending, ascending,
greedy-maximum or greedy-minimum order respectively.

## Exact fixed-resource observations

The retained artifact stores the deterministic status, return code,
termination reason and solver counters for every formula.  Volatile wall-clock,
memory, allocation, stdout and stderr fields are excluded.

| Order / retained consumer | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| descending / column | 5,499 | 2,246 | 4 | 501,080,367 | 444,826,315 | 118,712,650 |
| descending / theta | 5,188 | 2,456 | 7 | 501,080,375 | 444,893,232 | 118,702,111 |
| ascending / column | 4,383 | 2,318 | 2 | 501,079,873 | 446,138,641 | 119,498,024 |
| ascending / theta | 4,263 | 2,781 | 6 | 501,079,881 | 446,263,168 | 118,162,048 |
| greedy maximum / column | 5,873 | 2,315 | 4 | 501,080,259 | 444,831,840 | 118,317,115 |
| greedy maximum / theta | 5,939 | 2,650 | 9 | 501,080,267 | 444,982,028 | 117,860,291 |
| greedy minimum / column | 6,138 | 2,300 | 8 | 501,079,921 | 446,109,425 | 120,176,721 |
| greedy minimum / theta | 5,856 | 2,326 | 5 | 501,079,929 | 446,087,673 | 118,535,196 |

The canonical observation digests, in table order, are:

- `7957eae9846159797058d8308e80fdf3ff52a213aa03fb0812fed918c6a9c748`;
- `877b1c711733ecfdf5ddbc747c3572625df04aee83f610be62ca685d623a1398`;
- `06b3e85fde14a661f3531e5cf4356433b5ecf3fe6c7d71c1a390bd64c9227237`;
- `3579f4c11d8e22868e5db85508b04bea41463482773f8e34d85b986caefe3d60`;
- `2db59bd7962576b195c85783dfc505d46fe54f0d2c11a57b039975cb66f8cc55`;
- `5e9e62b12ae77d6b756df799bb2f7102588bf96417ccb308a7cb0ab83249c68e`;
- `1c20bedd3c790c719ec86428b0dc261b355e86ec6c45c721ec4d285a47f5f0c7`;
- `ca712ca7ed95fe4afb16bfd3941d513245849f960ccf72eb8dd60c42536295f9`.

## Exact Möbius identity

For each order, let `y00` be A166 with the alias literal inlined into both
consumers, `y10` retain only the column consumer, `y01` retain only the theta
consumer, and `y11` be A168 with both consumers connected.  A169 computes:

- column main effect: `y10 - y00`;
- theta main effect: `y01 - y00`;
- fanout interaction: `y11 - y10 - y01 + y00`;
- total materialization effect: `y11 - y00`.

The identity

`total = column main + theta main + interaction`

holds exactly in every order.  The canonical decomposition digest is
`af6b94835b169aeb9ef0e32b721623c0536ccb0e98cb1c156508f419907ec2ea`.

The descending interaction cancels almost half of the two beneficial main
effects.  Ascending has two harmful main effects partly cancelled by a negative
interaction.  Greedy maximum combines two harmful main effects with an
additional harmful interaction, while greedy minimum receives a modest
beneficial interaction against two harmful main effects.  The four distinct
sign/magnitude profiles are the exact order-dependent fanout mechanism exposed
by the experiment.

## Frozen information boundary

The protocol was frozen before any A169 solver execution at
`research/configs/shake_symbolic_r2_alias_fanout_mobius_frontier_v1.json`,
SHA-256
`a6849d51cccea60744fd45d97d734bbdc25efd82fc52aab8cd41deb786cd9f88`.

A168's completed result selected the two-consumer decomposition question.  It
did not select any A169 formula order, resource limit or single-consumer
outcome after the formulas were frozen.  Neither the target rate nor the
instrumented assignment selected a fanout arm.  Assignment 9,279,571 is read
only after all eight executions, and all eight posthoc match fields are `null`
because every solver result is `unknown`.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A168's
single connected alias, the exact two-consumer graph, the eight hash-bound
single-consumer formulas, their fixed-resource observations, and the exact
fanout Möbius decomposition.  The edges form one provenance chain with no
inferred edges.  `CryptoCausalReader` verifies provenance plus both retained
digests:

- Causal file SHA-256:
  `8937dffd71decf04159f06bfec1fbecfab41cb571a232587b4b609def3a9e0a8`;
- canonical graph SHA-256:
  `eb1a0329f1ec23822187b5b1e8f13dc52a5282947ac3f5f52bf01986be4c4956`.

## Retained bindings

- A169 result JSON:
  `b19c1b85bfad77c5e7aa909ba11a02821fce21f6603daa3174bfe5899a0c1334`;
- A168 result JSON:
  `becb3013cb079c2d45ee2a297d2847d5d85542843cb598e5b6288dc45b9eab76`;
- A166 result JSON:
  `e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db`.

## Reproduction

Fast protocol, fanout, formula, model-map, retained-artifact and Causal Reader
gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_alias_fanout_mobius_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_alias_fanout_mobius_frontier.py
```

Full sequential eight-formula execution:

```bash
rm -rf build/shake-r2-a169
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_alias_fanout_mobius_frontier.py \
  --work-dir "$PWD/build/shake-r2-a169"
```

## Consequence

A169 closes the single-consumer explanation for the connected negative-alias
effect.  Neither `c2173` nor `t3453` alone accounts for the response.  Their
aggregate main-effect magnitudes differ by only 25 decisions, every order has
a nonzero interaction, and that interaction carries 3,289 decisions of L1
magnitude.  The exact breadcrumb is therefore the joint two-consumer solver
graph and its interaction with input order, not an isolated suffix edge.
