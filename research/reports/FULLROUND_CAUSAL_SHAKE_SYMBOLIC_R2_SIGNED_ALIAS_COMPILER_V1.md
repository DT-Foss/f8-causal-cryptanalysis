# SHAKE Symbolic-R2 Signed-Alias Compiler Frontier v1

## Result

A166 tests two exact explanations for A164's universal `0x4e1e28` affine
gauge on the retained full-round A152 SHAKE128 relation.

First, it propagates syntactic path multiplicities backward from all 1,344
final rate constraints through every suffix depth from zero to 22 Keccak
rounds.  The exact static suffix-cone objective selects `0x498a92` at every
depth.  It never selects A164's `0x4e1e28` winner.  Static affine incidence in
the compiled suffix cone is therefore not the mechanism behind A164's
four-order result.

Second, A166 proves that the shifted R2 interface contains exactly five
unit-affine coordinates and normalizes both literal polarities in the compiler.
For gauge `0x4e1e28`, the old compiler directly substituted four positive
aliases but materialized the fifth coordinate, `917 = NOT x12`, as a separate
variable and assertion.  The signed compiler substitutes all five aliases,
removing exactly one variable and one assertion from every formula without
changing the relation, order, suffix rounds, target assertions, model mapping,
or fixed solver resource.

The four retained fixed-resource observations are:

| Frozen input order | A164 decisions | A166 decisions | Decision delta | A164 conflicts | A166 conflicts | Conflict delta | A166 `rlimit-count` |
|---|---:|---:|---:|---:|---:|---:|---:|
| weighted-degree descending | 5,339 | 7,347 | **+2,008** | 2,222 | 2,557 | **+335** | 501,080,364 |
| weighted-degree ascending | 4,402 | **3,425** | **-977** | 2,189 | 2,831 | **+642** | 501,079,870 |
| greedy maximum remaining weight | 6,870 | 5,247 | **-1,623** | 2,431 | 2,233 | **-198** | 501,080,256 |
| greedy minimum remaining weight | 6,505 | 5,323 | **-1,182** | 3,292 | 2,402 | **-890** | 501,079,918 |

The mixed decision signs resolve the frozen interpretation rule: signed-alias
normalization interacts with input order.  It improves three orders and makes
weighted-degree descending worse.  It is not a uniform explanation for the
`0x4e1e28` advantage.  The ascending cell establishes a new fixed-resource
traversal minimum of 3,425 decisions, 977 decisions or 22.2% below A164's
4,402 minimum, while representing the identical full-round relation.

All four executions terminate as `unknown` by exhausting the common
500,000,000-unit Z3 resource cap.  None emits a model.  A166 is an exact
semantics-preserving full-round compiler intervention and traversal result, not
a model-recovery claim.

## Exact suffix-cone boundary

The suffix Reader starts with unit weight on each of the 1,344 final SHAKE128
rate constraints and zero weight on the 256 capacity coordinates.  At each
depth it propagates exact syntactic path multiplicity backward through the
compiled Keccak suffix DAG and scores the four A162 gauges against their
shifted R2 affine incidences.

The round-backward operator preserves nonnegativity and multiplies total path
weight by exactly 33.  Across all 23 declared depths, the unique minimum is
`0x498a92`; the winner sequence contains no other gauge.  These exact bindings
are:

- suffix-cone plan:
  `b7163b88f68faf3bf8bca58c82ccb617bd060b260c23dd0cdefb92cad24538dc`;
- complete structural analysis:
  `ba3acec7cfcbf7f10e5f1fe1bc98b77a1a47aff7d85e64629319537426da75cd`.

This closes the static path-incidence hypothesis for the A164 winner.  The
remaining mechanism must include information absent from this objective, such
as elimination dynamics coupled to literal polarity and order.

## Exact signed unit-affine theorem

The five and only five unit-affine R2 coordinates are:

| R2 state coordinate | Lane | Bit | Input coordinate | Original constant | Literal under `0x4e1e28` |
|---:|---:|---:|---:|---:|---|
| 453 | 7 | 5 | 11 | 1 | positive |
| 516 | 8 | 4 | 15 | 0 | positive |
| 917 | 14 | 21 | 12 | 0 | **negative** |
| 990 | 15 | 30 | 12 | 1 | positive |
| 1,454 | 22 | 46 | 11 | 1 | positive |

The theorem digest is
`64c7ae36eb2c763dd29ac983addaf493b46b067b8debc78a5a218de7d531a7dc`.
The A166 compiler lowers each coordinate directly to either `x_i` or
`NOT x_i`.  Every rendered formula has 1,595 R2 state definitions, 121,575
total variables, and 122,895 total assertions.  Against A164's compiler this
is exactly one fewer definition, variable, and assertion per order.

The four exact formula hashes were frozen before solver execution under plan
digest
`fd2ed7f25529335e7403aafc638d21fa07a99e8bde81333518e4e8fdbb4a25f7`.

| Frozen input order | Formula bytes | Formula SHA-256 |
|---|---:|---|
| weighted-degree descending | 8,899,711 | `f5e9d9843c5ff13fb3df020aaa74313ab2787487b2e51d7b872b6f4263484724` |
| weighted-degree ascending | 8,900,219 | `eab43da12ff6fb5afa4e62fd6d23093cad7490c8220a24bf657e7e594aa9e7f8` |
| greedy maximum remaining weight | 8,899,694 | `f330e85d8602ac070b398bc6c50355d1392d7e76e5ef66dffcfad39b8e020407` |
| greedy minimum remaining weight | 8,900,197 | `c517f3bb2b275cc37c8a97368c1fe458b2279f8fc10d6c48e7f31b745f6f61fd` |

## Frozen information boundary

The protocol was written before every A166 solver execution at
`research/configs/shake_symbolic_r2_signed_alias_compiler_frontier_v1.json`,
SHA-256
`6c35f7d94045a9941f8ad72ceaa9e43471ff23c4757be2ed4e1d3887b588b77f`.

A164 solver counters were used only to identify the already established
four-order gauge winner.  They were not used to select signed-alias
normalization.  No target bit, target rate value, instrumented assignment, or
A166 observation entered the cone rule, compiler intervention, formula order,
or formula bytes.  The instrumented assignment 9,279,571 was read only after
all four executions and was not used by any production query.

The retained result excludes wall-clock, memory, allocation, stdout, and
stderr fields.  Each canonical observation contains only status, termination,
return code, and deterministic solver counters.  Their hashes are:

- descending:
  `73a8bac52b4f6dd9443d6d3c33a8961f296779d5b88f995ee086aca776be7486`;
- ascending:
  `f8d58597b2b0c00936d27c25811766df8cd50005ed4c07150a47d155ca4db2b7`;
- greedy maximum:
  `c68872d342e6e2f22cca39abea0b7fb75009289fc067324fb0762849eacdc56e`;
- greedy minimum:
  `b62ce10efe662101940d1ea4fc3e44657dfabe311f50b01d7f9d58e1744297a5`.

## Model and Causal gates

Before production, every formula's inverse order and affine model map recovers
the complete known rate witness under the independent 24-round, 1,344-bit
implementation; a corrupted assignment is rejected.  Production yields no
model, so `confirmed_models` is empty.

The five-edge Causal graph records, in order, the A164 universal gauge anchor,
the cone boundary and unit-affine theorem, four signed-alias formulas, four
fixed-resource observations, and the matched A164 intervention comparison.
`CryptoCausalReader` reopens the file and verifies the complete provenance
chain.

## Retained bindings

- A166 result JSON:
  `e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db`;
- intervention comparison:
  `1977e8c279a7d965f4723dc60de25e26a9a39b95eabcd2293d1b670cddc65418`;
- A166 Causal artifact:
  `2768b97542a5f3c90339def61c1bc61cf719b253d7e04ec2badc5983a55be641`;
- canonical Causal graph:
  `83229c065fdeefc654f65339b00f627301b1fb063e0dac55b2c710884c244f11`.

## Reproduction

Fast protocol, structural theorem, formula, model-map, artifact, observation,
and Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_signed_alias_compiler_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_signed_alias_compiler_frontier.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a166
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_signed_alias_compiler_frontier.py \
  --work-dir "$PWD/build/shake-r2-a166"
```

## Consequence

A166 removes two candidate explanations with exact interventions.  Static
suffix-cone affine incidence chooses the wrong gauge at every depth, and the
only previously materialized negative alias has a mixed, order-dependent
effect when eliminated.  The retained breadcrumb is therefore narrower and
stronger: the next predictor must model solver elimination dynamics jointly
with order and polarity, while the ascending signed-alias formula supplies the
new 3,425-decision full-round traversal baseline.
