# SHAKE Symbolic-R2 ID-Preserving Alias Decomposition v1

## Result

A167 separates the two changes that A166 made to A164's four full-round
SHAKE128 formulas: removing the connected negative-alias node and shifting all
subsequent solver declaration IDs.  It inlines the same exact R2 complement
alias as A166, but inserts one disconnected Boolean declaration, `s1215`, at
the original alias position.  Every downstream declaration ID is therefore
bit-for-bit identical to A164 while the semantic relation and A166's alias
normalization remain unchanged.

All four A167 executions exhaust the frozen 500,000,000-unit Z3 resource cap
as `unknown`.  Their decision counts are exactly A166's:

| Frozen input order | A164 connected alias, original IDs | A167 inlined alias, original IDs | A166 inlined alias, shifted IDs | Alias-node effect, A167 - A164 | ID-shift effect, A166 - A167 |
|---|---:|---:|---:|---:|---:|
| weighted-degree descending | 5,339 | 7,347 | 7,347 | **+2,008** | **0** |
| weighted-degree ascending | 4,402 | 3,425 | 3,425 | **-977** | **0** |
| greedy maximum remaining weight | 6,870 | 5,247 | 5,247 | **-1,623** | **0** |
| greedy minimum remaining weight | 6,505 | 5,323 | 5,323 | **-1,182** | **0** |

Under this exact three-arm intervention, the signed-alias decision effect has
L1 magnitude 5,790 and the downstream declaration-ID-shift decision effect has
L1 magnitude zero.  Thus A166's complete per-order decision changes are
attributable to removal of the connected alias node, not to its downstream ID
renumbering.  The established order interaction remains exact: alias removal
helps three orders and harms descending.

None of the four runs emits a model.  A167 is a deterministic full-round
compiler-component decomposition, not a model-recovery claim.

## Controlled three-arm intervention

The three representations differ in exactly the intended component:

1. **A164 control:** R2 coordinate 917 is materialized as the connected
   equality node `s1215 = NOT x12`; all later declarations use the original
   IDs.
2. **A166 intervention:** the complement literal is inlined and the `s1215`
   declaration disappears; every subsequent solver ID shifts by one.
3. **A167 isolation arm:** the complement literal remains inlined, while a
   disconnected `s1215` declaration occupies the original position; all
   subsequent declaration IDs return exactly to A164's sequence.

The A167 declaration-sequence digest is
`6ae51cff0ad3707df512db5933edd29dac9bf981b89b0201962ab1c1d79cfd61`
for every order and is exactly the A164 digest.  `s1215` occurs once as a
declaration and zero times in assertions.  Each formula has 121,576 declared
variables and 122,895 assertions: A164's variable count, with the one connected
alias assertion removed.

The complete relation remains fixed: the retained A152 SHAKE128 width-24
window, gauge `0x4e1e28`, the same four A158 orders, the shared R2 prefix, 22
unchanged Keccak suffix rounds, and all 1,344 rate constraints.  Model maps are
unchanged and independently recover the complete known-rate witness during the
pre-execution gate; a corrupted assignment is rejected.

## Frozen formulas

The protocol froze every formula and control identity before any A167 solver
execution.  The four regenerated formulas are:

| Frozen input order | Formula bytes | Formula SHA-256 | Original control source |
|---|---:|---|---|
| weighted-degree descending | 8,899,746 | `820a8194d49d916fc8a758e06b4caf2f0f39ca1653340c0a8aa704da63e29095` | A164 |
| weighted-degree ascending | 8,900,254 | `21e6f5e9f5c4369d60eb19cb971d92e5d6fe67142df7ba69faf47ac14cf2f6ca` | A164 |
| greedy maximum remaining weight | 8,899,729 | `b185f101a58c369d915a329cb194da1c7965e46cbe3492dd6688e46517a53ffa` | A163/A164 matrix cell |
| greedy minimum remaining weight | 8,900,232 | `55575f27f1524e9382adf77c2535c1f0e8932cff3afc97b472d5e176a196f14c` | A164 |

The complete formula-plan digest is
`ecdd9c3d43173ae07921f635c831bc67223215589d6aeaff17032d146c8a03cc`;
the matched-control plan digest is
`055c3c829573cbe39c783a686fbe2fc9665ec081b6857cdad04d8133a55650e7`.

## Exact fixed-resource observations

The retained canonical observations contain deterministic status, termination,
return code and solver counters only:

| Order | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | A167 - A166 | Binary propagations | A167 - A166 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| descending | 7,347 | 2,557 | 8 | 501,080,364 | 444,907,485 | +1,224 | 118,110,635 | +19 |
| ascending | 3,425 | 2,831 | 7 | 501,079,870 | 446,266,704 | -311 | 118,765,094 | -26 |
| greedy maximum | 5,247 | 2,233 | 3 | 501,080,256 | 444,843,241 | +130 | 118,828,202 | +46 |
| greedy minimum | 5,323 | 2,402 | 6 | 501,079,918 | 446,144,254 | +164 | 119,417,006 | +131 |

Decisions, conflicts, restarts and `rlimit-count` match A166 exactly for every
order.  Raw propagation counts do not: their A167-minus-A166 differences are
`[1224, -311, 130, 164]`, and the binary-propagation differences are
`[19, -26, 46, 131]`.  The retained conclusion is therefore an exact zero
decision effect for downstream ID shifting, not a claim that every internal
solver counter is bit-identical.

The four canonical observation digests, in table order, are:

- `ab6168baadc3191e523614b4d18e4f87b8b5644edc7c9d06d58ec04d12bf3e0d`;
- `618197b2ad48f4fb124acf2bbb115a960bca17ce7f520dff9d271052f03a593f`;
- `696daccf9b51d8605d64c0dc3dfc5ff9e668e66652c8a86e191226a541e6b39a`;
- `874209fcc6d34e8e45438818dc7da5b19617e54d0feb95b2b5778ce89f80864b`.

The exact additive decomposition

`A166 - A164 = (A167 - A164) + (A166 - A167)`

holds independently in every order.  Its canonical digest is
`524a5f785e461ba210652f3337be915ecac06ff4e8cf7701a58de51caaebcfde`.

## Frozen information boundary

The protocol was frozen before all A167 executions at
`research/configs/shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json`,
SHA-256
`a26e101e0d7e993dd5cd27485adf0e4d04e4f30f7c3c42a25db7a22ddee9d1c9`.

A166's completed outcomes were used to select the ID-preserving decomposition
question.  They were not used to choose an A167 order, formula, or resource
limit after formula generation.  A164 and A163 formulas were regenerated only
to bind their original declaration IDs.  No target rate, target value, or
instrumented assignment selected the isolation arm.  The instrumented
assignment 9,279,571 was read only after every A167 execution; since all four
runs are `unknown`, every posthoc model-match field is `null`.

Wall-clock, memory, allocation, stdout and stderr measurements are absent from
the canonical result.

## Causal Reader gate

The five-edge Causal graph records the A164 connected-alias control, A166
inlined-alias/shifted-ID arm, A167 inlined-alias/original-ID arm, the four fixed
resource observations, and the exact two-component decomposition.  The edges
form one explicit provenance chain with no inferred edges.
`CryptoCausalReader` reopens the artifact and verifies both its file hash and
canonical graph digest:

- Causal file SHA-256:
  `c922135a3a191c33a393a43d649b6eb595de34aadc36cd5ec20e45c063f81419`;
- canonical graph SHA-256:
  `4c5d50f49327f380b1748cdee878c93a96ef4bfbcadd406ea639f03d58796843`.

## Retained bindings

- A167 result JSON:
  `24ad17ce715c3471bef30979a16e973f742163931e9cd9e4acae93562f00fcdc`;
- A166 result JSON:
  `e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db`;
- A166 comparison:
  `1977e8c279a7d965f4723dc60de25e26a9a39b95eabcd2293d1b670cddc65418`;
- A164 result JSON:
  `c8b4f7446b3e78b3914f90e5fbbc201d00771a917c7fafe16eba6e134e0f55ab`.

## Reproduction

Fast protocol, declaration-ID, formula, model-map, retained-artifact and Causal
Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_id_preserving_signed_alias_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_id_preserving_signed_alias_frontier.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a167
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_id_preserving_signed_alias_frontier.py \
  --work-dir "$PWD/build/shake-r2-a167"
```

## Consequence

A167 closes the declaration-ID-shift explanation at the decision-count level
for all four frozen orders.  Removing the connected complement-alias node is
the complete source of A166's decision changes in this controlled comparison;
renumbering downstream declarations contributes zero decisions in every cell.
The remaining mechanism is therefore specifically tied to solver processing
of the connected negative-alias equality and its interaction with input order,
not to a generic one-position downstream ID perturbation.
