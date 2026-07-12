# SHAKE Symbolic-R2 Reversed-Order Alias-Polarity Frontier v1

## Result

A170 tests whether exact reversal of the complete 24-coordinate solver input
order universally reverses the decision-count polarity of A169's connected
negative-alias response.  It does not.  Two order pairs flip polarity and two
preserve it:

| Frozen base order | Base effect | Reversed inline | Reversed materialized | Reversed effect | Polarity |
|---|---:|---:|---:|---:|---|
| weighted-degree descending | -2,008 | 6,735 | 5,454 | **-1,281** | preserved |
| weighted-degree ascending | +977 | 8,543 | 5,645 | **-2,898** | flipped |
| greedy maximum remaining weight | +1,623 | 5,159 | 4,217 | **-942** | flipped |
| greedy minimum remaining weight | +1,182 | 4,693 | 5,711 | **+1,018** | preserved |

Effects are `materialized decisions - inline decisions`.  Negative values mean
that retaining the connected negative-alias node uses fewer decisions at the
fixed resource boundary; positive values mean that inlining it uses fewer.
The exact reversed effects are `[-1281,-2898,-942,+1018]`.  Therefore complete
order orientation alone is neither a universal polarity flip nor a universal
polarity-preservation rule.  The retained boundary is the mixed response
`2 flipped / 2 preserved / 0 zero`.

All eight formulas represent the same retained full-round SHAKE128 relation and
all eight exhaust the 500,000,000-unit Z3 resource cap as `unknown`.  A170 is a
paired fixed-resource solver-traversal intervention, not a model-recovery
result.

## Prospective reversal intervention

The protocol reverses each complete A158-derived order vector:

`reversed_order = list(reversed(base_order))`.

Every reversal is a permutation of all 24 coordinates, is an exact involution,
is distinct from its base vector, and was absent from the four base orders.
The negative-alias input coordinate moves from solver positions 10 to 13, 14
to 9, 8 to 15, and 9 to 14 for descending, ascending, greedy-maximum, and
greedy-minimum respectively.  Each pair sums to 23, as required by exact
reversal.

No SHAKE semantics change.  The affine gauge remains `0x4e1e28`; the shared R2
prefix, all 22 suffix rounds, and all 1,344 rate constraints are unchanged.
Each reversed order receives the same two compiler arms:

- **inline:** the negative unit-affine alias is inlined, yielding 121,575
  variables and 122,895 assertions;
- **materialized:** the normalized connected alias node is retained, yielding
  121,576 variables and 122,896 assertions.

The reversal-plan digest is
`ad32560fae33eac765403ae6cc5de579ca13d07561707c78a75ce740870c661a`.
The complete formula-plan digest is
`7f23984189baf93086fec55ab053d2396d9e48855ddaeef55ec1298e13201f68`.

## Frozen formulas

| Reversed order / arm | Formula bytes | Formula SHA-256 |
|---|---:|---|
| descending / inline | 8,900,219 | `8906897c35310a08afe3a9eb5f6f411d8d244547d0401a525107a483d38aa25c` |
| descending / materialized | 8,900,275 | `7a7394570d07eeaff46f100a2091fda57afa25a774c7402748f911838694bafd` |
| ascending / inline | 8,899,679 | `0e4f73be83500b4a0de23d96d7467e0edf63323b904729129c5006348db229f8` |
| ascending / materialized | 8,899,736 | `0895eeb15b51628be63633bf81462299d5ea6cd793dc39c238dd23828f9c0585` |
| greedy maximum / inline | 8,900,242 | `89381620ea9e766af21f35d80011ab7772b90a3d3668f5cc5cc32f60765241a9` |
| greedy maximum / materialized | 8,900,298 | `2621f5939fbb6e6bfaf2c293054429263282ad52c9c3526803ff1c2044812c0e` |
| greedy minimum / inline | 8,899,708 | `280a345ce28c55fea735b48b6c209f07f0f5e5021715f7c3056478bda4ee928e` |
| greedy minimum / materialized | 8,899,764 | `376775bc43a872597b6b84c6664e48db13b50f6aeb768bb61d7bea19407db6db` |

The formula plan was frozen before any A170 solver execution.  Every formula
map independently accepts the known complete-rate witness and rejects a
corrupted assignment before execution.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Reversed order / arm | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| descending / inline | 6,735 | 2,569 | 5 | 501,079,864 | 446,177,696 | 118,747,520 |
| descending / materialized | 5,454 | 2,551 | 9 | 501,079,869 | 446,182,164 | 117,927,172 |
| ascending / inline | 8,543 | 2,652 | 10 | 501,080,360 | 444,930,912 | 117,798,350 |
| ascending / materialized | 5,645 | 2,430 | 14 | 501,080,365 | 444,887,132 | 118,866,200 |
| greedy maximum / inline | 5,159 | 2,399 | 2 | 501,079,942 | 446,097,130 | 118,343,171 |
| greedy maximum / materialized | 4,217 | 2,266 | 5 | 501,079,947 | 446,124,625 | 120,271,484 |
| greedy minimum / inline | 4,693 | 2,265 | 5 | 501,080,338 | 444,877,807 | 119,177,813 |
| greedy minimum / materialized | 5,711 | 2,323 | 7 | 501,080,343 | 444,859,581 | 118,654,955 |

The canonical observation digests, in table order, are:

- `dab7bf13ac023e7a526bd1a292590f12c8c889e9cfada1d23ab0796ba6f29797`;
- `7e62d2383ff2523e5f5b864d28ce32af3d2ab75afe078e8ee3d437d7bf461a95`;
- `e2f403b79a27a34423cdcd74ffb1d06d0ffe2a9fe113b43db66a75bcfcc9a17c`;
- `ef43beddf5f4f25fdc00b37ab76643f5c5ea964c7efe24be025a86ddc4e60cce`;
- `729114a296879cb9311f55dd8817a0388221ee03a338cbdf89dc0c64f509e42d`;
- `4eb130691e980c65fa0d2045c869bbf0556d44748068c20e9ecee5d5723008df`;
- `a812bec06e2b4f81769f162df0e985deb060ebc47781997e36a63c5efd10ece6`;
- `c31cda468e087742a91010623fd4cf4f8b71b1a7a3e95dda3e2245eac12ba5b5`.

The canonical polarity-frontier digest is
`8fe2d08594044697a0aa27f17c3fd1dda253b76eea6ae2bca39a6f6da24e9a92`.

## Matched weighted adjacent-swap breadcrumb

The completed A170 matrix exposes a sharper follow-up relation inside the two
weighted orders.  This comparison was not the prospective A170 target or a
rule used to choose any A170 formula; it is a matched breadcrumb read from the
completed, already frozen order matrix.

- weighted ascending and reverse(weighted descending) differ only by swapping
  coordinates `0` and `12` at zero-based positions 13 and 14.  Their effects
  are respectively **+977** and **-1,281**;
- weighted descending and reverse(weighted ascending) differ only by swapping
  coordinates `0` and `12` at zero-based positions 9 and 10.  Their effects
  are respectively **-2,008** and **-2,898**.

Thus the weighted family contains two almost-identical matched order pairs in
which the local placement of coordinates `0` and `12` changes the response by
2,258 decisions in one context and 890 decisions in the other.  This does not
turn A170 into a prospective adjacent-swap experiment.  It identifies the
next exact, minimal order intervention supported by A170's completed evidence.

## Frozen information boundary

The protocol was frozen before any A170 solver execution at
`research/configs/shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json`,
SHA-256
`683d8363bc0865e48df13a880d9e9344d4acdd2faaf15d1f9eaa03f90ded3012`.

A169 selected the complete-order-reversal question.  It did not select an
A170 reversed vector, compiler arm, execution order, resource limit or solver
outcome after formula freeze.  Neither the target rate nor the instrumented
assignment selected a reversal.  Assignment 9,279,571 is extracted only after
all eight executions; all model-match fields are `null` because all eight
solver outcomes are `unknown`.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A169's
order-dependent two-path polarity, four exact order reversals, eight
hash-bound paired formulas, their fixed-resource observations, and the exact
mixed polarity frontier.  The edges form one provenance chain with no inferred
edges.  `CryptoCausalReader` verifies provenance and both retained digests:

- Causal file SHA-256:
  `94ee3ba158d853b1e2e1fb8eeead5de2dadaacda0d47dce10f942643cad98921`;
- canonical graph SHA-256:
  `6b5a7e11aeaa68c87a6de3c5000f7f21e1d493b0aac97fbab5f1da18a150a77b`.

## Retained bindings

- A170 result JSON:
  `f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f`;
- A169 result JSON:
  `b19c1b85bfad77c5e7aa909ba11a02821fce21f6603daa3174bfe5899a0c1334`;
- A168 result JSON:
  `becb3013cb079c2d45ee2a297d2847d5d85542843cb598e5b6288dc45b9eab76`;
- A166 result JSON:
  `e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db`.

## Reproduction

Fast protocol, reversal, formula, model-map, retained-artifact and Causal Reader
gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_reversed_order_alias_polarity_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_reversed_order_alias_polarity_frontier.py
```

Full sequential eight-formula execution:

```bash
rm -rf build/shake-r2-a170
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_reversed_order_alias_polarity_frontier.py \
  --work-dir "$PWD/build/shake-r2-a170"
```

## Consequence

A170 closes exact full-order reversal as a sufficient polarity law: the
response is mixed, with two flips and two preservations.  At the same time, the
completed weighted subset exposes a strictly smaller structural breadcrumb.
Two base/reversed weighted pairs differ only by an adjacent `0`/`12` swap, yet
retain distinct effects.  That matched local intervention, rather than another
unstructured global reorder, is the precise next mechanism to test.
