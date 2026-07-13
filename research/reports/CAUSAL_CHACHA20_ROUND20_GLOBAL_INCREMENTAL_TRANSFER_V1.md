# ChaCha20 full-round global incremental transfer (R20-A211-TRANSFER-V1)

This experiment transfers A211's common-CNF, retained-learned-state mechanism
to the unchanged public challenge from the complete Round-20 split18 pilot.
The primitive is the standard 20-round ChaCha20 block function including
feedforward.  Twenty low bits of key word 0 are unknown, the other 236 key bits
are known, and eight target blocks are public.

The old split18 representation executed 32 independent Bitwuzla cells with 15
free bits per cell.  Every cell returned `UNKNOWN` at ten seconds.  The new
representation removes every prefix condition, exports one common CNF, derives
the R20 key-literal map directly, applies an R20-specific BFS-far bijection, and
runs two independent CaDiCaL 3.0 states.  Each state traverses a complete
256-cell cover with 12 free bits per cell and retains sound learned clauses
across all prefix changes:

1. numeric eight-bit order; and
2. true binary-reflected eight-bit Gray order.

Both orders, all 512 cell budgets, the no-early-stop rule, the RSS scheduling
policy, and every success/boundary rule were frozen before either Round-20
helper called `solve`.

## Confirmed full-round partial-key recovery

Both independent solver states return the same SAT cell and the same model:

| Field | Retained value |
|---|---:|
| Prefix cell, key bits 19 through 12 | `11100100` (`0xe4`) |
| Recovered unknown low 20 bits | `0xe4934` (`936244`) |
| Recovered key word 0 | `0xf3ce4934` (`4090382644`) |
| Known key word 1 low byte | `0x1d` (`29`) |

An independent pure-Python implementation recomputes the standard 20-round
ChaCha20 block function for all eight counters.  Both returned models match
all eight blocks, all 4,096 checked output bits, the 236 known-key constraints,
and the eight-bit cell prefix.  The separately frozen one-bit-flipped control
does not match.

| Mode | SAT | UNSAT | UNKNOWN | Invalid | SAT position | SAT-cell time | Complete-mode wall time |
|---|---:|---:|---:|---:|---:|---:|---:|
| Numeric global | 1 | 0 | 255 | 0 | 228 | 8.859696375 s | 2564.172170084 s |
| Reflected Gray8 global | 1 | 0 | 255 | 0 | 184 | 0.404538 s | 2556.119982042 s |

Both modes continue through their remaining cells after recovery.  They finish
all 256 cells, return normally, and never reach the external mode timeout.  The
retained evidence stage is
`FULLROUND_R20_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED`.

The remaining 255 cells in each mode are `UNKNOWN`, not `UNSAT`.  Recovery is
therefore established twice; uniqueness over the complete `2^20` domain is not
established.

## Conversion of the old split18 target cell

The recovered eight-bit prefix lies inside the old five-bit split18 cell
`11100`.  That exact old cell contained 32,768 candidates and returned
`UNKNOWN` after 10.010918667 seconds.  Both new complete-cover orders recover
the model within the same ten-second per-cell cap.

This is a compound representation transfer: the experiment simultaneously
changes independent SMT cells into one assumption-incremental CNF state and
refines the partition from five to eight fixed bits.  It establishes the
combined R20 transfer.  It does not attribute the recovery to learned-state
persistence alone without a fresh-state 256-cell control.

## R20-specific CNF and literal derivation

The prefix-free split18 SMT formula is rebuilt byte-for-byte from the frozen
pilot source.  Bitwuzla 0.9.1 exports the following base:

| Quantity | Retained value |
|---|---:|
| SMT formula bytes | 38,513 |
| SMT formula SHA-256 | `11fa85e683034b7b8141bad3361240c932c67fba3f37e3bdb3ce64fcc727c291` |
| Original CNF header | `p cnf 68783 216461` |
| Original CNF bytes | 3,810,228 |
| Original CNF SHA-256 | `df051ca805414ea33f065627573aea791d8bee073d0f7ed5b020ce89c953dbea` |

Every one of the 20 unknown key coordinates is probed twice, once with bit
value zero and once with bit value one.  All 40 exports have the byte-identical
base body plus exactly one final unit clause; for every bit, the zero literal
is the exact negation of the one literal.  The derived one-literal map for bits
0 through 19 is:

```text
[16, 15, 18, 20, 22, 24, 26, 28, 30, 32,
 34, 36, 38, 40, 42, 44, 46, 48, 55, 60]
```

The BFS-far order is derived anew from the R20 primal graph using the common
base plus the eight positive prefix representatives for bits 19 through 12.
No R10 literal or permutation is reused.  The order is a complete bijection;
inverse reindexing restores the original CNF byte-for-byte.

| Quantity | Retained value |
|---|---:|
| Unit sources | 887 |
| Maximum BFS distance | 20 |
| Order SHA-256 | `e397b58fdaee44d6306f714ef9b280dc547019662f0ef4ac9cfbd2b60114dfee` |
| Old-to-new map SHA-256 | `13a9f01c6295baae836025be550f283265c313e418d45afcd6c9560839787455` |
| Transformed CNF bytes | 3,819,903 |
| Transformed CNF SHA-256 | `2c33afd9f78ed3e1a2180313571918af51d5eaf2e1cd3b09fb588b86745f19b1` |
| Inverse-restored SHA-256 | `df051ca805414ea33f065627573aea791d8bee073d0f7ed5b020ce89c953dbea` |

The transformed assumption-one literals for bits 19 through 12 are
`[67917, 67916, 67915, 67914, 67913, 67912, 67911, 67910]`.  None is a unit in
the common base.  The native helper accepts signed one-literals, freezes the
absolute assumption variables, decodes signed model literals correctly, and
reads the variable count from the DIMACS header.

## Load-only RSS gate

The helper loads the exact transformed CNF without calling `solve`.  The
measured maximum resident set is 34,226,176 bytes.  At the execution gate the
16 GiB host reports 71% free memory, giving an estimated 12,197,707,120 bytes
available.  Two measured copies plus the frozen 2 GiB safety margin require
2,215,936,000 bytes, so the prospective policy selects concurrent execution.
Observed solver RSS remains far below that bound throughout the run.

## Ordered-update profile

The complete same-prefix paired totals are:

| API metric | Numeric total | Gray8 total | Gray8 / Numeric | Prefixes with different deltas |
|---|---:|---:|---:|---:|
| Conflicts | 775,429 | 764,543 | 0.9859613195 | 256 / 256 |
| Decisions | 900,130 | 899,299 | 0.9990768000 | 256 / 256 |
| Search propagations | 14,877,389,638 | 14,869,769,992 | 0.9994878372 | 256 / 256 |

Aggregate work is nearly identical, while the learned trajectories differ at
every prefix.  At the recovered cell, Gray8 reaches SAT 21.9008 times faster
than Numeric.  Its target-cell ratios are 0.0458801 for conflicts, 0.1217326
for decisions, and 0.0555317 for search propagations.  Both modes nevertheless
recover the same key bits and complete the full cover.

## Scientific scope

This is independently confirmed 20-bit partial-key recovery for a standard
full-round ChaCha20 block challenge with 236 key bits known.  It is not a
256-bit full-key recovery, not a proof that deployed ChaCha20 traffic can be
decrypted, and not by itself a security break against ChaCha20's standard
256-bit key-search claim.

A184 already retains exhaustive standard-fullround recovery over a 40-bit
unknown subdomain with 216 key bits known.  The novelty here is not “first
fullround recovery”; it is the conversion of the previously all-`UNKNOWN`
direct R20 solver frontier into two independently confirmed SAT recoveries by
an R20-specific common-CNF, finer assumption partition, and retained-state
transfer.

## Causal Reader and artifact integrity

The native Causal artifact contains nine explicit provenance-linked edges:

1. old complete split18 boundary and prior A184 scope;
2. deterministic prefix-free R20 CNF export;
3. 40 signed key-literal probes;
4. R20-specific BFS-far bijection and byte-exact inverse;
5. signed dynamic CaDiCaL helper identity;
6. load-only RSS scheduling gate;
7. complete two-mode execution;
8. independent 4,096-bit confirmation; and
9. prospective transfer comparison.

`CryptoCausalReader` verifies all nine edges and the complete provenance
chain.  The final `.causal` bytes were atomically rewritten byte-identically
after execution; their SHA-256 remained unchanged.

## Reproduction

Fast protocol, source, retained-result, test, and Causal gates:

```bash
scripts/reproduce_chacha20_round20_global_incremental_transfer.sh
```

Fresh execution of both frozen 256-cell covers:

```bash
scripts/reproduce_chacha20_round20_global_incremental_transfer.sh --rerun
```

Direct no-solver protocol analysis:

```bash
PYTHONPATH=src python3 \
  research/experiments/chacha20_round20_global_incremental_transfer.py \
  --analyze-only
```

The retained test suite completes 12 tests, including all 40 signed probes,
byte-exact inverse reindexing, negative one-literal helper semantics, the
load-only no-solve RSS path, cumulative incremental-state parsing, invalid-mode
atomicity, `UNKNOWN` separation, and native Causal Reader provenance.

## Exact retained hashes

- public challenge SHA-256:
  `98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762`
- prospective protocol SHA-256:
  `64470896de99dacabb0b53f81d8c94c2da82e7088be09c8e1b4d38665ae09946`
- launch-time runner snapshot SHA-256:
  `9d7caab9ad3a5135fe31a144364021f73bb537a98ded2b618362a4535e1f3ab2`
- retained reproduction runner SHA-256:
  `1825035b90317e9d6c8a2ee0894f2569eada44177ee01ced49d043ca37ec881d`
- native helper source SHA-256:
  `016fc73b402fc02e0ecf83639ae75950a5971ad3207c1ea66e980268343fbef3`
- compiled native helper SHA-256:
  `1b451b3c6e6aa579753acc5229e1b90d04e40869012317f6eb9897e86c2ad822`
- test source SHA-256:
  `1b3ae6e55d633fd273ef68ee62d5cce9e2dcb6d0bce91c6d633013a9f226914f`
- reproduction script SHA-256:
  `7d5389b2795fe0edb49aabd739477eff582780077ba0f366c4bba814355049e9`
- result JSON SHA-256:
  `a5be062ebce29cbc864ef926c55a1f9dbaadd69c9edcc54aed43552304f8e3f0`
- native Causal SHA-256:
  `f9dd413e97c988335115f523a3a21d491564555d53020d902ac37854972c8e43`
- native Causal graph SHA-256:
  `47705df3ff4a4bbbd457c06785b859cb4686458ef9b9f1dedd16bce9d12b3ed1`

The retained runner differs from the launch-time in-memory snapshot only by
post-launch failure-path metric handling and atomic final-Causal replacement.
Neither change modifies the protocol, CNF, literal map, native helper, solver
options, cell orders, budgets, or model confirmation.  The valid retained run
does not exercise the hardened invalid-mode path.
