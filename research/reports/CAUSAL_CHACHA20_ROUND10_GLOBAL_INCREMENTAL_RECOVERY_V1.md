# ChaCha10 global incremental partial-key recovery (A211)

A211 removes the five fixed parent-unit clauses from the 32 byte-matched A204
CNFs, applies the frozen A209 BFS-far bijection, and obtains one common
14,158,038-byte Round-10 CNF.  Two independent CaDiCaL 3.0 instances traverse
the same complete 256-cell Width-12 cover while retaining sound learned state
across every prefix change:

1. numeric eight-bit order; and
2. true binary-reflected eight-bit Gray order.

Each mode covers all `2^20` candidates exactly once at ten seconds per cell.
The modes share no learned state and execute without early stop.  This is the
prospectively frozen T01 global ordered-update transfer selected from A210's
systematic sibling-learning result before any A211 solver outcome existed.

## Confirmed recovery

Both modes independently return the same SAT cell and the same model:

| Field | Retained value |
|---|---:|
| Prefix cell | `01111100` |
| Recovered unknown low 20 bits | `0x7c596` (`509334`) |
| Recovered `key_word0` | `0xcb37c596` |
| Known `key_word1` low byte | `0xab` |
| Combined retained assignment | `0xabcb37c596` (`737848837526`) |

Independent NumPy ChaCha10 recomputation confirms all eight shared-key blocks,
all 4,096 target bits, the known-key constraints, and the eight-bit cell
prefix.  The separately frozen control block does not match.  The hidden low
20-bit assignment is absent from the protocol, runner, helper, CNF mapping,
and public challenge before execution.

| Mode | SAT | UNSAT | UNKNOWN | Invalid | SAT position | SAT-cell time |
|---|---:|---:|---:|---:|---:|---:|
| Numeric global | 1 | 0 | 255 | 0 | 124 | 6.033346625 s |
| Reflected Gray8 global | 1 | 0 | 255 | 0 | 87 | 0.497954208 s |

Both complete mode runs remain valid after the SAT observation.  Numeric takes
2,570.12698 seconds and Gray8 2,564.65796 seconds; neither mode reaches its
external timeout.  The evidence stage is
`ROUND10_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED`.

This is an exact 20-bit partial-key recovery for the frozen reduced ChaCha10
eight-block challenge.  It is not a 256-bit full-key recovery.  The remaining
255 cells are `UNKNOWN`, not `UNSAT`, so uniqueness over the complete domain is
not adjudicated.

## Direct conversion of the prior boundary

The recovered prefix `01111100` is the exact same challenge cell in every
stage:

| Stage | State ownership | Status | Conflicts | Decisions |
|---|---|---|---:|---:|
| A209 | fresh cell | UNKNOWN | 4,520 | 74,261 |
| A210 numeric | retained within one eight-cell parent | UNKNOWN | 830 | 895 |
| A210 local Gray | retained within one eight-cell parent | UNKNOWN | 983 | 990 |
| A211 numeric | retained across all 256 cells | SAT | 638 | 2,243 |
| A211 reflected Gray8 | retained across all 256 cells | SAT | 47 | 1,619 |

Thus the recovery appears only after the 31 inter-parent solver resets are
removed.  Global state persistence converts a repeatedly open cell into two
independently confirmed SAT models.

At the target cell, Gray8 reaches SAT 12.1163 times faster than Numeric, with
`0.07366771159874608` times the conflicts and
`0.07451212066359092` times the search propagations.  It encounters the cell
at traversal position 87 rather than 124 and still executes the entire cover.

## Complete-domain learning effect

Against the 256 exact same-prefix fresh A209 cells:

| Mode | Conflicts / A209 | Decisions / A209 |
|---|---:|---:|
| Numeric global | 0.2109188017835493 | 0.01661959914035409 |
| Reflected Gray8 global | 0.21226814463344196 | 0.01670096288204968 |

The Numeric global state also provides a position-identical comparison with
A210 Numeric, differing only by removal of the 31 parent resets:

| API metric | A211 global / A210 local |
|---|---:|
| Conflicts | 0.7050458320317969 |
| Decisions | 0.11780521903015234 |
| Search propagations | 1.2210336115448384 |

Global persistence therefore reduces decisions by 88.22% beyond the already
incremental A210 boundary and by 98.34% against fresh A209 cells, while
retaining enough cross-prefix structure to reach the SAT model twice.

## Ordered-update control

Across all 256 same-prefix pairs, Gray8/Numeric aggregate ratios remain close
to one:

| API metric | Gray8 / Numeric |
|---|---:|
| Conflicts | 1.0063974517135623 |
| Decisions | 1.0048956500700446 |
| Search propagations | 1.000789867166455 |

Both modes recover the same assignment, so global learning is the dominant
recovery mechanism.  The traversal order changes the learned trajectory and
target-cell cost substantially without changing the recovered key bits.

## Reproduction and exact anchors

Retained gates without Round-10 solver execution:

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_global_incremental_cover.py \
  --analyze-only

PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_chacha20_round10_global_incremental_cover.py
```

Full frozen execution:

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_global_incremental_cover.py
```

- public challenge SHA-256:
  `5d17ed241b6b91224a4974f36b4b0b4ec5c677b9d975dd6bc8cec83b6ddbf86b`
- protocol SHA-256:
  `680346b1740173c2708a9debb90bb653387ac636bb876022e010c8857e50bd6e`
- runner SHA-256:
  `246c6e358f00f1ac34aefded1183534f9ce0376996201ec70b8f9bdec5c9af32`
- native helper source SHA-256:
  `3b4a5aa0a8d537d6599ec20d9e17d173db0c7b5fbddf8864859346b5fd4a497c`
- compiled native helper SHA-256:
  `fb822acdd0453a36bf6e5f6df763a72a7b999710e47ac9329160f28603d1ce84`
- result JSON SHA-256:
  `3dfe525c6340dd911d584c77a925a5eb01b246ff55f0981901f6400fd00d25c2`
- Causal SHA-256:
  `c5f30d2e55af6b38feca0b07136c7714f20b34b654d0d866d7e143588daf6881`
- native Causal graph SHA-256:
  `fa5a64e6736b1456210d4472a5c8856ce0a9e71c2d29a79915e202a866a62ee7`
