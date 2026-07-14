# A223: Full-Round Shared-B8 Retained-State Capacity Moonshot

## Status

The public protocol, five independently generated public challenges, generic
shared-key formula compiler, dynamic-width native helper, model-disclosure
barrier, RSS wave scheduler, and fast verification suite are implemented.
No A223 cell solver run is represented by this document. The reviewed
preflight manifest and phase-1 result are intentionally absent until their
respective commands complete.

## Mechanism composition

A223 composes two retained mechanisms and one exact mapping primitive:

- A187: one symbolic key jointly constrains eight counter-related blocks;
- A211: one CaDiCaL process retains learned state across a complete 256-cell
  prefix cover;
- A214: baseline plus binary-coordinate patterns recover every signed key-bit
  literal exactly, using only 6/7/7/8/9 probe exports at
  W32/W40/W64/W128/W256.

Each width has one split-18 SMT formula containing eight standard ChaCha20
20-round circuits with feed-forward. The shared key occurs in all eight
circuits, and all 128 forward/backward lane equalities are asserted in one
common CNF. Any returned model is then recomputed by a separate pure-Python
ChaCha20 implementation over all eight blocks (4096 output bits) and tested
against a one-bit-flipped first-block control.

## Prospective portfolio

| Priority | Arm | Unknown key bits | Order | Scientific role |
|---:|---|---:|---|---|
| 1 | `gray8_w40` | 40 | reflected Gray8 | direct A184-scope arm |
| 2 | `gray8_w256` | 256 | reflected Gray8 | full-key arm |
| 3 | `numeric_w40` | 40 | numeric | A217-diverse A184-scope arm |
| 4 | `numeric_w256` | 256 | numeric | A217-diverse full-key arm |
| 5 | `gray8_w32` | 32 | reflected Gray8 | lower capacity anchor |
| 6 | `gray8_w64` | 64 | reflected Gray8 | intermediate capacity arm |
| 7 | `gray8_w128` | 128 | reflected Gray8 | high capacity arm |

For width `w`, every arm fixes unknown global key bits `w-1..w-8` and leaves
`w-8` bits free. The 256 cells are disjoint and cover exactly `2^w`
candidates. Every cell receives 10 solver seconds; all 256 cells execute even
after SAT. `UNKNOWN` remains distinct from `UNSAT`.

## Resource and disclosure gates

Preflight loads each of the five b8 CNFs into the helper without calling
`solve()`. It measures maximum RSS and freezes deterministic waves in the
priority shown above. A wave is accepted only when summed measured helper RSS
plus 2 GiB is at most physical memory. At most seven A223 processes run at
once; with two A220 processes this reserves one of ten physical cores.

The helper never writes model bits to its stdout stream. SAT models are held in
child memory and written to a private per-arm spool only after that arm has
completed all 256 cells. The Python process reads no model spool until all
seven arms in all frozen waves have terminated. Outcomes cannot alter order,
budget, schedule, or stopping.

## Reproduction sequence

Fast source and protocol verification:

```sh
scripts/reproduce_chacha20_round20_capacity_moonshot_a223.sh
```

Materialize the exact CNFs, mappings, helper binary, load-only measurements,
and frozen memory schedule without running any cell:

```sh
scripts/reproduce_chacha20_round20_capacity_moonshot_a223.sh --preflight
```

Review the printed preflight SHA-256. A phase-1 launch requires that exact
digest explicitly:

```sh
scripts/reproduce_chacha20_round20_capacity_moonshot_a223.sh --run <reviewed-sha256>
```

## Artifact paths

- protocol: `research/configs/chacha20_round20_capacity_moonshot_a223_v1.json`
- runner: `research/experiments/chacha20_round20_capacity_moonshot_a223.py`
- native helper: `research/native/cadical_capacity_moonshot_a223.cpp`
- preflight: `research/results/v1/chacha20_round20_capacity_moonshot_a223_preflight_v1.json`
- phase-1 result: `research/results/v1/chacha20_round20_capacity_moonshot_a223_v1.json`
- tests: `tests/test_chacha20_round20_capacity_moonshot_a223.py`

## Interpretation boundary

W40 is a direct unknown-bit-scope comparison to the retained A184 full-round
result. W256 is the full-key capacity arm. A positive arm requires an
independently confirmed model; terminal, unknown, and unresolved arms remain
fully retained capacity observations. No immunity statement is produced from
an unresolved arm.
