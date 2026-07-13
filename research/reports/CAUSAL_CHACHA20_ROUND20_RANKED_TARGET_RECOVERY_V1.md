# ChaCha20 R20 Target-Blind Ranked Recovery (A219)

**Evidence stage:** `FULLROUND_R20_TARGET_BLIND_COMPLETE_ORDER_SOLVER_BOUNDARY_RETAINED`

A219 executes the complete target order frozen by A218 before the target secret or correct prefix is opened. One CaDiCaL state is retained across cells and execution stops only on the first SAT model or after all 256 cells.

## Execution

- Attempted cells: `256`
- SAT / UNSAT / UNKNOWN: `0` / `0` / `256`
- Seconds per cell: `10`
- SAT found: `False`
- Target secret read: `False`

All 256 rows returned `UNKNOWN`; every row fired the declared 10-second
terminator.  The observed per-row elapsed interval was
`[10.000027583, 10.069510542]` seconds, with one row above 10.05 seconds.
The retained-state continuity gate passed across the complete order.

## A218 reader boundary

- Selection-matched whole-key null p: `0.9538461538461539`
- The A218 linear across-key reader boundary remains in force regardless of   the A219 solver outcome.

## Post-reveal diagnosis

The commitment was opened only after the target-blind A219 result had been
atomically written with file SHA-256
`6a492b305f17c6668d000ad6f439a473fdc100e849ca7e2b6e7357eebad29940`.
The revealed low-20 value is `0x58d88`, whose eight-bit cell prefix is
`01011000`.  The commitment and all eight independent ChaCha20 block checks
passed.

The true prefix occupied position `211 / 256` in the frozen A218 order.  A219
did execute that row, but it remained `UNKNOWN` after `10.040835125` seconds:

- conflicts: `3798`
- decisions: `4133`
- search propagations: `80149256`
- redundant-clause delta: `+3078`

The result therefore separates two retained boundaries.  First, the A218
linear across-key reader did not concentrate this target, consistent with its
selection-matched whole-key null result.  Second, the correct cell itself was
not solved by the fixed 10-second retained-state budget.  No recovery claim is
made for A219.

The standalone dual-implementation post-SAT gate records
`NOT_APPLICABLE_NO_SAT_MODEL`; it neither reads the sealed target nor reruns the
solver.

## Reproduction

```bash
PYTHONPATH=src .venv/bin/python \
  research/provenance/a219_started_runner_a942b120c975ad1d5b664d94449ff2fcc31fda6bc0b6b74adb976f75d8187bf9.py
```

- Exact started-runner SHA-256: `a942b120c975ad1d5b664d94449ff2fcc31fda6bc0b6b74adb976f75d8187bf9`
- Protocol SHA-256: `e2b457120536a5e7a3950b288bf8ed65fd4ff2e9740535b946416127a441d80b`
- Measurement SHA-256: `ce865cd4d058e6083362274b5a33ab935e3c78bd7c446215082ce19458589b72`
- Causal graph SHA-256: `3be903319813935a5e2d96484d1823458b450b40da49903561e347ab030d5603`
- Reveal result SHA-256: `461269691d0d2403532617c48f8a1359965885f3ecb48ed7970da4c6f8d4a0f7`
- Cross-gate result SHA-256: `2e9298baf09484c9bc5c676ac4971b95756b0934d54fbad675e9e706aaac69ae`
