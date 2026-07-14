# A238 mechanical preflight — full-key Speck32/64

## Scope

This is a bounded solver-selection experiment, not a key-recovery result.  The
instance uses standard Speck32/64 with all 22 rounds, all 64 master-key bits
unknown, and three known plaintext/ciphertext pairs.  The benchmark key and
plaintexts are deterministic SHA-256 derivations and are public because this
run measures solver mechanics rather than protocol secrecy.

The direct SMT-LIB formula is 21,031 bytes with SHA-256
`147649d60975217a4632a8295dc6f692d663ae32b27d86dfaa871149fd4846b3`.
Bitwuzla bit-blasts it to 11,068 variables and 35,648 clauses (566,465
bytes; SHA-256
`6df9dee9de0aea4353da2083cbae800b48860a578ab4f3c53c8bd40635888498`).

## Correctness gates

- `py_compile` and Ruff pass for the compiler.
- Five focused unit tests pass.
- Z3 4.15.4, Bitwuzla 0.9.1, and Boolector 3.2.4 all return SAT and the exact
  benchmark key when that key is constrained.  This gates the 22-round
  relation, word order, solver syntax, and model parser.
- The parser now maps Z3's literal `timeout` status to `unknown` rather than
  treating it as a malformed solver response.

## Bounded direct-encoding probes

Each single-thread probe received 15 seconds unless stated otherwise.

| Engine | Configuration | Result |
| --- | --- | --- |
| Z3 | default QF_BV | timeout |
| Z3 | `smt.bv.delay=true` | timeout |
| Z3 | `qfbv-sls`, 20 s | unknown |
| Z3 | `sls-smt`, 20 s | unknown |
| Bitwuzla | bitblast + CaDiCaL | unknown |
| Bitwuzla | propagation | unknown |
| Bitwuzla | propagation preprocessing | unknown |
| Boolector | functional + Lingeling | unknown |
| Boolector | propagation / SLS / AIG propagation | unknown |
| Kissat | default CNF | unknown; 41,815 conflicts |
| Kissat | SAT profile CNF | unknown; 66,069 conflicts, 131,598,869 propagations |
| CaDiCaL | default / SAT profile CNF | unknown |
| CryptoMiniSat | one and four threads | indeterminate |
| MiniSat | external 18-second guard | timeout |

The local Bitwuzla binary advertises Kissat, CryptoMiniSat, and Gimsatul
backends but was compiled only with CaDiCaL.  The local Boolector binary falls
back to Lingeling when CaDiCaL or CryptoMiniSat is requested.  These fallback
paths are therefore not independent benchmark rows.

## Bidirectional encoding probe

A second valid encoding declares the 64-bit key-schedule state at round 10,
derives the schedule in both directions, executes data rounds 0--10 forward
from each plaintext, executes rounds 21--11 backward from each ciphertext, and
equates the three round-11 midstates.

The known-key gate returns the exact key in both Z3 and Bitwuzla.  Its CNF has
12,125 variables and 38,791 clauses: 9.4% more variables and 8.8% more clauses
than the direct encoding.  Z3 and Bitwuzla remained unknown at 20 seconds.
Kissat's SAT profile executed 105,798 conflicts and 174,266,501 propagations in
20 seconds without finding a model.  The bounded probe therefore establishes
no split-encoding advantage.

Three structured chosen plaintexts (`0000:0000`, `0000:0001`, `0001:0000`)
also produced no bounded solve advantage.

## Decision

Do not convert these short UNKNOWN outcomes into a long default-SMT run.  The
current mechanical baseline is the smaller direct Bitwuzla CNF with Kissat's
SAT profile.  The next encoding experiment should preserve Speck's XOR
relations natively instead of Tseitin-expanding every XOR into ordinary CNF,
or first construct a deterministic round/unknown-bit calibration surface to
locate the actual solver phase transition.  Either path is more informative
than adding runtime to the unchanged direct formula.

The exact commands, wall times, return codes, dimensions, hashes, and selected
solver counters are stored in
`research/results/v1/speck32_64_fullkey_solver_probe_v1.json`.
