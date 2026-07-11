# SHAKE Symbolic-R1 Scaling Reader v1

## Result

The A137-selected R1 interface resolves the complete monolithic 16-coordinate
SHAKE128 state-window system without a fixed prefix or external partition.  It
returns assignment **35,837** in 4,701 decisions.  Independent injection into
the complete 24-round implementation reproduces every one of the 1,344 observed
next-rate bits.

| variable coordinates | search form | first query | decisions | decision count / complete assignment space | independent complete-rate check | blocked query |
|---:|---|---|---:|---:|---|---|
| **16** | monolithic R1 | **SAT** | **4,701** | **0.07173** | **1,344/1,344 bits** | configured boundary |
| 20 | monolithic R1 | configured boundary | -- | -- | -- | not issued |
| 24 | monolithic R1 | configured boundary | -- | -- | -- | not issued |

This is the first exact monolithic 16-coordinate model in the Boolean Reader
track.  The canonical CNF and symbolic-R2 monolithic representations both reach
their 120-second boundary on the same 16-coordinate problem; the R1 interface
returns the correct model with only 4,701 decisions.  That count is 13.94 times
smaller than the complete 65,536-assignment space.

The blocked-model query reaches its configured boundary, so A138 records exact
model reconstruction and complete-rate verification without promoting a new
global uniqueness certificate.  Widths 20 and 24 similarly define the next
monolithic scaling boundary.  They immediately select disjoint R1 subspaces as
the next representation step.

## Exact R1 interface

The Reader compiles one Keccak round directly in the Boolean polynomial ring,
then retains the remaining 23 rounds as explicit local Boolean equations.  The
complete next-rate state supplies 1,344 output constraints.

| variable coordinates | shared R1 monomials | R1 coordinate coefficients | total variables | total assertions | SMT bytes |
|---:|---:|---:|---:|---:|---:|
| 16 | 27 | 1,196 | 126,746 | 128,074 | 9,187,068 |
| 20 | 49 | 1,278 | 126,768 | 128,092 | 9,189,138 |
| 24 | 34 | 1,350 | 126,753 | 128,073 | 9,188,279 |

The 20/24 boundary is not accompanied by a symbolic-formula explosion: all
three R1 interfaces remain small and degree at most two.  The retained next
step is therefore search decomposition over the same R1 equations, not a later
symbolic split.

## Independent model gate

The returned 16-coordinate assignment is injected into the cleared window and
evaluated through an implementation separate from the SMT equation writer.  The
candidate and observed complete-rate hashes are identical:

```text
6d23d92d3ae295ffc64a53b5d1c70042a9a2efb73ad0daf6cd923fef31c940e4
```

The assignment also equals the posthoc instrumented coordinates.  Solver
output, independent complete-state evaluation, and instrumentation therefore
all agree on 35,837.

## Causal Reader artifact

The `.causal` file stores three provenance-linked operations:

- compile the exact first-round Boolean-ring interface selected by A137;
- attach all remaining 23 rounds and the complete next-rate observation;
- independently evaluate each returned assignment and issue the blocked-model
  status query.

A137 is accepted only at SHA-256
`19cc21bb0b60943182ac8d0c927e9090ac881c24fba04a9f646ae4972fe84583`.
The new graph is reopened with `CryptoCausalReader`; its provenance and exact
three-triplet recipe are checked during production.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_scaling_reader.py \
  --window-bits 16,20,24 \
  --timeout-seconds 120 \
  --output research/results/v1/shake_symbolic_r1_scaling_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_scaling_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_scaling_reader.py
```

## Artifact hashes

- result JSON:
  `428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078`
- three-edge `.causal`:
  `440a5e2757579ed0cbd88179fc284b222fa904712a13a183a200f9899c0e35b4`
