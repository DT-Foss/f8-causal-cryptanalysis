# SHAKE Symbolic-R2 Native-XOR SMT Reader v1

## Result

An exact round-split Reader now connects the compact symbolic R2 interface to
the complete R3--R24 Keccak-f[1600] suffix.  The prefix remains in native n-ary
Boolean XOR form instead of being flattened into Tseitin XOR chains.  From the
complete 1,344-bit next-rate state, the Reader reconstructs the tested 4-, 8-,
and 12-coordinate SHAKE128 capacity windows exactly and proves each assignment
unique with a second blocked-model query.

| variable coordinates | canonical CNF decisions | native-XOR decisions | native/CNF | reconstructed assignment | second model |
|---:|---:|---:|---:|---:|---|
| 4 | 57,319 | 2,025 | **0.03533** | 11 | proved absent |
| 8 | 48,477 | 8,252 | **0.17023** | 66 | proved absent |
| 12 | 586,636 | 35,088 | **0.05981** | 3,464 | proved absent |
| 16 | configured boundary | configured boundary | -- | -- | not queried |

The solved instances use between 3.53% and 17.02% of the first-query decisions
recorded by the canonical CNF Reader.  At width 12, the native-XOR split removes
551,548 decisions, a 16.72-fold reduction.  The second queries are UNSAT at all
three solved widths, so these are exact fullround reconstructions with exact
uniqueness certificates.

The 16-coordinate monolithic instance reaches the same configured 120-second
boundary as the canonical CNF representation.  This localizes the next gain:
the symbolic interface changes solver work dramatically at solved widths, while
the remaining 16-coordinate search needs decomposition rather than a third
monolithic encoding.

## Exact round split

The Reader compiles the real SHAKE state in two exact components:

1. rounds R0 and R1 are evaluated directly in the Boolean polynomial ring from
   the variable capacity coordinates;
2. every resulting monomial is represented once and every one of the 1,600 R2
   state coordinates is asserted as one native n-ary XOR equation;
3. rounds R2 through R23 are encoded operation by operation as Boolean Theta,
   Rho, Pi, Chi, and Iota equations;
4. all 1,344 next-rate bits are constrained to the observed target;
5. a returned model is compared with the independently instrumented capacity
   window, then blocked and solved again for uniqueness.

There is no truth-table materialization, learned approximation, formula
truncation, output-prefix shortcut, or substitution of the known assignment.
The branch variables are the capacity-window coordinates themselves.  The
known complement and complete next-rate observation match the established
state-window inference model used by the earlier SHAKE Readers.

The exact width-16 system contains 121,553 Boolean variables and 122,881
assertions.  Its symbolic R2 interface uses 274 nonconstant monomials and 1,857
R2 assertions; the remaining equations are the complete 22-round suffix and
1,344 output constraints.

## Causal Reader artifact

The `.causal` file stores three explicit, provenance-linked operations:

- compile the known-complement capacity window through exact R2 Boolean-ring
  formulas into a native-XOR interface;
- attach and solve the exact R3--R24 suffix against the complete next-rate
  observation;
- block the first assignment and resolve to determine uniqueness.

The artifact is reopened with `CryptoCausalReader`; provenance verification and
the exact three-triplet gate are part of the experiment itself.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_smt_reader.py \
  --window-bits 4,8,12,16 \
  --timeout-seconds 120 \
  --output research/results/v1/shake_symbolic_r2_smt_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r2_smt_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_smt_reader.py
```

The reference artifact uses Z3 4.15.4 with one solver thread.  The canonical A128
baseline is accepted only at SHA-256
`4281b0ab9eb6156cc428b34cd14216cf5c465ba786c85a0332bb8f71eb0e92dc`.

## Artifact hashes

- result JSON:
  `239098b2944535bb1d8544783ce8e1f1b11efbe48aa9dbb0a4ec9ee61c637b71`
- three-edge `.causal`:
  `aab3b9990e8df2fb1ac7966f71b11491ecda44dcec4b68a6b0ecefb9e356600d`
