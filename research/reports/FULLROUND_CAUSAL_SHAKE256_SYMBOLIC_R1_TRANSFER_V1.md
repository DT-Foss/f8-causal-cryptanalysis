# SHAKE256 Symbolic-R1 Transfer v1

## Result

A142 instantiates the R1 interface selected on SHAKE128 by A137 as a transfer
hypothesis for SHAKE256.  The exact R1 prefix is joined to 23 explicit Keccak
rounds and the complete 1,088-bit SHAKE256 next-rate observation.  Under the
tested single-thread, 120-second monolithic parameters, widths 16, 20, and 24
all return `unknown` on the first model query.

| variable coordinates | shared R1 monomials | coordinate coefficients | variables | assertions | first query |
|---:|---:|---:|---:|---:|---|
| 16 | 23 | 1,194 | 126,742 | 127,814 | `unknown` |
| 20 | 35 | 1,268 | 126,754 | 127,822 | `unknown` |
| 24 | 76 | 1,377 | 126,795 | 127,859 | `unknown` |

The SHAKE128-selected R1 split therefore does not transfer directly to a
resolved SHAKE256 model under these three monolithic configurations.  The
result is scoped to this representation, seed plan, complete-rate constraint,
solver version, one solver thread, and 120-second per-query limit.  It does not
establish that the SHAKE256 state-window relation is ambiguous or that another
split/partition cannot resolve it.

The result removes direct monolithic portability as a sufficient transfer
hypothesis.  The retained breadcrumb is a SHAKE256-specific interface frontier
or a disjoint SHAKE256 partition rather than importing the SHAKE128 R1 outcome.

## Transfer isolation

A137 is accepted only at SHA-256
`19cc21bb0b60943182ac8d0c927e9090ac881c24fba04a9f646ae4972fe84583`.
Only its structural choice `symbolic_prefix_rounds=1` is transferred.  No
SHAKE128 solver status, assignment, or observed output is imported.  A142 uses
independent SHAKE256 seeds 89,757,055 / 89,758,064 / 89,759,073 for widths
16/20/24 and constrains all 17 SHAKE256 rate lanes.

All three R1 interfaces remain degree at most two and their SMT encodings range
only from 9,181,487 to 9,186,209 bytes.  Consequently, formula size alone does
not account for the three bounded statuses.  As in A139--A141, nominal free
dimension is not a complete predictor of solver work.

## Functional and Reader gates

The runner checks the Keccak-f[1600] zero-state vector, embedded SHAKE128/256
empty-message vectors, and complete first-rate outputs against `hashlib`.  The
`.causal` graph stores exactly three explicit operations:

- instantiate the hash-gated SHAKE128 R1 choice only as a SHAKE256 hypothesis;
- execute the bounded SHAKE256 model query and any available blocked query;
- independently evaluate any returned candidate over all 24 rounds and 1,088
  output bits.

No model is available in A142, so the second and independent model queries are
not issued.  The artifact is reopened with `CryptoCausalReader`, and its exact
three-triplet provenance chain passes.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake256_symbolic_r1_scaling_reader.py \
  --window-bits 16,20,24 \
  --timeout-seconds 120 \
  --output research/results/v1/shake256_symbolic_r1_scaling_reader_v1.json \
  --causal-output research/results/v1/shake256_symbolic_r1_scaling_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake256_symbolic_r1_scaling_reader.py
```

## Artifact hashes

- result JSON:
  `1eb430adfa3e29f8d776eca71b892b2f307b24248babc0de37b36dd8ad547b7d`
- three-edge `.causal`:
  `fe7f07023db3f3c9d3b63526d3f2f3bcecd234b14d2177df11d4ee54ab1c8eab`
