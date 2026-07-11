# PQC output controls v1

Raw result: `research/results/v1/pqc_output_controls.json`
SHA-256: `c99202ee691b2652132676c72d39bb15d13851085a9b3d6c21ba3738cc740c5e`

## What was measured

Nine real `pqcrypto==0.4.0` backends were run: ML-KEM-512/768/1024,
ML-DSA-44/65/87 and HQC-128/192/256.  For each target, two independent runs
of 128 operations were collected under a fixed keypair and under a fresh
keypair per operation.  Every KEM's first operation was decapsulated; every
signature's first operation was verified.  The output was split into 32-byte
rows and evaluated with the current portable CASI implementation and F8-O.

F8-O is the quantized F8 statistic on *adjacent public output rows*.  It is
not an internal-round trace and must never be reported as an F8
cryptanalytic distinguisher.  The fixed-key output was additionally row
permuted twice per seed.

## Result snapshot

| Family | CASI behavior | F8-O behavior |
|---|---|---|
| ML-KEM | 1.016--1.174 (mean across target/condition summaries) | 0.046--0.057, close to the nominal 0.05 rate |
| HQC | 0.991--1.342 | 0.036--0.058, close to the nominal 0.05 rate |
| ML-DSA | 2.489--5.393 | 0.048--0.063; no stable family-wide departure from null |

The maximal F8-O value was ML-DSA-65 under fixed keys (0.06250).  Its
permuted control was 0.05859.  This remains within the small-pilot variation
of the public byte stream; it is not evidence of a
cryptanalytic weakness, key recovery, or an internal NTT/round signal.

## Immediate deductions

1. The old PQC runner's conflation of CASI rows and independent PQC operations
   is removed here: the raw record reports both numbers.
2. ML-DSA's elevated CASI is separated from an F8-O finding.  This is
   consistent with signature encoding being structurally non-uniform.
3. ML-KEM and HQC do not produce an output-order F8-O effect in this pilot.
   The next valid F8 direction is therefore not more output-only sweeps, but
   the deterministic ML-KEM trace through NTT and compression stages.

## Reproduction

```bash
.venv/bin/python research/experiments/pqc_output_control_suite.py \
  --operations 128 --seeds 2 --permutations 2 \
  --output research/results/v1/pqc_output_controls.json
```

The suite is stochastic because `pqcrypto` generates randomized keys and
encapsulations/signatures.  It records backend version, exact operation count,
row count, functional gates, all seed-level values, and control values.  A
registered higher-power replication is required before any quantitative claim.
