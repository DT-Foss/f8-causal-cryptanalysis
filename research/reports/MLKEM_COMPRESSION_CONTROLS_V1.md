# ML-KEM compression controls v1

Raw result: `research/results/v1/mlkem_compression_controls.json`
SHA-256: `04d2cf1c3d13759d9d5efc06e184bd1d665f5f62ae8fec7474a66d5684cc13c2`

## Design

For each ML-KEM parameter set, 500 real encapsulations were generated per
seed, across three seeds. Every operation was decapsulated successfully.
From each ciphertext's real compressed `u` component, the study forms four
same-length streams:

| Stream | Content |
|---|---|
| A | Original packed `u` bytes |
| B | Decoded real compressed coefficients in 16-bit words, with random high bits |
| C | Uniform matched-range coefficients in the same 16-bit/random-high-bit representation |
| D | Uniform random bytes |

Each stream is independently scored by the portable CASI implementation with
the same baseline seed inside a replication.  Real zlib compressibility is
reported separately in the raw records; it is not silently folded into CASI.

## Result

| Variant | A packed | B real coeffs | C uniform coeffs | D random | A-B packing | B-C coefficient model |
|---|---:|---:|---:|---:|---:|---:|
| ML-KEM-512 | 1.1263 | 1.3275 | 1.0847 | 1.0754 | -0.2013 | +0.2428 |
| ML-KEM-768 | 1.0965 | 1.1977 | 1.4739 | 1.3986 | -0.1012 | -0.2762 |
| ML-KEM-1024 | 1.1256 | 1.7925 | 1.5212 | 1.0683 | -0.6670 | +0.2714 |

The A-B effect is directionally stable: bitpacking lowers this CASI measure by
about 0.10--0.67 compared to the matched decoded-coefficient representation.
The B-C effect is not stable across parameters, especially ML-KEM-768. Thus
this run supports a representation-dependent packing effect, but does **not**
support the stronger universal claim that the test isolates an LWE coefficient
distributional signature.

## Reproduction

```bash
.venv/bin/python research/experiments/mlkem_compression_control_suite.py \
  --operations 500 --seeds 3 \
  --output research/results/v1/mlkem_compression_controls.json
```

This is a format/distribution measurement. It does not test IND-CPA,
IND-CCA, decryption failure, key recovery, or a cryptanalytic distinguisher.
