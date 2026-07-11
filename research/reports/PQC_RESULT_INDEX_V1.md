# PQC result index v1

This index records what each result actually establishes. No row implies a
cryptanalytic break, key recovery, or an IND-CPA/IND-CCA statement.

| ID | Target | Measurement | Controlled result | Interpretation |
|---|---|---|---|---|
| PQC-01 | ML-KEM/ML-DSA/HQC | CASI + F8-O, fixed/fresh keys | ML-DSA CASI is elevated; ML-KEM/HQC F8-O remains near null | Output format is not an F8 cipher trace |
| PQC-02 | ML-KEM | packed `v` -> coefficients -> NTT | Byte F8 and field F8-Fq match both shuffled and balanced BvN re-pairing controls | Linear NTT transition is not an automatic F8 trigger |
| PQC-03 | ML-KEM | A/B/C/D packing isolation | Packed `u` lowers CASI; coefficient-model difference changes sign by parameter set | Packing effect is real; universal LWE-signature claim is unsupported |
| PQC-04 | SPHINCS+ family | Signature-boundary F8-O | Whole-signature permutation retains F8-O; within-signature row permutation removes it | Public intra-signature serialization marker |
| PQC-05 | ML-KEM | deterministic coins -> ciphertext/secret F8-I/O | All three parameter sets match shuffled outputs | No tested input/output F8 relation |
| PQC-06 | ML-KEM | ciphertext mutations | Fine bit/packing faults change secret but remain CASI/F8-near-valid | CASI is not a fine-grained KEM integrity checker |
| PQC-07 | ML-DSA-44 | signature-boundary F8-O | F8-O remains null under both permutations despite elevated CASI | ML-DSA CASI is not a row-order F8 artifact |
| PQC-08 | ML-KEM-512, ML-DSA-44 | balanced BvN route controls | Routes preserve every public 32-byte row exactly while intervening on order; all CASI and F8-O readings lie within the route-null range on the full rerun | A required public-output order/format gate, not an internal PQC or security result |
| PQC-09 | ML-KEM-512/768/1024 | corrected compression-cause intervention | Real compressed-symbol histograms match `Uniform(Z_q) -> Compress_d` (`reduced chi-square ≈ 1`); CASI/F8-O match the corrected control | Earlier B-vs-C separation is public quantizer occupancy, not evidence of an LWE-noise-specific signature |

## Executable evidence

`./scripts/reproduce_pqc.sh` regenerates the principal real-backend artifacts
and `results/v1/PQC_SHA256SUMS` pins their hashes.  The ML-DSA boundary result
is additionally retained in `results/v1/mldsa44_boundary_controls.json`. The
balanced route artifact is `results/v1/pqc_bvn_route_controls_v1.json`; its
method and bounded interpretation are in `BVN_ROUTE_CAUSAL_V1.md`.
The corrected compression cause and its exact preimage-count formula are in
`CAUSAL_MECHANISM_RESULTS_V1.md`.

## Next experimental frontier

The high-value next question is not another output-only sweep. It is a
version-matched instrumented ML-KEM `indcpa_enc` trace with explicit snapshots
before/after noise addition, NTT, reduction, compression and packing, plus
the same BvN-route, shuffled and representation controls used here. The current wheel
does not ship C source, so that extension requires a source revision proven
identical to the installed backend before it can be treated as evidence.
