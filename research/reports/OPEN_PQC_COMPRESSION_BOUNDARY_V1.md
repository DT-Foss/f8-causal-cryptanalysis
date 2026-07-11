# Open PQC Inference: ML-KEM NTT/Compress Boundary

This run was selected from the causal-reader breadcrumbs `poly_decompress_then_ntt`
and `Compress_10/11_unequal_preimage_counts`.  It tests a public formula chain,
not an ML-KEM security game.

For real ciphertext `v` samples, the decoded 256-coefficient vector was used
as a public representation baseline.  One fixed field coordinate was changed
by `+1 mod 3329`, followed by native `NTT` and `Compress_d`.  The matched
compressed-symbol difference was compared with row repairing and with an
equal-weight control that changes a random coefficient position per row.

The corrected `v` widths are `d=4` for ML-KEM-512/768 and `d=5` for ML-KEM-1024.
All 4,500 KEM operations passed decapsulation and all causal artifacts passed
reader round-trip validation.

| variant | fixed-position effect range | random-position effect range | exact p for fixed family |
|---|---:|---:|---:|
| ML-KEM-512 | 82.565 .. 83.712 | 249.990 .. 250.907 | 0.0625 |
| ML-KEM-768 | 82.347 .. 83.513 | 249.847 .. 250.992 | 0.0625 |
| ML-KEM-1024 | 44.942 .. 49.772 | 245.623 .. 252.356 | 0.0625 |

The random-position control is consistently more nonuniform than any frozen
position.  No position meets the five-seed `p<=0.01` gate, and the effect is
not parameter-set-specific.  This closes the immediate NTT/Compress boundary
line as an expected locality/null phenomenon.

Artifacts:

- Config: `configs/mlkem_compression_boundary_frontier_v1.json`, SHA-256
  `9fdb1ec7b8bf724ac56a762dcda3412cead14dcc9a2fe44c79f837482e3db8c0`.
- Results: `results/v1/mlkem_compression_boundary_frontier_v1.json`, SHA-256
  `ae672c328bea91a1074fa55b18d0912fd7e5aa9644adc8e671de036f8372272e`.
- Causal graph: `results/v1/mlkem_compression_boundary_frontier_v1.causal`,
  SHA-256 `25595d2cc4642df7e40cde77446e623c558be5970c519bdb5c810dc24794be83`.

The reader-driven planning artifact is
`results/v1/causal_breadcrumbs_v1.json` (SHA-256
`6e7bf3b2727470f3028a581f19044ce281cb6d56112bace6b9245e366b9b9606`).  It
read 54 graphs and 5,352 explicit edges, deduplicated generic metric tokens,
and retained 29 cross-mechanism bridges.  Those are hypotheses only until a
new run produces its own evidence triplets.
