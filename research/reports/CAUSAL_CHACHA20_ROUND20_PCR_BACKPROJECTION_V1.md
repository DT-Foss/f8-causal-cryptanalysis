# ChaCha20 R20 Causal-PCR Exact Backprojection (A213)

**Evidence stage:** `PROPAGATION_BOUNDARY`

A213 treats the key signal as joint compatibility with the public standard-output constraints, not as compressibility of the key bytes themselves. The five views share one exact CNF; their constraints are intersected, never multiplied as independent probabilities.

## Exact readout

- V1 base closure: 1649 assigned variables; 0 forced key bits.
- V2 singles: 0 contradictions; 0 key implications across 40 probes.
- V3 pairs: 0 pair nogoods; 0 genuinely pair-conditioned implications across 760 probes.
- V4 binary graph: 117030 residual binary clauses; 0 signed-key implications; 0 equivalences.
- V5 overlay: 1048576 / 1,048,576 candidates; entropy reduction 0.000000000000 bits.

## Scope

This experiment uses eight public standard ChaCha20 R20 input-output blocks and 236 declared known key bits. Secret-key R1-R19 states are not observed and candidate-generated trajectories are not relabeled as observations. A per-round versus jointly stacked CASI/F8/Kolmogorov arm therefore remains a separately labeled cross-round-oracle experiment.

## Reproduction anchors

- Protocol SHA-256: `d84e69246b1d78499f464184f1e5d841e36cef5ea3849f150ebdba0094703d47`
- R20 CNF SHA-256: `2c33afd9f78ed3e1a2180313571918af51d5eaf2e1cd3b09fb588b86745f19b1`
- Measurement SHA-256: `fd54833dae43ea25e7f236f57c964f56ab80821a2b31e9713c825a278fc90401`
- Causal graph SHA-256: `be4cee5319c3a30f0932cb683bbfe2ccdc08bda079bab273c6db446e7a0bf6f3`
- Causal reader provenance verified: `True`
