# Direct Output-Causal ML-KEM INDCPA Keyseed Null

The second native deterministic ML-KEM axis intervenes in the 32-byte seed of
`PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand` and observes public-key output.
For each of four seed-bit interventions (0/63/127/255), the graph compresses
factual public-key XOR deltas against shared BvN repairs into 32 entropy
chunks. Every base and changed key pair passes a native `indcpa_enc` then
`indcpa_dec` functional gate: 50,000/50,000 per run.

The discovery and frozen new-key confirmation both score exactly 25%, the
four-class chance rate. A bit-63 discovery value of 3/5 becomes 2/5 in the
confirmation. Thus no native deterministic keyseed-bit→public-key causal
profile is retained for this codec.

- Discovery: `results/v1/mlkem_indcpa_keyseed_causal_v1.json`, SHA-256 `d9398d92b08532e3831fee1df6c2628f7d1f204ccd91645a17ec7065d2350801`.
- Confirmation: `results/v1/mlkem_indcpa_keyseed_causal_confirm_v1.json`, SHA-256 `638931403b28938d6b1161777739ac0ae47c05fa8c687ef54e928f59887986bc`.
