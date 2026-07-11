# Direct Output-Causal ML-KEM INDCPA Noise Null

The direct native ML-KEM experiment was moved below the Fujisaki--Okamoto KEM
wrapper to the exported PQClean `indcpa_enc` primitive. For each deterministic
key, a fixed 32-byte message is encrypted with deterministic noise coins and
four one-bit coin interventions (0/63/127/255). Each base and changed
ciphertext was checked by native `indcpa_dec`: 50,000/50,000 decryptions
recovered the fixed message.

The direct cipher-output graph stores 32 chunk-entropy factual-minus-BvN
repair contrasts. Routes are shared across all four bit classes for a key and
the reader uses a pooled variance model on five new keys. Accuracy is 3/20
(15%) against four-class chance 25%; per-bit scores are 2/5, 0/5, 1/5 and
0/5. This closes the current deterministic INDCPA-noise-bit/chunk-entropy
codec. It is a controlled null, not an assertion about ML-KEM security.

Artifact: `results/v1/mlkem_indcpa_noise_causal_v1.json`, SHA-256
`fce09b55c42c17623a3180243923c59dcf6065421d0feb443d757269f2a791d4`.
