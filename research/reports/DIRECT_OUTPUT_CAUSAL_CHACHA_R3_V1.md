# Direct Output-Causal Compression: ChaCha R3 Transfer

The AES factual-minus-repairing causal contrast codec transfers to ChaCha
without using AES formulas.  Inputs are random counters paired with a frozen
counter-bit XOR; cipher outputs are compressed into a 64-node per-byte entropy
contrast profile against row-repair counterfactuals.  The `.causal` graph is
reopened with `CryptoCausalReader` for the holdout reverse class query.

The three classes are ChaCha R3, R4 and R20.  Each run uses five train keys,
five disjoint holdout keys, 10,000 pairs/key, frozen bits 0/7/15/31 and 16
repairing routes.

| class | discovery | independent confirmation |
|---|---:|---:|
| R3 | 85% (17/20) | **90% (18/20)** |
| R4 | 50% (10/20) | 60% (12/20) |
| R20 | 55% (11/20) | 50% (10/20) |

Three-class chance is 33.3%.  The frozen rule required R3 at least 75% and at
least 20 percentage points above the stronger R4/R20 control.  Confirmation
gives 90% versus 60%, satisfying the rule.

This is reduced-round output inference under chosen counter differences, not a
key-recovery result or a break of ChaCha20.

## Stronger global-pairing null

The confirmation was repeated with 16 BvN global bijective routes rather than
independent shuffles. The routes preserve the output multiset and exclude true
and adjacent pairings. R3 increases to 19/20, while R4 is 10/20 and R20 is
8/20. The ChaCha result therefore does not depend on the weaker shuffle null.

Artifacts:

- Config: `configs/chacha_causal_contrast_signature_confirm_v1.json`, SHA-256
  `d4b2ebcbd6c29f9e84e6be7f6ae89261e3c761d91e3cce9910882d324dfa4f31`.
- Confirmation JSON: `results/v1/chacha_causal_contrast_signature_confirm_v1.json`,
  SHA-256 `da377fd4c977409eacc48a7ab5855497a107c19f3ce614ec3263ea03a0bc3364`.
- Confirmation graph: `results/v1/chacha_causal_contrast_signature_confirm_v1.causal`,
  SHA-256 `654ad59958c9158f1b554ed669e3f871dbe0490ea50f7dbb47062de8de3676db`.
- BvN hardening: `results/v1/chacha_causal_contrast_signature_bvn_v1.json`,
  SHA-256 `3e9ba83dc46bb49bbc2007d86fa9a58663b675ef27917c888839eaed6ad989bb`.
