# Direct Output-Causal Compression: ML-KEM Coin-Bit Null

The AES/ChaCha direct causal contrast codec was applied to real native
ML-KEM-512 `enc_derand` calls. For each fixed deterministic key, a 32-byte
coin string and a one-bit-mutated copy were encapsulated; all ciphertext pairs
were functional and every decapsulation was verified. The output graph
contains factual ciphertext pairs and row-repair counterfactuals, then the
reader tries to reverse-classify the coin-bit intervention.

The four pre-specified coin bits were 0, 63, 127 and 255. The full run used
10 keys, 1,000 paired encapsulations/key, five train keys, five holdout keys,
and 16 repair routes. All 10,000 decapsulations were exact.

Overall reader-only accuracy is 25%, exactly four-class chance. Bit 63 was a
4/5 discovery fluctuation, then scored 0/5 in the frozen new-key confirmation.
The Coinbit-to-ciphertext causal-contrast family is therefore closed for this
configuration. This is a controlled public relation study, not a security
claim.

Artifacts:

- Full screen: `results/v1/mlkem_coin_causal_contrast_v1.json`, SHA-256
  `e8007fd8447d568b76e11a32a99f3b4757f09e999293eb24c911ea3ce4ee3ad3`.
- Frozen config: `configs/mlkem_coin_causal_bit63_confirm_v1.json`, SHA-256
  `a8db70cdd387524658d23d6a1706753fe8ba7af09a0547dc1e4f819ea1c02e84`.
- Confirmation: `results/v1/mlkem_coin_causal_bit63_confirm_v1.json`, SHA-256
  `bff8954b7c03e4a90b44f5a99be98fd3add2d2246fef539544f1407de88074ce`.
- Confirmation graph: `results/v1/mlkem_coin_causal_bit63_confirm_v1.causal`,
  SHA-256 `d8d3f75005254dc6ade40a42c445402ff0b193f822b0353e1ff96b3736b95422`.
