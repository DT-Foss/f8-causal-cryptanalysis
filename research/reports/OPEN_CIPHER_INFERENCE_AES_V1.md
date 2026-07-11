# Open Cipher Inference: AES Prefix Formula Projection

## Scope

This is a separate reduced-round chosen-input/output inference track.  It is
not an F8 claim, not a carry-leak claim, and not a key-recovery claim.  The
question is whether a fixed, public representation of paired AES outputs
reveals a reproducible differential structure that disappears at later rounds.

## Exact experiment

`aes_prefix_batch` implements genuine AES-128 prefixes: MixColumns is present
in rounds 1--9 and absent only in round 10.  For each random key, 10,000 unique
random plaintext blocks are paired with the same block after XORing exactly one
of all 128 possible input bits.  The factual pairing is compared with eight
independent permutations of the second output rows.  The primary statistic is
the summed bytewise entropy deficit of the XOR differences.

The formula projection is public and key-free.  For prefix rounds 1--9, XORing
two outputs cancels the final AddRoundKey; applying InvMixColumns followed by
InvShiftRows therefore removes only the final public linear layer.  For AES-10,
where the final round has no MixColumns, the semantically correct projection is
InvShiftRows alone.

## Discovery and frozen confirmation

The discovery screen covered R1/R2/R3/R4/AES-10, all 128 input bits, five keys,
and both identity and formula-derived representations.  The frozen confirmation
used ten disjoint keys, 10,000 pairs per key, eight repairing routes, and the
pre-registered families R3/R4/AES-10 × identity/peeled representation.

| round | representation | effect range (min--max) | all ten-key effects positive | family BH q <= .01 |
|---|---|---:|---:|---:|
| R3 | identity | -0.00563 .. 0.00544 | 0/128 | 0/128 |
| R3 | peeled final linear | 0.08440 .. 0.09412 | 128/128 | 128/128 |
| R4 | identity | -0.00552 .. 0.00464 | 0/128 | 0/128 |
| R4 | peeled final linear | -0.00591 .. 0.00649 | 0/128 | 0/128 |
| AES-10 | identity | -0.00446 .. 0.00655 | 0/128 | 0/128 |
| AES-10 | peeled final linear | -0.00512 .. 0.00555 | 0/128 | 0/128 |

The R3 peeled family has exact paired sign-flip `p=0.001953125` for every
bit and family BH `q=0.001953125`.  A conservative global BH correction across
all six pre-specified families is also stored; its minimum for R3 peeled is
`0.0116279`.  The family statistic is the frozen decision statistic, while the
global value is reported to prevent hidden multiplicity optimism.

## Interpretation boundary

The result shows a reproducible R3 differential structure in a formula-derived
output representation.  It does not provide key recovery, a distinguisher for
full AES, or a security break.  R2 is partly explained by the expected sparse
active-byte geometry after undoing the final linear layer; R3 is the nontrivial
frontier because the raw representation is null-like while the peeled
representation remains consistently nonuniform.  R4 and AES-10 controls close
the immediate extension tested here.

## Artifacts

- Config: `configs/aes_formula_projection_confirm_v1.json`, SHA-256
  `01a630afe1309fad2c6e2ac20c6a542cd31c98508c728645eccdabaf81f9c5b2`.
- Discovery: `results/v1/aes_formula_projection_screen_v1.json`, SHA-256
  `9577e9a62e5b10b29e141e9b330099b49c63cf71c991239e3eb238faadca2678`.
- Confirmation: `results/v1/aes_formula_projection_confirm_v1.json`, SHA-256
  `5aa6cb0e68d72ff4be581c7dea81941f3740dfbae2a31bdd2a1c0035bbdf0201`.
- Causal graph: `results/v1/aes_formula_projection_confirm_v1.causal`, SHA-256
  `de6f553737688856124197e9e0a37f929a5b9bd0e1c0d6aa21f257e012da2f41`.

The `.causal` artifact has 768 typed edges.  It is read back with
`CryptoCausalReader` as part of the experiment and by the repository-wide
validator.
