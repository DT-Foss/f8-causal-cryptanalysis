# ChaCha20 key-contrast Mobius width-8 calibration (A215P)

**Evidence stage:** `ROUND3_RAW_OUTPUT_MOBIUS_SATURATION_BOUNDARY`

This target-free calibration enumerates the complete low-8 subspace of the frozen R20 public material and computes the exact Boolean Mobius spectrum of one standard 512-bit feed-forward block at every round boundary.

| Round | Maximum degree | Order-3 strict holdout accuracy |
|---:|---:|---:|
| 0 | 1 | 1.000000000 |
| 1 | 8 | 0.938386695 |
| 2 | 8 | 0.570456288 |
| 3 | 8 | 0.500047929 |
| 4 | 8 | 0.500047929 |
| 8 | 8 | 0.497591545 |
| 12 | 8 | 0.499652512 |
| 16 | 8 | 0.500287577 |
| 20 | 8 | 0.499269076 |

R1 retains a strong low-order extrapolation signal. R2 is the transition. By R3, strict unseen-key accuracy is at chance and each degree band is approximately half dense; R20 retains that saturated raw-output boundary.

The calibration therefore routes A215 toward carry residuals, multiple contrast centers, Causal/F8/CASI views, and—if order 3 does not transfer—the exact full-width degree spectrum rather than treating a raw low-order output polynomial as the final mechanism.

- A215 protocol SHA-256: `22f8d8b703575d19fb8ecfd5543b925f39d8f36693cc30748fb65f4d4941bd04`
- Measurement SHA-256: `e3a140ad01a1c6e67dcb988a2c2324f1d6e5fdd354b707e0f7c23368ddebccf8`
- Causal graph SHA-256: `b3229a7023fcb56f856a40dc70d0a9ea46e56ef079cef79a9e237292136fbed3`
