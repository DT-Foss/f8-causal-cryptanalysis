# ChaCha20 R1--R20 key-contrast Mobius atlas (A215)

**Evidence stage:** `R3_RAW_OUTPUT_DEGREE_SATURATION_AND_R20_LOW_ORDER_REPRESENTATION_BOUNDARY`

A215 turns the four low-entropy key patterns into exact intervention centers, measures every first-, second-, and third-order derivative, and evaluates the frozen surrogates on 1,024 key-disjoint holdouts before opening the retained R20 target. The public-output rank never uses a candidate ChaCha evaluation.

## Round frontier

| Round | Nearest-center order-3 bit accuracy |
|---:|---:|
| 0 | 1.000000000 |
| 1 | 0.915982008 |
| 2 | 0.527808189 |
| 3 | 0.500032663 |
| 4 | 0.499711752 |
| 8 | 0.500024080 |
| 12 | 0.499974251 |
| 16 | 0.500103712 |
| 20 | 0.500073433 |

## Complete-domain public-output rank

- Validation-selected model: order `1`, `minimum_output_distance_four_centers`
- Validation median rank: `342,922.0` / 1,048,576
- Public R20 target rank: `985,694` / 1,048,576
- Target low20 (postseal confirmation): `0xe4934`

## Mechanism

The carry-free XOR control remains exactly affine through R20. Any observed higher-order coefficient in the factual path is therefore localized to modular carry generation and its propagation, not to rotation, XOR, layout, or serialization.

- Protocol SHA-256: `22f8d8b703575d19fb8ecfd5543b925f39d8f36693cc30748fb65f4d4941bd04`
- Prereveal SHA-256: `aad591b55094f50497ebf19c0399bfae2c6e33c8d1e3c3cfdae764ef50813839`
- Measurement artifact SHA-256: `882ae2504851f1bac1f2350f8c160dba6cddd5b03afc4eb09f2252fc9b8cb5ff`
- Causal graph SHA-256: `cc9794ae854baf65cbf6003dbc59dc709a6f90869401ad863b2b747060b82b60`
