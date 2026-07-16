# A442 personal Causal Reader readback

The main agent opened
`research/results/v1/chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.causal`
with `dotcausal.io.CausalReader(..., verify_integrity=True)` after the frozen A442
evaluation completed. This was a native Reader pass, not a JSON substitute.

## Native structure

- API id: `a442meta`
- Explicit triplets: 4
- Materialized inferred triplets: 1
- Embedded rules: 4
- Clusters: 1
- Gaps: 1
- Causal SHA-256: `89e079477ca230be5d2d6ba0231bf7833b29b5c6793076e5800622bf0b8ffb6b`

## Retained chain read by the main agent

1. The four positive and diverse A375 Readers generate a seven-operator
   Known-key aggregation atlas.
2. The prospectively frozen robustness key selects `borda_sum`; it is positive
   on all eight fixed blocks and its weakest block still gains
   `0.3287263877670634` bits.
3. The selected operator transfers identically and without W52 labels or
   refitting to both complete A439 axes.
4. The resulting exact `2^24` pair order has Spearman `0.8431311772480021`
   against A439 and intersects A439 in only `12,792 / 65,536 =
   0.1951904296875` of the first 65,536 pair cells.
5. The Reader materializes the closure from the A375 Reader family directly to
   `A442:orthogonal_W52_recovery_ready`.

## Main-agent interpretation

A441 established that preserving all sixteen direct product Readers barely
changed A439's global order. A442 changes the aggregation geometry instead:
coverage-first minimum rank is replaced by a calibration-selected consensus
rank. The large, exact pair-space displacement shows that this is a genuinely
new recovery trajectory rather than another tie-breaking variant of A439.

The single native gap asks for a qualified recovery execution. The next action
is therefore A443: freeze an executor that consumes the committed A442 prefix
and off-axis orders unchanged, preserves the existing A426 challenge and
candidate evaluator, and enters the compute queue without competing with live
workers.
