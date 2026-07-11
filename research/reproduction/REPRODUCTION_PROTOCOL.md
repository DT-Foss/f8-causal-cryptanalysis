# Historical reproduction protocol

The historical sources under `provenance/` are read-only evidence. A paper
result is reproduced only when the archived source hash, exact command,
environment, stdout, stderr, exit status, runtime, and output hashes are retained.

## Two non-interchangeable tracks

1. **Historical replay** executes the archived source exactly as found. It can
   reproduce what was computed, including implementation defects.
2. **Corrected rerun** uses only implementations that pass the applicable
   primary reference-vector gate. It answers whether the reported phenomenon
   survives the correction.

Historical and corrected outputs must never overwrite each other. They live in
`research/results/reproduction_v1/` and `research/results/corrected_v1/`.

## Commands

```bash
.venv/bin/python research/reproduction/build_manifest.py
.venv/bin/python research/reproduction/run_legacy_reproduction.py --list
.venv/bin/python research/reproduction/run_legacy_reproduction.py <experiment-id>
.venv/bin/python research/reproduction/summarize_runs.py
.venv/bin/python research/reproduction/rebuild_nano_master.py \
  --output research/results/reproduction_v1/nano_master_rebuild.json
.venv/bin/python research/reproduction/audit_nano_protocol.py \
  --output research/results/reproduction_v1/nano_protocol_audit.json
```

The runner skips an already completed experiment unless `--force` is supplied.
Timeouts and failures are evidence and remain on disk.

An expected historical failure may be marked `reproduced_expected_failure` only
when both its return code and a specific terminal error match the manifest.
`graph_attack.py` is such a case: it requests AES round 11 from a ten-round key
schedule. Any different failure remains `unexpected_outcome` and fails the run.

## Claim closure rule

A claim is `EVIDENCED` only if all of the following exist:

- a versioned executable source;
- retained raw or structured output;
- an exact portable command;
- a passing implementation-validity gate where a primitive is implemented;
- agreement between paper protocol, executed protocol, and reported number.

Narrative-only numbers, hard-coded observations, missing generators, protocol
drift, and KAT failures remain `PARTIAL`, `MISSING`, or `CONTRADICTED`.
