# Contributing

F8-Causal accepts reproducibility fixes, new primitive gates, new controls,
Reader improvements, and cryptanalytic experiments with a complete evidence
chain.

## Required evidence chain

1. State the attack model, known variables, recovered object, and complexity.
2. Gate the primitive against an official or independently embedded vector.
3. Freeze parameters and deterministic seeds in a config or explicit CLI.
4. Separate discovery from confirmation when selecting coordinates or graph
   structure from data.
5. Add structure-preserving and wrong-formula/source/key controls.
6. Emit result JSON and a `.causal` graph when the result uses a Reader.
7. Reopen the graph with `CryptoCausalReader`; never trust writer output alone.
8. Add focused tests and update one report, the attempt log, and the relevant
   SHA-256 manifest.

Do not overwrite a retained artifact without changing the experiment or schema
and documenting why. Control results and representation boundaries belong in
the attempt log; they are not deleted to create a cleaner success narrative.

## Local checks

```bash
python -m pytest -q
python -m compileall -q src research/experiments tests
python scripts/validate_causal_artifacts.py
python scripts/verify_hash_manifest.py \
  research/results/v1/FULLROUND_TRANSFER_SHA256SUMS
bash -n scripts/*.sh
git diff --check
```

Run `./scripts/reproduce_quick.sh` before opening a pull request. Paper-scale
and extended runs are required only when their artifacts change; attach the
command, environment, wall time, and resulting hashes.

## Style and authorship

- Preserve existing import/package names where changing them would break
  artifacts.
- Use `David Tom Foss` exactly in author metadata and credits.
- Do not commit host-specific absolute paths, caches, virtual environments,
  checkpoints, private correspondence, publisher PDFs, or secrets.
- Keep claims quantitative and bind them to the exact tested object. Do not
  label a distinguisher or state Reader as key recovery.
- Retain third-party copyright and license notices.

## Publication artifacts

Figures must be deterministic outputs of committed scripts reading committed
result data. The generated file must identify its inputs and their hashes.
Decorative or manually adjusted scientific plots are not accepted.
