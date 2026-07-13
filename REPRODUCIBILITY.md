# Reproducibility

The maintained four-tier protocol, fresh-clone commands, expected artifacts,
native portability notes, and hash verification procedure are in
[`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).

Fast integrity gate:

```bash
./scripts/reproduce_quick.sh
```

Completed A211--A220P retained-evidence plus frozen A220/A220B/A222
infrastructure gate:

```bash
./scripts/reproduce_a211_a220p.sh
```

Hash-only authentication of the twelve original full-round F8 configurations:

```bash
./scripts/verify_anchors.sh
```
