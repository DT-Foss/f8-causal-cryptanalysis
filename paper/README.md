# Paper sources

Both author-owned conference sources are retained. The ICECET tree includes the
unmodified LPPL-1.3 `IEEEtran.cls`; the Nano tree uses the installed IEEEtran
package. Build with TeX Live and `latexmk`:

```bash
cd paper/icecet2026 && latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
cd ../nano2026 && latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

Generated PDFs and LaTeX intermediates are ignored. Publisher-formatted PDFs,
review exports, and decision correspondence are not part of the Git release.
The sanitized author-owned Nanjing PowerPoint is retained under
`nano2026/presentation/`; see `docs/PRIOR_ART.md` for its hash and metadata
audit.
