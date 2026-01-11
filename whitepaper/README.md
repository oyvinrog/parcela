# Whitepaper

Source files live here to keep `docs/` clean for GitHub Pages.

## Build APA PDF (recommended)

```bash
cd whitepaper
latexmk -pdf Parcela-Whitepaper.tex
```

Then copy the PDF into `docs/` so it is published by GitHub Pages:

```bash
cp whitepaper/Parcela-Whitepaper.pdf docs/Parcela-Whitepaper.pdf
```

## Legacy groff source

`Parcela-Whitepaper.tr` is kept for reference only; the APA-styled PDF is built from LaTeX.
