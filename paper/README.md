# RealVuln Paper

LaTeX source for *RealVuln: Benchmarking Rule-Based, LLM, and Security-Specialized Scanners on Real-World Code*.

## Building

Requires a full TeX Live installation. Easiest via Docker:

```bash
# Generate figures first
pip install matplotlib numpy
python scripts/generate_scatter_plots.py

# Compile PDF (two passes for cross-references)
docker run --rm -v $(pwd):/work texlive/texlive \
  bash -c "cd /work && pdflatex -interaction=nonstopmode main.tex && pdflatex -interaction=nonstopmode main.tex"
```

Output: `main.pdf`

## Structure

```
main.tex                    # Root document
arxiv.sty                   # Two-column arXiv preprint style
sections/
  00-abstract.tex
  01-introduction.tex
  02-background.tex
  03-benchmark-design.tex   # Matching algorithm, scoring metrics
  04-experimental-setup.tex # Scanner descriptions, evaluation modes
  05-results.tex            # Leaderboard, cost analysis, figures
  06-analysis.tex           # Per-CWE breakdown, discussion
  07-living-benchmark.tex   # Roadmap, contribution path
  08-conclusion.tex
  09-appendix.tex
figures/                    # Generated PDFs (precision-recall, F3-vs-cost)
scripts/
  generate_scatter_plots.py # Reads reports/dashboard.json, writes figures/
references.bib
```

## Regenerating Figures

Figures are generated from the dashboard data. To update after re-scoring:

```bash
# From repo root
python dashboard.py --scanner-group all
python paper/scripts/generate_scatter_plots.py
```
