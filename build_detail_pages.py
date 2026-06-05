#!/usr/bin/env python3
"""Generate reskin-styled per-scanner deep-dive pages into reports/scanners/<slug>.html.

Replaces the legacy Plotly-themed detail pages with pages that share the main
site's shell (topbar, gold editorial theme, styles.css, footer). Data comes from
reports/dashboard.json (per-scanner aggregates + per-repo grid).
"""
from __future__ import annotations

import json
from pathlib import Path

from build_site import SCANNER_META  # slug -> (name, cat, ver)

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CAT_LABEL = {"sec": "Security-Specialized", "llm": "General-Purpose LLM", "rule": "Rule-Based SAST"}

SHELL_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{title} — RealVuln</title>
<meta name="description" content="RealVuln scanner deep-dive for {title}: F3/F2, recall, precision, cost, and per-repository detection breakdown." />
<link rel="stylesheet" href="../styles.css" />
</head>
<body>

<header class="topbar">
  <div class="wrap topbar-inner">
    <a class="brand" href="../index.html"><span class="mark">▚</span> real<span style="color:var(--accent)">vuln</span> <span class="v">v1.0</span></a>
    <nav class="topnav">
      <span class="navlinks" style="display:contents">
        <a href="../dashboard.html" style="color:var(--fg)">Dashboard</a>
        <a href="../methodology.html">Methodology</a>
        <a href="../dataset.html">Dataset</a>
        <a href="../findings.html">Findings</a>
        <a href="../roadmap.html">Roadmap</a>
      </span>
      <a class="gh" href="https://github.com/kolega-ai/Real-Vuln-Benchmark" target="_blank" rel="noopener">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GitHub
      </a>
      <button class="nav-toggle" aria-label="Menu">≡</button>
    </nav>
  </div>
</header>

<div class="mobile-menu" id="mobile-menu">
  <a href="../dashboard.html">Dashboard</a>
  <a href="../methodology.html">Methodology</a>
  <a href="../dataset.html">Dataset</a>
  <a href="../findings.html">Findings</a>
  <a href="../roadmap.html">Roadmap</a>
  <a href="https://github.com/kolega-ai/Real-Vuln-Benchmark" target="_blank" rel="noopener">GitHub ↗</a>
</div>

<main>
"""

SHELL_FOOT = """</main>

<footer class="footer">
  <div class="wrap">
    <div class="footer-base" style="margin-top:0;padding-top:0;border-top:none">
      <span>RealVuln · MIT License · arXiv:2604.13764 · v1.0, March 2026</span>
      <span class="disc">RealVuln is independent research by John Pellew and Faizan Raza, founding members of Kolega.Dev. Kolega.Dev is among the scanners evaluated here — so every ground-truth label, scanner output, and scoring script is released openly for independent reproduction and audit.</span>
    </div>
  </div>
</footer>

<script src="../app.js"></script>
</body>
</html>
"""


def kpi(n, label):
    return f'<div class="hk"><div class="hk-n">{n}</div><div class="hk-l">{label}</div></div>'


def fnum(v, suffix="", dash="—"):
    return f"{v}{suffix}" if v is not None else dash


def build_page(slug: str, agg: dict, grid: dict) -> str:
    name, cat, ver = SCANNER_META.get(slug, (slug, "llm", ""))
    strict = agg.get("strict_micro", agg.get("micro", {}))
    micro = agg.get("micro", {})
    cost = (agg.get("cost") or {}).get("total_cost", 0) or 0
    repos_scored = agg.get("repos_scored", 0)
    repos_total = agg.get("repos_total", 26)
    cost_str = "Free" if (cat == "rule" or cost <= 0) else f"${cost:,.0f}"

    # per-repo rows from the grid
    rows = []
    fam_acc: dict[str, list] = {}
    for repo, cells in grid.items():
        cell = cells.get(slug)
        if not cell:
            continue
        rows.append({
            "repo": repo.replace("realvuln-", ""),
            "tp": cell.get("tp", 0), "fp": cell.get("fp", 0), "fn": cell.get("fn", 0),
            "recall": cell.get("recall", 0) * 100, "f2": cell.get("f2_score", 0),
        })
        for fam, info in (cell.get("per_family") or {}).items():
            a = fam_acc.setdefault(fam, [info.get("label", fam), 0, 0, 0])
            a[1] += info.get("tp", 0); a[2] += info.get("fp", 0); a[3] += info.get("fn", 0)
    rows.sort(key=lambda r: r["f2"], reverse=True)

    out = [SHELL_HEAD.format(title=name)]
    # hero
    out.append('<section class="wrap page-hero">')
    out.append('  <div class="breadcrumb"><a href="../index.html">RealVuln</a><span class="sep">/</span>'
               '<a href="../dashboard.html">Dashboard</a><span class="sep">/</span><span>' + name + '</span></div>')
    out.append(f'  <div class="ph-num">Scanner deep-dive</div>')
    out.append(f'  <h1>{name}</h1>')
    out.append(f'  <p class="lede">{CAT_LABEL.get(cat, cat)} · <span class="mono">{ver}</span> · '
               f'scored on {repos_scored}/{repos_total} repositories. Strict scoring (unfinished repos counted as misses).</p>')
    out.append("</section>")
    # KPI strip
    out.append('<section class="wrap" style="padding-bottom:8px"><div class="hero-kpis">')
    out.append(kpi(f'{strict.get("f3_score", 0):.1f}', "F3 (strict)"))
    out.append(kpi(f'{strict.get("f2_score", 0):.1f}', "F2 (strict)"))
    out.append(kpi(f'{strict.get("recall", 0) * 100:.1f}%', "Recall"))
    out.append(kpi(f'{micro.get("precision", 0) * 100:.1f}%', "Precision"))
    out.append(kpi(cost_str, "Run cost"))
    out.append(kpi(f'{repos_scored}<span style="color:var(--fg-3)">/{repos_total}</span>', "Repos scored"))
    out.append("</div></section>")
    # per-repo breakdown
    out.append('<section class="section"><div class="wrap">')
    out.append('  <div class="subhead"><span class="sn">§</span><h2 style="font-size:clamp(22px,3vw,30px);letter-spacing:-0.02em">Per-repository detection</h2></div>')
    out.append('  <p class="section-intro">True/false positives and misses on each repository this scanner completed, ranked by F2.</p>')
    out.append('  <div class="table-scroll" style="margin-top:20px"><table class="simple"><thead><tr>'
               '<th class="l">Repository</th><th>TP</th><th>FP</th><th>FN</th><th>Recall %</th><th>F2</th></tr></thead><tbody>')
    for r in rows:
        out.append(f'<tr><td class="l">{r["repo"]}</td><td>{r["tp"]}</td><td>{r["fp"]}</td>'
                   f'<td>{r["fn"]}</td><td>{r["recall"]:.1f}</td><td>{r["f2"]:.1f}</td></tr>')
    out.append("</tbody></table></div>")
    # per-family
    fams = [v for v in fam_acc.values() if (v[1] + v[3]) > 0]
    fams.sort(key=lambda v: -(v[1] / (v[1] + v[3]) if (v[1] + v[3]) else 0))
    if fams:
        out.append('  <div class="subhead" style="margin-top:46px"><span class="sn">§</span>'
                   '<h2 style="font-size:clamp(22px,3vw,30px);letter-spacing:-0.02em">Detection by vulnerability class</h2></div>')
        out.append('  <div class="table-scroll" style="margin-top:20px"><table class="simple"><thead><tr>'
                   '<th class="l">CWE family</th><th>TP</th><th>FP</th><th>FN</th><th>Recall %</th></tr></thead><tbody>')
        for label, tp, fp, fn in fams:
            rec = tp / (tp + fn) * 100 if (tp + fn) else 0
            out.append(f'<tr><td class="l">{label}</td><td>{tp}</td><td>{fp}</td><td>{fn}</td><td>{rec:.1f}</td></tr>')
        out.append("</tbody></table></div>")
    out.append('  <p class="figure-cap" style="margin-top:22px"><a href="../dashboard.html">← Back to the leaderboard</a></p>')
    out.append("</div></section>")
    out.append(SHELL_FOOT)
    return "\n".join(out)


def main() -> None:
    data = json.loads((REPORTS / "dashboard.json").read_text())
    aggs, grid = data["aggregates"], data["grid"]
    outdir = REPORTS / "scanners"
    outdir.mkdir(exist_ok=True)
    n = 0
    for slug in SCANNER_META:
        if slug not in aggs:
            continue
        (outdir / f"{slug}.html").write_text(build_page(slug, aggs[slug], grid))
        n += 1
    print(f"wrote {n} reskin-styled scanner detail pages -> reports/scanners/")


if __name__ == "__main__":
    main()
