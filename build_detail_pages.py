#!/usr/bin/env python3
"""Generate reskin-styled per-scanner deep-dive pages into reports/scanners/<slug>.html.

Shares the main site's shell (topbar, gold theme, styles.css, footer) and surfaces
the full per-scanner detail: 8 headline KPIs, a visual per-repository TP/FP/FN
stacked-bar chart + table, detection-by-severity, detection-by-CWE-family, and
(for LLM scanners) operational + cost metric grids. Data: reports/dashboard.json.
"""
from __future__ import annotations

import json
from pathlib import Path

from build_site import SCANNER_META, SCANNER_NOTES, SCANNER_PROVIDERS, SCANNER_URLS, inject_analytics  # slug -> (name, cat, ver); slug -> note html

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CAT_LABEL = {"sec": "Security-Specialized", "llm": "General-Purpose LLM", "rule": "Rule-Based SAST"}
SEV_ORDER = ["critical", "high", "medium", "low"]

SHELL_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{title} — RealVuln</title>
<meta name="description" content="RealVuln scanner deep-dive for {title}: F3/F2, recall, precision, cost, per-repository detection, severity, CWE families, and operational metrics." />
<link rel="stylesheet" href="../styles.css" />
</head>
<body>

<header class="topbar">
  <div class="wrap topbar-inner">
    <a class="brand" href="../index.html"><span class="mark">▚</span> real<span style="color:var(--accent)">vuln</span> <span class="v">v{ver}</span></a>
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
      <span>RealVuln · Apache 2.0 · arXiv:2604.13764 · v{ver}</span>
      <span class="disc">RealVuln is independent research by John Pellew and Faizan Raza, founding members of Kolega.Dev. Kolega.Dev is among the scanners evaluated here — so every ground-truth label, scanner output, and scoring script is released openly for independent reproduction and audit.</span>
    </div>
  </div>
</footer>

<script src="../app.js"></script>
<script src="../versions.js"></script>
</body>
</html>
"""


def kpi(n, label):
    return f'<div class="hk"><div class="hk-n">{n}</div><div class="hk-l">{label}</div></div>'


def mg(v, label):
    return f'<div class="mg"><div class="v">{v}</div><div class="l">{label}</div></div>'


def subhead(title):
    return ('<div class="subhead" style="margin-top:46px"><span class="sn">§</span>'
            f'<h2 style="font-size:clamp(22px,3vw,30px);letter-spacing:-0.02em">{title}</h2></div>')


def simple_table(headers, rows):
    h = "".join(f'<th class="l">{headers[0]}</th>' if i == 0 else f"<th>{c}</th>" for i, c in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f'<td class="l">{c}</td>' if i == 0 else f"<td>{c}</td>" for i, c in enumerate(r)) + "</tr>"
        for r in rows
    )
    return f'<div class="table-scroll" style="margin-top:20px"><table class="simple"><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table></div>'


def build_page(slug: str, agg: dict, grid: dict, meta: dict) -> str:
    name, cat, ver = SCANNER_META.get(slug, (slug, "llm", ""))
    strict = agg.get("strict_micro", agg.get("micro", {}))
    micro = agg.get("micro", {})
    cost_d = agg.get("cost") or {}
    cost = cost_d.get("total_cost", 0) or 0
    repos_scored = agg.get("repos_scored", 0)
    repos_total = agg.get("repos_total", 26)
    has_metrics = bool(meta.get("has_metrics"))
    cost_est = bool(cost_d.get("estimated"))
    if cat == "rule" or cost <= 0:
        cost_str = "Free"
    elif cost_est:
        cost_str = f"~${cost:,.0f} <span style=\"font-size:.5em;color:var(--fg-3)\">est.</span>"
    else:
        cost_str = f"${cost:,.0f}"
    model = meta.get("model") or "—"
    latency = f'{meta.get("avg_wall_clock_seconds", 0):.0f}s' if has_metrics else "—"

    # ---- per-repo rows + severity/family accumulation ----
    rows = []
    fam_acc: dict[str, list] = {}
    sev_acc: dict[str, list] = {s: [0, 0, 0] for s in SEV_ORDER}
    for repo, cells in grid.items():
        cell = cells.get(slug)
        if not cell:
            continue
        tp, fp, fn = cell.get("tp", 0), cell.get("fp", 0), cell.get("fn", 0)
        rows.append({"repo": repo.replace("realvuln-", ""), "tp": tp, "fp": fp, "fn": fn,
                     "recall": cell.get("recall", 0) * 100, "f2": cell.get("f2_score", 0)})
        for fam, info in (cell.get("per_family") or {}).items():
            a = fam_acc.setdefault(fam, [info.get("label", fam), 0, 0, 0])
            a[1] += info.get("tp", 0); a[2] += info.get("fp", 0); a[3] += info.get("fn", 0)
        for sev, info in (cell.get("per_severity") or {}).items():
            if sev in sev_acc:
                sev_acc[sev][0] += info.get("tp", 0); sev_acc[sev][1] += info.get("fp", 0); sev_acc[sev][2] += info.get("fn", 0)
    rows.sort(key=lambda r: r["f2"], reverse=True)
    max_total = max((r["tp"] + r["fp"] + r["fn"] for r in rows), default=1) or 1

    out = [inject_analytics(SHELL_HEAD.format(title=name, ver=VER))]

    # hero
    out.append('<section class="wrap page-hero">')
    out.append('  <div class="breadcrumb"><a href="../index.html">RealVuln</a><span class="sep">/</span>'
               '<a href="../dashboard.html">Dashboard</a><span class="sep">/</span><span>' + name + '</span></div>')
    out.append('  <div class="ph-num">Scanner deep-dive</div>')
    provider, url = SCANNER_PROVIDERS.get(slug), SCANNER_URLS.get(slug)
    if provider and url:
        provider_html = (f' <a href="{url}" target="_blank" rel="noopener" '
                         f'style="font-family:var(--mono);font-size:clamp(13px,1.4vw,15px);'
                         f'font-weight:400;letter-spacing:0;color:var(--accent);'
                         f'text-decoration:none;white-space:nowrap;vertical-align:middle">'
                         f'by {provider} ↗</a>')
    elif provider:
        provider_html = (f' <span style="font-family:var(--mono);font-size:clamp(13px,1.4vw,15px);'
                         f'font-weight:400;letter-spacing:0;color:var(--fg-2);'
                         f'white-space:nowrap;vertical-align:middle">by {provider}</span>')
    else:
        provider_html = ""
    out.append(f'  <h1>{name}{provider_html}</h1>')
    out.append(f'  <p class="lede">{CAT_LABEL.get(cat, cat)} · <span class="mono">{ver}</span> · '
               f'scored on {repos_scored}/{repos_total} repositories. Strict scoring (unfinished repos counted as misses).</p>')
    out.append("</section>")

    # optional methodology note (e.g. non-standard harness)
    note = SCANNER_NOTES.get(slug)
    if note:
        out.append('<section class="wrap" style="padding-top:0">')
        out.append('  <div style="border:1px solid var(--accent);border-left-width:3px;'
                   'border-radius:8px;padding:18px 20px;background:rgba(212,160,23,0.06);'
                   'font-size:15px;line-height:1.6;color:var(--fg-2)">'
                   '<div class="mono" style="color:var(--accent);font-size:12px;'
                   'letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">'
                   'Methodology note</div>' + note + '</div>')
        out.append("</section>")

    # KPI strip (8)
    out.append('<section class="wrap" style="padding-bottom:8px"><div class="hero-kpis sd-kpis">')
    out.append(kpi(f'{strict.get("f3_score", 0):.1f}', "F3 (strict)"))
    out.append(kpi(f'{strict.get("f2_score", 0):.1f}', "F2 (strict)"))
    out.append(kpi(f'{strict.get("recall", 0) * 100:.1f}%', "Recall (strict)"))
    out.append(kpi(f'{micro.get("precision", 0) * 100:.1f}%', "Precision"))
    out.append(kpi(f'{repos_scored}<span style="color:var(--fg-3)">/{repos_total}</span>', "Repos scored"))
    out.append(kpi(f'<span style="font-size:.5em">{model}</span>', "Model"))
    out.append(kpi(cost_str, "Total cost"))
    out.append(kpi(latency, "Avg latency"))
    out.append("</div></section>")

    out.append('<section class="section"><div class="wrap">')

    # per-repo stacked bars (visual) + table
    out.append('  <div class="subhead"><span class="sn">§</span>'
               '<h2 style="font-size:clamp(22px,3vw,30px);letter-spacing:-0.02em">Per-repository breakdown</h2></div>')
    out.append('  <p class="section-intro">Each bar shows true positives, false positives, and misses on one repository; bar length is proportional to that repo\'s labeled vulnerabilities. Ranked by F2.</p>')
    out.append('  <div class="barlegend" style="margin-top:18px"><span><span class="sw tp"></span>True positive</span>'
               '<span><span class="sw fp"></span>False positive</span><span><span class="sw fn"></span>Missed (FN)</span></div>')
    out.append('  <div class="repobars">')
    for r in rows:
        total = r["tp"] + r["fp"] + r["fn"]
        scale = (total / max_total) * 100  # bar width vs widest repo
        segs = ""
        for kind in ("tp", "fp", "fn"):
            if r[kind]:
                w = (r[kind] / total) * scale if total else 0
                segs += f'<span class="rb-seg {kind}" style="width:{w:.2f}%"></span>'
        out.append(f'    <div class="rb"><span class="rb-name">{r["repo"]}</span>'
                   f'<span class="rb-bar">{segs}</span>'
                   f'<span class="rb-meta"><b>{r["f2"]:.0f}</b> F2 · {r["recall"]:.0f}%</span></div>')
    out.append("  </div>")
    out.append(simple_table(["Repository", "TP", "FP", "FN", "Recall %", "F2"],
                            [[r["repo"], r["tp"], r["fp"], r["fn"], f'{r["recall"]:.1f}', f'{r["f2"]:.1f}'] for r in rows]))

    # detection by severity
    sev_rows = [[s.capitalize(), v[0], v[1], v[2], f'{(v[0] / (v[0] + v[2]) * 100 if (v[0] + v[2]) else 0):.1f}']
                for s in SEV_ORDER for v in [sev_acc[s]] if (v[0] + v[1] + v[2]) > 0]
    if sev_rows:
        out.append(subhead("Detection by severity"))
        out.append(simple_table(["Severity", "TP", "FP", "FN", "Recall %"], sev_rows))

    # detection by CWE family
    fams = [v for v in fam_acc.values() if (v[1] + v[3]) > 0]
    fams.sort(key=lambda v: -(v[1] / (v[1] + v[3]) if (v[1] + v[3]) else 0))
    if fams:
        out.append(subhead("Detection by vulnerability class"))
        out.append(simple_table(["CWE family", "TP", "FP", "FN", "Recall %"],
                                [[lbl, tp, fp, fn, f'{(tp / (tp + fn) * 100 if (tp + fn) else 0):.1f}'] for lbl, tp, fp, fn in fams]))

    # LLM operational metrics
    if has_metrics:
        out.append(subhead("LLM operational metrics"))
        out.append('  <div class="mgrid" style="margin-top:20px">')
        out.append(mg(f'{meta.get("avg_input_tokens", 0):,}', "Avg input tokens"))
        out.append(mg(f'{meta.get("avg_output_tokens", 0):,}', "Avg output tokens"))
        out.append(mg(f'{meta.get("avg_total_tokens", 0):,}', "Avg total tokens"))
        out.append(mg(f'{meta.get("avg_wall_clock_seconds", 0):.0f}s', "Avg latency / repo"))
        out.append(mg(f'{meta.get("json_repair_rate", 0) * 100:.1f}%', "JSON repair rate"))
        out.append(mg(f'{meta.get("total_runs", 0)}', "Total runs"))
        if agg.get("num_runs", 1) > 1:
            out.append(mg(f'±{agg.get("f2_stddev", 0):.1f}', "F2 run-to-run σ"))
        out.append("  </div>")

    # cost breakdown
    out.append(subhead("Cost"))
    out.append('  <div class="mgrid" style="margin-top:20px">')
    out.append(mg(cost_str, "Total cost"))
    if cost > 0:
        out.append(mg(f'${cost_d.get("cost_per_run", 0):.2f}', "Cost / run"))
        out.append(mg(f'${cost_d.get("cost_per_100_loc", 0):.3f}', "Cost / 100 LOC"))
    out.append(mg(f'{cost_d.get("total_loc_scanned", 0):,}', "Python LOC scanned"))
    out.append(mg(f'{cost_d.get("successful_runs", 0)}', "Successful runs"))
    out.append("  </div>")

    out.append('  <p class="figure-cap" style="margin-top:30px"><a href="../dashboard.html">← Back to the leaderboard</a></p>')
    out.append("</div></section>")
    out.append(SHELL_FOOT.format(ver=VER))
    return "\n".join(out)


# benchmark version (e.g. "2.0") shown in the shared shell; set in main()
VER = "1.0"


def main() -> None:
    global VER
    data = json.loads((REPORTS / "dashboard.json").read_text())
    bv = str(data.get("benchmark_version", "") or "")
    VER = ".".join(bv.split(".")[:2]) if bv else "1.0"
    aggs, grid = data["aggregates"], data["grid"]
    meta_all = data.get("scanner_metadata", {})
    outdir = REPORTS / "scanners"
    outdir.mkdir(exist_ok=True)
    n = 0
    for slug in SCANNER_META:
        if slug not in aggs:
            continue
        (outdir / f"{slug}.html").write_text(build_page(slug, aggs[slug], grid, meta_all.get(slug, {})))
        n += 1
    print(f"wrote {n} reskin-styled scanner detail pages -> reports/scanners/")


if __name__ == "__main__":
    main()
