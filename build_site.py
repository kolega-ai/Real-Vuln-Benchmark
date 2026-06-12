#!/usr/bin/env python3
"""Build the public RealVuln site into reports/.

Reads the canonical dashboard.json (produced by dashboard.py) and emits
reports/realvuln-data.js — the single source of truth consumed by the static
site's app.js / dashboard.js. Then copies the static site source from site/
into reports/, replacing the old single-file dashboard.html.

Usage:
    python build_site.py                 # uses reports/dashboard.json
    python build_site.py --data foo.json
"""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SITE_SRC = ROOT / "site"
REPORTS = ROOT / "reports"

# Google Analytics 4 measurement ID for realvuln.com. Injected into every page's
# <head> at build time (see inject_analytics) so the tag lives in one place
# rather than being duplicated across source/generated pages.
GA_MEASUREMENT_ID = "G-BD1PYVN294"
GA_SNIPPET = (
    "\n<!-- Google tag (gtag.js) -->\n"
    f'<script async src="https://www.googletagmanager.com/gtag/js?id={GA_MEASUREMENT_ID}"></script>\n'
    "<script>\n"
    "  window.dataLayer = window.dataLayer || [];\n"
    "  function gtag(){dataLayer.push(arguments);}\n"
    "  gtag('js', new Date());\n"
    f"  gtag('config', '{GA_MEASUREMENT_ID}');\n"
    "</script>"
)


def inject_analytics(html: str) -> str:
    """Insert the GA4 tag right after <head>. Idempotent."""
    if GA_MEASUREMENT_ID in html or "<head>" not in html:
        return html
    return html.replace("<head>", "<head>" + GA_SNIPPET, 1)

# --- scanner slug -> (display name, category, version label) -----------------
# category: sec = Security-Specialized, llm = General-Purpose LLM, rule = Rule-Based SAST
SCANNER_META: dict[str, tuple[str, str, str]] = {
    "kolega-enterprise-v1":           ("Kolega Enterprise",  "sec",  "enterprise-v1"),
    "kolega-v0.0.1":                  ("Kolega.Dev",         "sec",  "v0.0.1"),
    "gpt-5.5-agentic-v1":             ("GPT-5.5",            "llm",  "agentic-v1"),
    "glm-5.1-agentic-v1":             ("GLM-5.1",            "llm",  "agentic-v1"),
    "glm-5-agentic-v1":               ("GLM-5",              "llm",  "agentic-v1"),
    "deepseek-v4-flash-agentic-v1":   ("DeepSeek V4 Flash",  "llm",  "agentic-v1"),
    "deepseek-v4-pro-agentic-v1":     ("DeepSeek V4 Pro",    "llm",  "agentic-v1"),
    "kimi-k2.6-agentic-v1":           ("Kimi K2.6",          "llm",  "agentic-v1"),
    "kimi-k2.5-agentic-v1":           ("Kimi K2.5",          "llm",  "agentic-v1"),
    "claude-fable-5-cc-v1":           ("Claude Fable 5",     "llm",  "claude-code-v1"),
    "claude-opus-4-8-agentic-v1":     ("Claude Opus 4.8",    "llm",  "agentic-v1"),
    "claude-opus-4-7-agentic-v1":     ("Claude Opus 4.7",    "llm",  "agentic-v1"),
    "claude-opus-4-6-agentic-v1":     ("Claude Opus 4.6",    "llm",  "agentic-v1"),
    "claude-sonnet-4-6-agentic-v1":   ("Claude Sonnet 4.6",  "llm",  "agentic-v1"),
    "claude-haiku-4-5-agentic-v1":    ("Claude Haiku 4.5",   "llm",  "agentic-v1"),
    "claude-haiku-4-5-v1":            ("Claude Haiku 4.5",   "llm",  "direct-v1"),
    "gemini-3.1-pro-agentic-v1":      ("Gemini 3.1 Pro",     "llm",  "agentic-v1"),
    "gemini-3.5-flash-agentic-v1":    ("Gemini 3.5 Flash",   "llm",  "agentic-v1"),
    "grok-4.20-reasoning-agentic-v1": ("Grok 4.20 Reasoning","llm",  "agentic-v1"),
    "grok-3-agentic-v1":              ("Grok 3",             "llm",  "agentic-v1"),
    "minimax-m2.7-agentic-v1":        ("Minimax M2.7",       "llm",  "agentic-v1"),
    "qwen-3.5-397b-agentic-v1":       ("Qwen 3.5 397B",      "llm",  "agentic-v1"),
    "semgrep":                        ("Semgrep",            "rule", "rule-based"),
    "snyk":                           ("Snyk Code",          "rule", "pattern+flow"),
    "sonarqube":                      ("SonarQube",          "rule", "community"),
}

# Vendor / company website per scanner, rendered as an external link (↗) next to
# the leaderboard label. Kolega entries point at product landing pages.
SCANNER_URLS: dict[str, str] = {
    "kolega-enterprise-v1":           "https://kolega.ai/enterprise",
    "kolega-v0.0.1":                  "https://kolega.dev",
    "gpt-5.5-agentic-v1":             "https://openai.com",
    "glm-5.1-agentic-v1":             "https://z.ai",
    "glm-5-agentic-v1":               "https://z.ai",
    "deepseek-v4-flash-agentic-v1":   "https://www.deepseek.com",
    "deepseek-v4-pro-agentic-v1":     "https://www.deepseek.com",
    "kimi-k2.6-agentic-v1":           "https://www.moonshot.ai",
    "kimi-k2.5-agentic-v1":           "https://www.moonshot.ai",
    "claude-fable-5-cc-v1":           "https://www.anthropic.com",
    "claude-opus-4-8-agentic-v1":     "https://www.anthropic.com",
    "claude-opus-4-7-agentic-v1":     "https://www.anthropic.com",
    "claude-opus-4-6-agentic-v1":     "https://www.anthropic.com",
    "claude-sonnet-4-6-agentic-v1":   "https://www.anthropic.com",
    "claude-haiku-4-5-agentic-v1":    "https://www.anthropic.com",
    "claude-haiku-4-5-v1":            "https://www.anthropic.com",
    "gemini-3.1-pro-agentic-v1":      "https://deepmind.google",
    "gemini-3.5-flash-agentic-v1":    "https://deepmind.google",
    "grok-4.20-reasoning-agentic-v1": "https://x.ai",
    "grok-3-agentic-v1":              "https://x.ai",
    "minimax-m2.7-agentic-v1":        "https://www.minimax.io",
    "qwen-3.5-397b-agentic-v1":       "https://qwen.ai",
    "semgrep":                        "https://semgrep.dev",
    "snyk":                           "https://snyk.io",
    "sonarqube":                      "https://www.sonarsource.com",
}

# Optional per-scanner methodology notes, rendered as a callout on the deep-dive
# page. Use for scanners whose run conditions differ from the standard agentic
# (OpenCode) harness, so the difference is transparent rather than implicit in
# the version label. HTML allowed.
SCANNER_NOTES: dict[str, str] = {
    "claude-fable-5-cc-v1": (
        "<strong>Different harness.</strong> Every other LLM scanner here runs "
        "agentically through the <span class=\"mono\">OpenCode</span> CLI "
        "(version label <span class=\"mono\">agentic-v1</span>). Fable 5 could "
        "not be benchmarked that way: the OpenCode→Anthropic API path was "
        "consistently blocked by provider content filtering on the "
        "intentionally-vulnerable source, returning refusals instead of findings. "
        "<br><br>"
        "Instead, each of the 26 repositories was scanned by a dedicated "
        "<span class=\"mono\">Claude Code</span> subagent (version label "
        "<span class=\"mono\">claude-code-v1</span>) using the <em>identical</em> "
        "system prompt as the agentic runner (prompt hash "
        "<span class=\"mono\">sha256:14ccb06a286c</span>), so findings remain "
        "comparable. The same prompt ran cleanly through Claude Code, which "
        "confirms the block was specific to the OpenCode delivery path — not "
        "the prompt or the model. "
        "<br><br>"
        "<strong>Caveats.</strong> These runs were interactive rather than "
        "metered, so token and latency figures were not recorded. The cost shown "
        "is an <em>estimate</em>: Fable 5's API price is exactly 2× Claude Opus "
        "4.8 ($10/$50 vs $5/$25 per 1M input/output tokens), so we project its "
        "cost as 2× Opus 4.8's measured cost on the same benchmark. One "
        "repository (<span class=\"mono\">python-app</span>) nests its source "
        "under a <span class=\"mono\">target/</span> directory; the agent reported "
        "paths without that prefix, which were normalized to align with ground "
        "truth before scoring."
    ),
}

# CWE families surfaced in the "detection by class" panel: (label, cwe display, family slug)
CWE_FAMILIES: list[tuple[str, str, str]] = [
    ("SQL injection",            "CWE-89",      "sql_injection"),
    ("Command / OS injection",   "CWE-77 · 78", "command_injection"),
    ("Insecure deserialization", "CWE-502",     "insecure_deserialization"),
    ("Cross-site scripting",     "CWE-79",      "xss"),
    ("Code injection / RFI",     "CWE-94 · 98", "code_injection"),
]

RULE_SLUGS = {"semgrep", "snyk", "sonarqube"}
SEC_SLUGS = {"kolega-enterprise-v1", "kolega-v0.0.1"}


def round1(x: float) -> float:
    return round(float(x) + 1e-9, 1)


def round3(x: float) -> float:
    return round(float(x) + 1e-12, 3)


def build_scanners(data: dict) -> tuple[list[dict], int]:
    ag = data["aggregates"]
    repos_total = max((a.get("repos_total", 26) for a in ag.values()), default=26)
    out = []
    for slug, meta in SCANNER_META.items():
        a = ag.get(slug)
        if not a:
            continue
        name, cat, ver = meta
        micro, strict = a["micro"], a["strict_micro"]
        cost = a.get("cost", {}).get("total_cost", 0) or 0
        out.append({
            "name": name,
            "slug": slug,
            "cat": cat,
            "ver": ver,
            "url": SCANNER_URLS.get(slug),
            "repos": a.get("repos_scored", repos_total),
            "f2": round1(micro["f2_score"]),
            "f2s": round1(strict["f2_score"]),
            "f3": round1(micro["f3_score"]),
            "f3s": round1(strict["f3_score"]),
            "rec": round3(micro["recall"]),
            "recs": round3(strict["recall"]),
            "prec": round3(micro["precision"]),
            # cost: null for free rule-based tools and the enterprise tier (no published price)
            "cost": None if (cat == "rule" or slug == "kolega-enterprise-v1" or cost <= 0) else round(cost, 2),
            # est: True when cost is a projection rather than metered (rendered as ~$X)
            "est": bool((a.get("cost") or {}).get("estimated")),
            # run-to-run F2 stddev (shown under the score for multi-run scanners)
            "sd": round1(a.get("f2_stddev", 0)) if a.get("num_runs", 1) > 1 else None,
        })
    # rank by strict F3 desc (primary metric on the live dashboard)
    out.sort(key=lambda s: s["f3s"], reverse=True)
    return out, repos_total


def build_cwe(data: dict) -> list[dict]:
    grid = data["grid"]
    # accumulate tp/fn per scanner per family
    acc: dict[str, dict[str, list[int]]] = {}
    for row in grid.values():
        for slug, cell in row.items():
            if not cell:
                continue
            for fam, info in cell.get("per_family", {}).items():
                acc.setdefault(slug, {}).setdefault(fam, [0, 0])
                acc[slug][fam][0] += info.get("tp", 0)
                acc[slug][fam][1] += info.get("fn", 0)
    rows = []
    for label, cwe, fam in CWE_FAMILIES:
        best_llm = best_rule = 0.0
        for slug, fams in acc.items():
            if fam not in fams:
                continue
            tp, fn = fams[fam]
            if tp + fn == 0:
                continue
            r = tp / (tp + fn) * 100
            if slug in RULE_SLUGS:
                best_rule = max(best_rule, r)
            elif slug not in SEC_SLUGS:
                best_llm = max(best_llm, r)
        rows.append({"slug": fam, "label": label, "cwe": cwe, "llm": round(best_llm), "rule": round(best_rule)})
    return rows


def count_ground_truth(gt_dir: Path) -> tuple[int, int, int]:
    """Return (repos, real_vulns, fp_traps) counted from ground-truth.json files."""
    repos = vulns = traps = 0
    for f in sorted(gt_dir.glob("*/ground-truth.json")):
        repos += 1
        gt = json.loads(f.read_text())
        items = gt
        if isinstance(gt, dict):
            for k in ("vulnerabilities", "findings", "entries", "ground_truth"):
                if k in gt:
                    items = gt[k]
                    break
        for it in items:
            if it.get("is_vulnerable", True):
                vulns += 1
            else:
                traps += 1
    return repos, vulns, traps


def dataset_stats(data: dict, scanners: list[dict], repos_total: int) -> dict:
    repos, vulns, traps = count_ground_truth(ROOT / "ground-truth")
    # total Python LOC scanned (constant across runs) — take any aggregate's value
    loc = 0
    for a in data["aggregates"].values():
        loc = a.get("cost", {}).get("total_loc_scanned", 0) or loc
        if loc:
            break
    return {
        "repos": repos or repos_total,
        "vulns": vulns,
        "traps": traps,
        "loc": loc,
        "scanners": len(scanners),
        # number of distinct CWE families with at least one labeled finding
        "families": dataset_family_count(data),
    }


def dataset_family_count(data: dict) -> int:
    fams: set[str] = set()
    for row in data["grid"].values():
        for cell in row.values():
            if cell:
                fams.update(cell.get("per_family", {}).keys())
    return len(fams)


def js_value(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, int):
        return str(v)
    return json.dumps(v)


def emit_data_js(scanners: list[dict], cwe: list[dict], dataset: dict) -> str:
    lines = []
    lines.append("/* ============================================================")
    lines.append("   RealVuln — canonical results data (GENERATED by build_site.py)")
    lines.append("   Source of truth: reports/dashboard.json (dashboard.py output).")
    lines.append("   DO NOT EDIT BY HAND — run `python build_site.py` to regenerate.")
    lines.append("   Ranking metric on the live dashboard: F3 (strict).")
    lines.append("   ============================================================ */")
    lines.append("(function () {")
    lines.append("  var S = [")
    keys = ["name", "slug", "cat", "ver", "url", "repos", "f2", "f2s", "f3", "f3s", "rec", "recs", "prec", "cost", "est", "sd"]
    for s in scanners:
        parts = ", ".join(f"{k}: {js_value(s[k])}" for k in keys)
        lines.append(f"    {{ {parts} }},")
    lines.append("  ];")
    lines.append("")
    lines.append("  var CWE = [")
    for c in cwe:
        lines.append(
            f"    {{ label: {js_value(c['label'])}, cwe: {js_value(c['cwe'])}, "
            f"llm: {c['llm']}, rule: {c['rule']} }},"
        )
    lines.append("  ];")
    lines.append("")
    lines.append("  window.RV = {")
    lines.append("    SCANNERS: S,")
    lines.append("    CWE: CWE,")
    lines.append("    CAT_LABEL: { sec: 'Security-Specialized', llm: 'General-Purpose LLM', rule: 'Rule-Based SAST' },")
    lines.append("    CAT_SHORT: { sec: 'Sec.-spec.', llm: 'GP-LLM', rule: 'Rule SAST' },")
    lines.append("    COL: { sec: '#cfa45c', llm: '#7e9fc4', rule: '#8c8478' },")
    lines.append(
        "    DATASET: { repos: %(repos)d, vulns: %(vulns)d, traps: %(traps)d, "
        "loc: %(loc)d, scanners: %(scanners)d, families: %(families)d }" % dataset
    )
    lines.append("  };")
    lines.append("})();")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(REPORTS / "dashboard.json"))
    ap.add_argument("--no-copy", action="store_true", help="only regenerate realvuln-data.js")
    args = ap.parse_args()

    data = json.loads(Path(args.data).read_text())
    scanners, repos_total = build_scanners(data)
    cwe = build_cwe(data)
    dataset = dataset_stats(data, scanners, repos_total)

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "realvuln-data.js").write_text(emit_data_js(scanners, cwe, dataset))
    print(f"wrote reports/realvuln-data.js  ({len(scanners)} scanners, {len(cwe)} CWE families)")
    print(f"  dataset: {dataset}")

    if args.no_copy:
        return

    # Template tokens substituted into the static HTML so prose figures stay
    # in sync with the real pipeline. Keep keys in sync with {{...}} in site/*.html.
    entries = dataset["vulns"] + dataset["traps"]
    tokens = {
        "{{REPOS}}": f"{dataset['repos']:,}",
        "{{VULNS}}": f"{dataset['vulns']:,}",
        "{{TRAPS}}": f"{dataset['traps']:,}",
        "{{ENTRIES}}": f"{entries:,}",
        "{{LOC}}": f"{dataset['loc']:,}",
        "{{SCANNERS}}": f"{dataset['scanners']:,}",
        "{{FAMILIES}}": f"{dataset['families']:,}",
        "{{TRAP_PCT}}": f"{(dataset['traps'] / entries * 100):.1f}" if entries else "0",
    }
    # per-CWE recall tokens (best LLM vs best rule), keyed by family slug → e.g. {{CWE_SQL_LLM}}
    SLUG_TOKEN = {"sql_injection": "SQL", "insecure_deserialization": "DESER",
                  "xss": "XSS", "command_injection": "CMD", "code_injection": "CODE"}
    for c in cwe:
        tag = SLUG_TOKEN.get(c["slug"])
        if tag:
            tokens[f"{{{{CWE_{tag}_LLM}}}}"] = str(c["llm"])
            tokens[f"{{{{CWE_{tag}_RULE}}}}"] = str(c["rule"])

    # copy static site source into reports/, replacing old dashboard.html
    for src in sorted(SITE_SRC.iterdir()):
        if src.name == "realvuln-data.js":
            continue  # generated above
        if not src.is_file():
            continue
        dst = REPORTS / src.name
        if src.suffix == ".html":
            text = src.read_text()
            for tok, val in tokens.items():
                text = text.replace(tok, val)
            left = [t for t in tokens if t in text]
            if left:
                print(f"  WARNING: unresolved tokens in {src.name}: {left}")
            text = inject_analytics(text)
            dst.write_text(text)
        else:
            shutil.copy2(src, dst)
        print(f"copied {src.name}")

    # reskin-styled per-scanner deep-dive pages (reports/scanners/<slug>.html)
    try:
        import build_detail_pages
        build_detail_pages.main()
    except Exception as e:  # never block the main build on detail-page generation
        print(f"  WARNING: detail-page generation skipped: {e}")

    # sitemap.xml — generated from the pages that actually exist so it never
    # drifts as scanner detail pages are added/removed.
    write_sitemap()


SITE_BASE_URL = "https://realvuln.com"


def write_sitemap() -> None:
    """Emit reports/sitemap.xml covering canonical, linked pages only.

    Restricted to the public nav pages plus the scanner detail pages that are
    actually published (SCANNER_META) — legacy/orphan HTML in reports/ is
    excluded so Google doesn't index stale or unlinked pages.
    """
    today = date.today().isoformat()
    urls: list[tuple[str, str, str]] = []  # (loc, changefreq, priority)

    def add(path: str, changefreq: str, priority: str) -> None:
        loc = SITE_BASE_URL if path == "index.html" else f"{SITE_BASE_URL}/{path}"
        urls.append((loc, changefreq, priority))

    # canonical nav pages, in priority order
    nav_pages = [
        ("index.html", "1.0"),
        ("dashboard.html", "0.9"),
        ("methodology.html", "0.7"),
        ("dataset.html", "0.7"),
        ("findings.html", "0.7"),
        ("roadmap.html", "0.7"),
    ]
    for name, pr in nav_pages:
        if (REPORTS / name).is_file():
            add(name, "weekly", pr)

    # per-scanner deep-dive pages — only those actually published on the site
    for slug in SCANNER_META:
        if (REPORTS / "scanners" / f"{slug}.html").is_file():
            add(f"scanners/{slug}.html", "monthly", "0.5")

    body = "\n".join(
        f"  <url><loc>{loc}</loc><lastmod>{today}</lastmod>"
        f"<changefreq>{cf}</changefreq><priority>{pr}</priority></url>"
        for loc, cf, pr in urls
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}\n</urlset>\n"
    )
    (REPORTS / "sitemap.xml").write_text(xml)
    print(f"wrote reports/sitemap.xml ({len(urls)} urls)")


if __name__ == "__main__":
    main()
