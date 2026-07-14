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
import re
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
    "kolega-devsec-max-v0.0.1": (
        "Kolega DevSec Max V0.0.1",
        "sec",
        "Kolega DevSec Platform",
    ),
    "kolega-devsec-core-v0.0.1": (
        "Kolega DevSec Core V0.0.1",
        "sec",
        "Kolega DevSec Platform",
    ),
    "kolega-claude-adaptation": (
        "Kolega Scan OSS - V2 - 3 Model",
        "sec",
        "Kolega Scan OSS",
    ),
    "kolega-claude-adaptation-deepseek-only": (
        "Kolega Scan OSS - V1 - 2 Model",
        "sec",
        "Kolega Scan OSS",
    ),
    "kolega-original-claude-adaptation-deepseek-v4-pro": (
        "Anthropic Method (DeepSeek V4 Pro)",
        "sec",
        "Bespoke Adaptation",
    ),
    "kolega-ca-cc-sonnet": (
        "Anthropic Method - Sonnet 4.6",
        "sec",
        "Claude Code",
    ),
    "gpt-5.5-agentic-v1": ("GPT-5.5", "llm", "agentic-v1"),
    "glm-5.2-agentic-v1": ("GLM-5.2", "llm", "agentic-v1"),
    "glm-5.1-agentic-v1": ("GLM-5.1", "llm", "agentic-v1"),
    "glm-5-agentic-v1": ("GLM-5", "llm", "agentic-v1"),
    "deepseek-v4-flash-agentic-v1": ("DeepSeek V4 Flash", "llm", "agentic-v1"),
    "deepseek-v4-pro-agentic-v1": ("DeepSeek V4 Pro", "llm", "agentic-v1"),
    "kimi-k2.7-agentic-v1": ("Kimi K2.7", "llm", "agentic-v1"),
    "kimi-k2.6-agentic-v1": ("Kimi K2.6", "llm", "agentic-v1"),
    "kimi-k2.5-agentic-v1": ("Kimi K2.5", "llm", "agentic-v1"),
    "claude-fable-5-cc-v1": ("Claude Fable 5", "llm", "claude-code-v1"),
    "claude-opus-4-8-agentic-v1": ("Claude Opus 4.8", "llm", "agentic-v1"),
    "claude-opus-4-7-agentic-v1": ("Claude Opus 4.7", "llm", "agentic-v1"),
    "claude-opus-4-6-agentic-v1": ("Claude Opus 4.6", "llm", "agentic-v1"),
    "claude-sonnet-4-6-agentic-v1": ("Claude Sonnet 4.6", "llm", "agentic-v1"),
    "claude-haiku-4-5-agentic-v1": ("Claude Haiku 4.5", "llm", "agentic-v1"),
    "claude-haiku-4-5-v1": ("Claude Haiku 4.5", "llm", "direct-v1"),
    "gemini-3.1-pro-agentic-v1": ("Gemini 3.1 Pro", "llm", "agentic-v1"),
    "gemini-3.5-flash-agentic-v1": ("Gemini 3.5 Flash", "llm", "agentic-v1"),
    "grok-4.20-reasoning-agentic-v1": ("Grok 4.20 Reasoning", "llm", "agentic-v1"),
    "grok-3-agentic-v1": ("Grok 3", "llm", "agentic-v1"),
    "minimax-m2.7-agentic-v1": ("Minimax M2.7", "llm", "agentic-v1"),
    "qwen-3.5-397b-agentic-v1": ("Qwen 3.5 397B", "llm", "agentic-v1"),
    "qwen3.6-35b-agentic-v1": ("Qwen 3.6 35B", "llm", "agentic-v1"),
    "gemma4-31b-agentic-v1": ("Gemma 4 31B", "llm", "agentic-v1"),
    "ornith-q3-agentic-v1": ("Ornith 1.0 35B", "llm", "agentic-v1"),
    "semgrep": ("Semgrep", "rule", "rule-based"),
    "snyk": ("Snyk Code", "rule", "pattern+flow"),
    "sonarqube": ("SonarQube", "rule", "community"),
}

# Model / product page per scanner, rendered as an explicit external link on the
# leaderboard tag line. LLM entries point at the provider's own page for the
# model (or the provider site where none exists); rule-based tools at their
# product page.
SCANNER_URLS: dict[str, str] = {
    "kolega-devsec-max-v0.0.1": "https://kolega.dev/",
    "kolega-devsec-core-v0.0.1": "https://kolega.dev/",
    "kolega-claude-adaptation": "https://kolega.dev/",
    "kolega-claude-adaptation-deepseek-only": "https://kolega.dev/",
    "kolega-original-claude-adaptation-deepseek-v4-pro": "https://claude.com/blog/using-llms-to-secure-source-code",
    "kolega-ca-cc-sonnet": "https://claude.com/blog/using-llms-to-secure-source-code",
    "gpt-5.5-agentic-v1": "https://openai.com/index/introducing-gpt-5-5/",
    "glm-5.2-agentic-v1": "https://docs.z.ai/guides/llm/glm-5.2",
    "glm-5.1-agentic-v1": "https://docs.z.ai/guides/llm/glm-5.1",
    "glm-5-agentic-v1": "https://docs.z.ai/guides/llm/glm-5",
    "deepseek-v4-flash-agentic-v1": "https://www.deepseek.com",
    "deepseek-v4-pro-agentic-v1": "https://www.deepseek.com",
    "kimi-k2.7-agentic-v1": "https://www.moonshot.ai",
    "kimi-k2.6-agentic-v1": "https://www.moonshot.ai",
    "kimi-k2.5-agentic-v1": "https://www.moonshot.ai",
    "claude-fable-5-cc-v1": "https://www.anthropic.com/news/claude-fable-5-mythos-5",
    "claude-opus-4-8-agentic-v1": "https://www.anthropic.com/claude/opus",
    "claude-opus-4-7-agentic-v1": "https://www.anthropic.com/claude/opus",
    "claude-opus-4-6-agentic-v1": "https://www.anthropic.com/claude/opus",
    "claude-sonnet-4-6-agentic-v1": "https://www.anthropic.com/claude/sonnet",
    "claude-haiku-4-5-agentic-v1": "https://www.anthropic.com/claude/haiku",
    "claude-haiku-4-5-v1": "https://www.anthropic.com/claude/haiku",
    "gemini-3.1-pro-agentic-v1": "https://deepmind.google/models/gemini/pro/",
    "gemini-3.5-flash-agentic-v1": "https://deepmind.google/models/gemini/flash/",
    "grok-4.20-reasoning-agentic-v1": "https://docs.x.ai/developers/models/grok-4.20",
    "grok-3-agentic-v1": "https://x.ai/news/grok-3",
    "minimax-m2.7-agentic-v1": "https://www.minimax.io/models/text/m27",
    "qwen-3.5-397b-agentic-v1": "https://qwen.ai/blog?id=qwen3.5",
    "qwen3.6-35b-agentic-v1": "https://qwen.ai/",
    "gemma4-31b-agentic-v1": "https://ai.google.dev/gemma",
    "ornith-q3-agentic-v1": "https://huggingface.co/OrnithAI",
    "semgrep": "https://semgrep.dev/products/semgrep-code",
    "snyk": "https://snyk.io/product/snyk-code/",
    "sonarqube": "https://www.sonarsource.com/products/sonarqube/",
}

# Provider display name per scanner, shown with a link (SCANNER_URLS) on the
# deep-dive pages.
SCANNER_PROVIDERS: dict[str, str] = {
    "kolega-devsec-max-v0.0.1": "Kolega DevSec Platform",
    "kolega-devsec-core-v0.0.1": "Kolega DevSec Platform",
    "kolega-claude-adaptation": "Kolega Scan OSS",
    "kolega-claude-adaptation-deepseek-only": "Kolega Scan OSS",
    "kolega-original-claude-adaptation-deepseek-v4-pro": "Kolega Scan OSS",
    "kolega-ca-cc-sonnet": "Kolega Scan OSS",
    "gpt-5.5-agentic-v1": "OpenAI",
    "glm-5.2-agentic-v1": "Z.ai",
    "glm-5.1-agentic-v1": "Z.ai",
    "glm-5-agentic-v1": "Z.ai",
    "deepseek-v4-flash-agentic-v1": "DeepSeek",
    "deepseek-v4-pro-agentic-v1": "DeepSeek",
    "kimi-k2.7-agentic-v1": "Moonshot AI",
    "kimi-k2.6-agentic-v1": "Moonshot AI",
    "kimi-k2.5-agentic-v1": "Moonshot AI",
    "claude-fable-5-cc-v1": "Anthropic",
    "claude-opus-4-8-agentic-v1": "Anthropic",
    "claude-opus-4-7-agentic-v1": "Anthropic",
    "claude-opus-4-6-agentic-v1": "Anthropic",
    "claude-sonnet-4-6-agentic-v1": "Anthropic",
    "claude-haiku-4-5-agentic-v1": "Anthropic",
    "claude-haiku-4-5-v1": "Anthropic",
    "gemini-3.1-pro-agentic-v1": "Google DeepMind",
    "gemini-3.5-flash-agentic-v1": "Google DeepMind",
    "grok-4.20-reasoning-agentic-v1": "xAI",
    "grok-3-agentic-v1": "xAI",
    "minimax-m2.7-agentic-v1": "MiniMax",
    "qwen-3.5-397b-agentic-v1": "Alibaba Qwen",
    "qwen3.6-35b-agentic-v1": "Alibaba Qwen",
    "gemma4-31b-agentic-v1": "Google",
    "ornith-q3-agentic-v1": "OrnithAI",
    "semgrep": "Semgrep",
    "snyk": "Snyk",
    "sonarqube": "SonarSource",
}

# Optional per-scanner methodology notes, rendered as a callout on the deep-dive
# page. Use for scanners whose run conditions differ from the standard agentic
# (OpenCode) harness, so the difference is transparent rather than implicit in
# the version label. HTML allowed.
SCANNER_NOTES: dict[str, str] = {
    "ornith-q3-agentic-v1": (
        "<strong>Locally hosted; template fix.</strong> Open-weight GGUF (Q4_K_M) via "
        "Ollama through the standard agentic-v1 harness. Ornith's shipped GGUF template was "
        "replaced with the canonical Qwen3 template for tool calling. Completed 58/66. Cost $0."
    ),
    "qwen3.6-35b-agentic-v1": (
        "<strong>Locally hosted.</strong> Open-weight GGUF (Q4_K_M) via Ollama on one "
        "RTX PRO 6000, standard agentic-v1 harness. Cost $0 (self-hosted)."
    ),
    "gemma4-31b-agentic-v1": (
        "<strong>Locally hosted.</strong> Open-weight GGUF (Q4_K_M) via Ollama, standard "
        "agentic-v1 harness. Cost $0 (self-hosted)."
    ),
    "claude-fable-5-cc-v1": (
        "<strong>Different harness.</strong> Every other LLM scanner here runs "
        'agentically through the <span class="mono">OpenCode</span> CLI '
        '(version label <span class="mono">agentic-v1</span>). Fable 5 could '
        "not be benchmarked that way: the OpenCode→Anthropic API path was "
        "consistently blocked by provider content filtering on the "
        "intentionally-vulnerable source, returning refusals instead of findings. "
        "<br><br>"
        "Instead, each of the 26 repositories was scanned by a dedicated "
        '<span class="mono">Claude Code</span> subagent (version label '
        '<span class="mono">claude-code-v1</span>) using the <em>identical</em> '
        "system prompt as the agentic runner (prompt hash "
        '<span class="mono">sha256:14ccb06a286c</span>), so findings remain '
        "comparable. The same prompt ran cleanly through Claude Code, which "
        "confirms the block was specific to the OpenCode delivery path — not "
        "the prompt or the model. "
        "<br><br>"
        "<strong>Caveats.</strong> These runs were interactive rather than "
        "metered, so token and latency figures were not recorded. The cost shown "
        "is an <em>estimate</em>: Fable 5's API price is exactly 2× Claude Opus "
        "4.8 ($10/$50 vs $5/$25 per 1M input/output tokens), so we project its "
        "cost as 2× Opus 4.8's measured cost on the same benchmark. One "
        'repository (<span class="mono">python-app</span>) nests its source '
        'under a <span class="mono">target/</span> directory; the agent reported '
        "paths without that prefix, which were normalized to align with ground "
        "truth before scoring."
    ),
}

# CWE families surfaced in the "detection by class" panel: (label, cwe display, family slug)
CWE_FAMILIES: list[tuple[str, str, str]] = [
    ("SQL injection", "CWE-89", "sql_injection"),
    ("Command / OS injection", "CWE-77 · 78", "command_injection"),
    ("Insecure deserialization", "CWE-502", "insecure_deserialization"),
    ("Cross-site scripting", "CWE-79", "xss"),
    ("Code injection / RFI", "CWE-94 · 98", "code_injection"),
]

RULE_SLUGS = {"semgrep", "snyk", "sonarqube"}
SEC_SLUGS = {
    "kolega-devsec-max-v0.0.1",
    "kolega-devsec-core-v0.0.1",
}


def round1(x: float) -> float:
    return round(float(x) + 1e-9, 1)


def round3(x: float) -> float:
    return round(float(x) + 1e-12, 3)


# A scanner must cover at least this share of a tab's repo set for its score to
# appear on that tab at all. Deliberately loose — agentic scanners legitimately
# fail on some repos mid-run (18/26 or ~50/66 still counts as a full attempt);
# what it excludes is runs that never attempted the bulk of the corpus.
COVERAGE_THRESHOLD = 0.69


def scanners_from_aggregates(ag: dict, repos_total: int) -> list[dict]:
    out = []
    # total Python LOC of the whole corpus — used to price fixed-rate products per vuln
    _, _, _, corpus_loc = count_ground_truth(ROOT / "ground-truth")
    for slug, meta in SCANNER_META.items():
        a = ag.get(slug)
        if not a or not a.get("repos_scored", 0):
            continue
        name, cat, ver = meta
        micro, strict = a["micro"], a["strict_micro"]
        cost_per_100k = (a.get("cost", {}).get("cost_per_100_loc", 0) or 0) * 1000
        COST_OVERRIDES = {
            "kolega-devsec-core-v0.0.1": 5.69,
            "kolega-devsec-max-v0.0.1": 2.37,
        }
        if slug in COST_OVERRIDES:
            cost_val = COST_OVERRIDES[slug]
            cost_est = False
        elif cat == "rule" or cost_per_100k <= 0:
            cost_val = None
            cost_est = False
        else:
            cost_val = round(cost_per_100k)
            cost_est = bool((a.get("cost") or {}).get("estimated"))
        total_cost = a.get("cost", {}).get("total_cost", 0) or 0
        tp = micro.get("tp", 0) or 0
        if slug in COST_OVERRIDES and COST_OVERRIDES[slug] == 0:
            cpv_val = 0.0
        elif slug in COST_OVERRIDES and COST_OVERRIDES[slug] > 0 and tp > 0:
            # LOC this scanner covered; fall back to corpus LOC scaled by repo coverage
            loc_cov = a.get("cost", {}).get("total_loc_scanned", 0) or 0
            if loc_cov <= 0:
                repos_cov = a.get("repos_scored", repos_total)
                loc_cov = (
                    corpus_loc * (repos_cov / repos_total)
                    if repos_total
                    else corpus_loc
                )
            cpv_val = round(COST_OVERRIDES[slug] / 100000 * loc_cov / tp * 100, 2)
        elif cat == "rule" or total_cost <= 0 or tp <= 0:
            cpv_val = None
        else:
            cpv_val = round(total_cost / tp * 100, 2)
        out.append(
            {
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
                # tp: real vulnerabilities found (true positives, micro)
                "tp": micro.get("tp", 0) or 0,
                # fp: false positives (flagged but not a real vuln, micro)
                "fp": micro.get("fp", 0) or 0,
                "prec": round3(micro["precision"]),
                # cost: per-100k-LOC spend; 0 = Free, null = no published price, else fixed/metered $
                "cost": cost_val,
                # cpv: cost per 100 vulnerabilities found (TP); 0 = Free, null = n/a
                "cpv": cpv_val,
                # est: True when cost is a projection rather than metered (rendered as ~$X)
                "est": cost_est,
                # run-to-run F2 stddev (shown under the score for multi-run scanners)
                "sd": (
                    round1(a.get("f2_stddev", 0)) if a.get("num_runs", 1) > 1 else None
                ),
                # partial: covered fewer than COVERAGE_THRESHOLD of this tab's repos —
                # score is not comparable, rendered unranked below the leaderboard
                "partial": (
                    a.get("repos_scored", repos_total)
                    < COVERAGE_THRESHOLD * repos_total
                ),
            }
        )
    # entries below the coverage threshold are dropped from this tab entirely —
    # they still appear on any tab whose repo set they did cover
    out = [s for s in out if not s.pop("partial")]
    # rank by strict F3 desc (primary metric on the live dashboard)
    out.sort(key=lambda s: -s["f3s"])
    return out


def build_scanners(data: dict) -> tuple[list[dict], int]:
    ag = data["aggregates"]
    repos_total = max((a.get("repos_total", 26) for a in ag.values()), default=26)
    return scanners_from_aggregates(ag, repos_total), repos_total


def build_tab_datasets(
    data: dict, all_scanners: list[dict], repos_total: int
) -> tuple[dict, dict]:
    """Build leaderboard datasets for the All / Intentional / Vibe tabs.

    'intentional' = the 26 hand-labeled realvuln-* apps; 'vibe' = the 40
    vc-*-seeded-v2 apps. Source split comes from dashboard.json source_aggregates.
    """
    src_ag = data.get("source_aggregates", {}) or {}
    src_repos = data.get("source_repos", {}) or {}
    tabs = {"all": all_scanners}
    totals = {"all": repos_total}
    for key in ("intentional", "vibe"):
        if key in src_ag:
            n = len(src_repos.get(key, [])) or repos_total
            tabs[key] = scanners_from_aggregates(src_ag[key], n)
            totals[key] = n
    return tabs, totals


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
        rows.append(
            {
                "slug": fam,
                "label": label,
                "cwe": cwe,
                "llm": round(best_llm),
                "rule": round(best_rule),
            }
        )
    return rows


def framework_distribution(gt_dir: Path) -> list[tuple[str, int]]:
    """(display_name, repo_count) per framework, from ground-truth, count desc."""
    from collections import Counter

    DISPLAY = {
        "flask": "Flask",
        "django": "Django",
        "fastapi": "FastAPI",
        "aiohttp": "aiohttp",
        "tornado": "Tornado",
        "none": "custom",
    }
    counts: Counter = Counter()
    for f in sorted(gt_dir.glob("*/ground-truth.json")):
        gt = json.loads(f.read_text())
        fw = (gt.get("framework") if isinstance(gt, dict) else None) or "none"
        counts[fw] += 1
    return [(DISPLAY.get(k, k), v) for k, v in counts.most_common()]


def bar_rows(items: list[tuple[str, int]], color: str | None = None) -> str:
    """Render .fw-row bars (name · proportional fill · count). Matches the
    static markup so one generated block drops into both dashboard and dataset."""
    mx = max((c for _, c in items), default=1) or 1
    bg = f";background:{color}" if color else ""
    rows = []
    for name, c in items:
        w = round(c / mx * 100)
        rows.append(
            f'<div class="fw-row"><span class="fwn">{name}</span>'
            f'<span class="fwt"><span class="fwf" style="width:{w}%{bg}"></span></span>'
            f'<span class="fwc">{c}</span></div>'
        )
    return "\n              ".join(rows)


def per_tier_bests(scanners: list[dict]) -> dict:
    """Best/extreme figures per scanner category, ranked by strict F3 (the live
    dashboard's primary metric). Returns token dict."""
    CAT_COLOR = {
        "llm": "var(--tier-llm)",
        "rule": "var(--tier-rule)",
        "sec": "var(--accent)",
    }
    CAT_LABEL = {"llm": "GP-LLM", "rule": "Rule SAST", "sec": "Sec.-spec."}
    by_cat: dict[str, list[dict]] = {"sec": [], "llm": [], "rule": []}
    # prose tokens compare fully-covered scanners only; fall back to partial
    # rows when a whole category never covered the current corpus
    for s in scanners:
        if not s.get("partial"):
            by_cat.setdefault(s["cat"], []).append(s)
    for s in scanners:
        if s.get("partial") and not by_cat.get(s["cat"]):
            by_cat.setdefault(s["cat"], []).append(s)
    tok: dict = {}
    for cat in CAT_LABEL:
        grp = by_cat.get(cat, [])
        tok[f"CAT_{cat.upper()}"] = len(grp)
        if grp:
            best = max(grp, key=lambda s: s["f3s"])
            tok[f"BEST_{cat.upper()}_F3"] = f"{best['f3s']:.1f}"
            tok[f"BEST_{cat.upper()}_NAME"] = best["name"]
            tok[f"BEST_{cat.upper()}_REC"] = f"{best['recs']:.2f}"
            tok[f"BEST_{cat.upper()}_MIN"] = f"{min(s['f3s'] for s in grp):.1f}"
    # category bars (ordered llm, rule, sec — as on the dashboard)
    rows = []
    for cat in ("llm", "rule", "sec"):
        grp = by_cat.get(cat, [])
        rows.append((CAT_LABEL[cat], len(grp)))
    mx = max((c for _, c in rows), default=1) or 1
    bars = []
    for cat, (lab, c) in zip(("llm", "rule", "sec"), rows):
        w = round(c / mx * 100)
        bars.append(
            f'<div class="fw-row"><span class="fwn">{lab}</span>'
            f'<span class="fwt"><span class="fwf" style="width:{w}%;background:{CAT_COLOR[cat]}"></span></span>'
            f'<span class="fwc">{c}</span></div>'
        )
    tok["CATEGORY_BARS"] = "\n              ".join(bars)
    # tier gaps (best Sec F3 over best LLM / best rule), for findings prose
    try:
        sec, llm, rule = (
            float(tok["BEST_SEC_F3"]),
            float(tok["BEST_LLM_F3"]),
            float(tok["BEST_RULE_F3"]),
        )
        tok["SEC_LLM_GAP"] = f"{sec - llm:.1f}"
        tok["SEC_RULE_GAP"] = f"{sec - rule:.1f}"
    except (KeyError, ValueError):
        pass
    return tok


def repo_table_rows(gt_dir: Path) -> str:
    """<tr> rows for the dataset repo table — name, framework pill, vuln/trap
    counts — straight from ground truth, sorted by vulnerability count desc."""
    FW = {"none": "custom"}
    repos = []
    for f in sorted(gt_dir.glob("*/ground-truth.json")):
        gt = json.loads(f.read_text())
        items = gt.get("findings", gt) if isinstance(gt, dict) else gt
        vulns = sum(1 for it in items if it.get("is_vulnerable", True))
        traps = sum(1 for it in items if not it.get("is_vulnerable", True))
        name = (gt.get("repo_id") if isinstance(gt, dict) else None) or f.parent.name
        name = name.replace("realvuln-", "")
        fw = (gt.get("framework") if isinstance(gt, dict) else None) or "none"
        repos.append((name, FW.get(fw, fw), vulns, traps))
    repos.sort(key=lambda r: r[2], reverse=True)
    return "\n          ".join(
        f'<tr><td class="repo-id">{n}</td><td><span class="fw-pill">{fw}</span></td>'
        f'<td class="r">{v}</td><td class="r">{t}</td></tr>'
        for n, fw, v, t in repos
    )


def count_ground_truth(gt_dir: Path) -> tuple[int, int, int, int]:
    """Return (repos, real_vulns, fp_traps, total_loc) counted from ground-truth.json files."""
    repos = vulns = traps = loc = 0
    for f in sorted(gt_dir.glob("*/ground-truth.json")):
        repos += 1
        gt = json.loads(f.read_text())
        if isinstance(gt, dict):
            loc += gt.get("loc") or 0
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
    return repos, vulns, traps, loc


def dataset_stats(data: dict, scanners: list[dict], repos_total: int) -> dict:
    # total Python LOC across every benchmark repo (summed from ground truth)
    repos, vulns, traps, loc = count_ground_truth(ROOT / "ground-truth")
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


def emit_scanner_array(scanners: list[dict], keys: list[str]) -> str:
    rows = []
    for s in scanners:
        parts = ", ".join(f"{k}: {js_value(s.get(k))}" for k in keys)
        rows.append(f"      {{ {parts} }},")
    return "[\n" + "\n".join(rows) + "\n    ]"


def emit_data_js(
    scanners: list[dict],
    cwe: list[dict],
    dataset: dict,
    tabs: dict | None = None,
    tab_totals: dict | None = None,
) -> str:
    lines = []
    lines.append("/* ============================================================")
    lines.append("   RealVuln — canonical results data (GENERATED by build_site.py)")
    lines.append("   Source of truth: reports/dashboard.json (dashboard.py output).")
    lines.append("   DO NOT EDIT BY HAND — run `python build_site.py` to regenerate.")
    lines.append("   Ranking metric on the live dashboard: F3 (strict).")
    lines.append("   ============================================================ */")
    lines.append("(function () {")
    lines.append("  var S = [")
    keys = [
        "name",
        "slug",
        "cat",
        "ver",
        "url",
        "repos",
        "f2",
        "f2s",
        "f3",
        "f3s",
        "rec",
        "recs",
        "tp",
        "fp",
        "prec",
        "cost",
        "cpv",
        "est",
        "sd",
    ]
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
    # Per-tab leaderboard datasets: all (66) / intentional (26) / vibe (40)
    if tabs:
        keys = [
            "name",
            "slug",
            "cat",
            "ver",
            "url",
            "repos",
            "f2",
            "f2s",
            "f3",
            "f3s",
            "rec",
            "recs",
            "tp",
            "fp",
            "prec",
            "cost",
            "cpv",
            "est",
            "sd",
        ]
        lines.append("    SCANNERS_BY_TAB: {")
        for tk in ("all", "intentional", "vibe"):
            if tk in tabs:
                lines.append(f"      {tk}: {emit_scanner_array(tabs[tk], keys)},")
        lines.append("    },")
        lines.append("    TAB_TOTALS: " + json.dumps(tab_totals or {}) + ",")
        lines.append(
            "    TAB_LABELS: { all: 'All', intentional: 'Human Authored', vibe: 'Vibe Coded' },"
        )
    lines.append("    CWE: CWE,")
    lines.append(
        "    CAT_LABEL: { sec: 'Security-Specialized', llm: 'General-Purpose LLM', rule: 'Rule-Based SAST' },"
    )
    lines.append(
        "    CAT_SHORT: { sec: 'Sec.-spec.', llm: 'GP-LLM', rule: 'Rule SAST' },"
    )
    lines.append("    COL: { sec: '#cfa45c', llm: '#7e9fc4', rule: '#8c8478' },")
    lines.append(
        "    DATASET: { repos: %(repos)d, vulns: %(vulns)d, traps: %(traps)d, "
        "loc: %(loc)d, scanners: %(scanners)d, families: %(families)d }" % dataset
    )
    lines.append("  };")
    lines.append("})();")
    lines.append("")
    return "\n".join(lines)


def warn_unfrozen_overwrite() -> None:
    """Warn (don't block) if the site currently in reports/ reflects a release
    that was never frozen under reports/v/. Rebuilding the root overwrites it,
    so an unfrozen version would be lost. Freeze it first with release.py."""
    live = REPORTS / "dashboard.json"
    versions = REPORTS / "versions.json"
    if not live.is_file():
        return
    try:
        cur_ver = json.loads(live.read_text()).get("benchmark_version")
    except Exception:
        return
    if not cur_ver:
        return
    frozen = set()
    if versions.is_file():
        try:
            frozen = {
                v["version"]
                for v in json.loads(versions.read_text()).get("versions", [])
            }
        except Exception:
            pass
    if cur_ver not in frozen:
        print(
            f"  WARNING: reports/ currently holds v{cur_ver}, which is NOT frozen "
            f"under reports/v/. Rebuilding overwrites it. If v{cur_ver} was published, "
            f"freeze it first:  python release.py {cur_ver}"
        )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(REPORTS / "dashboard.json"))
    ap.add_argument(
        "--no-copy", action="store_true", help="only regenerate realvuln-data.js"
    )
    args = ap.parse_args()

    data = json.loads(Path(args.data).read_text())
    scanners, repos_total = build_scanners(data)
    tabs, tab_totals = build_tab_datasets(data, scanners, repos_total)
    cwe = build_cwe(data)
    dataset = dataset_stats(data, scanners, repos_total)

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "realvuln-data.js").write_text(
        emit_data_js(scanners, cwe, dataset, tabs, tab_totals)
    )
    print(
        f"wrote reports/realvuln-data.js  ({len(scanners)} scanners, {len(cwe)} CWE families)"
    )
    print(f"  dataset: {dataset}")

    if args.no_copy:
        return

    # Template tokens substituted into the static HTML so prose figures stay
    # in sync with the real pipeline. Keep keys in sync with {{...}} in site/*.html.
    entries = dataset["vulns"] + dataset["traps"]
    # benchmark version (e.g. "2.0") shown in the brand; the version switcher
    # (versions.js) upgrades this static label into a dropdown at runtime.
    bench_ver = str(data.get("benchmark_version", "") or "")
    ver_short = ".".join(bench_ver.split(".")[:2]) if bench_ver else "1.0"
    # release date as "Month YYYY" for footers/masthead — prefer the manifest's
    # release_date, fall back to the dashboard build time
    rel_raw = ""
    mani = ROOT / "benchmark-manifest.json"
    if mani.is_file():
        rel_raw = json.loads(mani.read_text()).get("release_date") or ""
    rel_raw = rel_raw or str(data.get("generated_at", ""))
    try:
        rel_date = date.fromisoformat(rel_raw[:10]).strftime("%B %Y")
    except ValueError:
        rel_date = "2026"
    tokens = {
        "{{VERSION}}": ver_short,
        "{{RELEASE_DATE}}": rel_date,
        "{{REPOS}}": f"{dataset['repos']:,}",
        "{{VULNS}}": f"{dataset['vulns']:,}",
        "{{TRAPS}}": f"{dataset['traps']:,}",
        "{{ENTRIES}}": f"{entries:,}",
        "{{LOC}}": f"{dataset['loc']:,}",
        "{{SCANNERS}}": f"{dataset['scanners']:,}",
        "{{FAMILIES}}": f"{dataset['families']:,}",
        "{{TRAP_PCT}}": f"{(dataset['traps'] / entries * 100):.1f}" if entries else "0",
        "{{VULN_PCT}}": f"{(dataset['vulns'] / entries * 100):.1f}" if entries else "0",
    }
    # framework distribution + scanner-category bars/counts + per-tier bests,
    # all computed from live data so prose & panels never drift from the dataset
    fw_dist = framework_distribution(ROOT / "ground-truth")
    tokens["{{FW_COUNT}}"] = str(len(fw_dist))
    tokens["{{FRAMEWORK_BARS}}"] = bar_rows(fw_dist)
    # authorship split (human vs LLM-generated/vibe-coded), from ground truth
    from collections import Counter as _C

    auth = _C()
    for gf in sorted((ROOT / "ground-truth").glob("*/ground-truth.json")):
        gd = json.loads(gf.read_text())
        auth[(gd.get("authorship") if isinstance(gd, dict) else None) or "unknown"] += 1
    human = auth.get("human_authored", 0)
    llm = auth.get("llm_generated", 0)
    tot = sum(auth.values()) or 1
    tokens["{{HUMAN_REPOS}}"] = str(human)
    tokens["{{LLM_REPOS}}"] = str(llm)
    tokens["{{HUMAN_PCT}}"] = f"{human / tot * 100:.0f}"
    tokens["{{LLM_PCT}}"] = f"{llm / tot * 100:.0f}"
    tokens["{{REPO_TABLE_ROWS}}"] = repo_table_rows(ROOT / "ground-truth")
    for k, v in per_tier_bests(scanners).items():
        tokens[f"{{{{{k}}}}}"] = str(v)

    # per-CWE recall tokens (best LLM vs best rule), keyed by family slug → e.g. {{CWE_SQL_LLM}}
    SLUG_TOKEN = {
        "sql_injection": "SQL",
        "insecure_deserialization": "DESER",
        "xss": "XSS",
        "command_injection": "CMD",
        "code_injection": "CODE",
    }
    for c in cwe:
        tag = SLUG_TOKEN.get(c["slug"])
        if tag:
            tokens[f"{{{{CWE_{tag}_LLM}}}}"] = str(c["llm"])
            tokens[f"{{{{CWE_{tag}_RULE}}}}"] = str(c["rule"])

    # cache-busting version derived from the data build time, so a regen forces
    # browsers (and dev servers like Live Server) to reload the generated assets
    cb_ver = re.sub(r"\D", "", str(data.get("generated_at", "")))[:14] or "1"

    def bust(text: str) -> str:
        # append ?v=<ver> to local generated JS/CSS refs (skip absolute URLs)
        return re.sub(
            r'(src|href)="(?!https?:)([^"?]+\.(?:js|css))"',
            lambda m: f'{m.group(1)}="{m.group(2)}?v={cb_ver}"',
            text,
        )

    warn_unfrozen_overwrite()

    # copy static site source into reports/, replacing old dashboard.html
    for src in sorted(SITE_SRC.iterdir()):
        if src.name == "realvuln-data.js":
            continue  # generated above
        if src.is_dir():
            # static asset directories (e.g. site/assets — the paper PDF) copied verbatim
            shutil.copytree(src, REPORTS / src.name, dirs_exist_ok=True)
            print(f"copied {src.name}/")
            continue
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
            text = bust(text)
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
