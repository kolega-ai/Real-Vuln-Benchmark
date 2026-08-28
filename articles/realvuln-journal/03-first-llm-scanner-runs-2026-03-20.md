---
title: "First LLM scanner runs: the agentic models enter the leaderboard"
description: "Our first agentic LLM scanner F2 results: Gemini 3.1 Pro and Sonnet 4.6 lead, GLM-5 follows — and what the early data showed."
date: "2026-03-20"
slug: "first-llm-scanner-runs"
author: "Faizan Raza"
tags: ["LLM vulnerability detection", "AI code security", "LLM security scanner", "AI vulnerability scanner", "AI code review"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/first-llm-scanner-runs.html"
og_type: "article"
og_title: "First LLM scanner runs: the agentic models enter the leaderboard — RealVuln Benchmark"
og_description: "Our first agentic LLM scanner F2 results: Gemini 3.1 Pro and Sonnet 4.6 lead, GLM-5 follows — and what the early data showed."
twitter_card: "summary_large_image"
twitter_title: "First LLM scanner runs: the agentic models enter the leaderboard"
twitter_description: "Our first agentic LLM scanner F2 results: Gemini 3.1 Pro and Sonnet 4.6 lead, GLM-5 follows — and what the early data showed."
---

## Why this matters

Claims about AI code security are cheap; measurements are not. This entry records the first time we ran general-purpose models through the same coherent, whole-application Python corpus — with the same false-positive accounting and false-positive traps — as the rule-based SAST tools already on our board. It is the beginning of a proper conversation about LLM vulnerability detection, grounded in accuracy rather than a feature list, and we fully expect others to disagree with parts of it.

## What we did

During the March 2026 campaign — the commits between 2026-03-12 ("Add LLM security scanner benchmark framework with pilot results") and 2026-03-20 — we replaced our earlier OpenHands harness with one built on OpenCode. The new harness tracks real tokens and cost per run, which is a prerequisite for treating any model seriously as an AI vulnerability scanner you might run in production. It also makes the runs genuinely agentic: each model is given the repository and a tool loop, and we score what it actually finds rather than what it claims to be able to find.

Nine models ran the identical corpus and scoring pipeline as the traditional tools. Standard-mode F2 scores:

| Model | F2 |
| --- | --- |
| agentic Haiku | 43.0 |
| Sonnet 4.6 | 59.7 |
| Kimi K2.5 | 51.4 |
| Qwen 3.5 397B | 43.2 |
| Gemini 3.1 Pro | 60.5 |
| Grok 3 | 27.6 |
| Grok 4.20 Reasoning | 28.2 |
| GLM-5 | 54.5 |
| MiniMax M2.7 | 48.4 |

We report F2 here because that is what the campaign commits captured; the leaderboard's headline remains F3, which weights recall more heavily, with F2 and F3 both published in standard and strict modes. We also logged cost per run — Kimi K2.5 came to $1.44 across 72 runs, while Gemini 3.1 Pro ran $27.24 — and shipped two toggles the board had been missing: cost-per-100k-LOC and optimistic-vs-strict scoring. These are pilot results, not final rankings.

## What we observed

Three things. First, LLM and AI vulnerability detection were already competitive with rule-based SAST on this corpus. Several general-purpose models landed in the mid-to-high 50s on F2 — Gemini 3.1 Pro at 60.5 and Sonnet 4.6 at 59.7 effectively tied, with GLM-5 at 54.5 behind them — and a middle tier of Kimi K2.5 (51.4), MiniMax M2.7 (48.4), Qwen 3.5 397B (43.2), and agentic Haiku (43.0) clustered in the 40s. Second, cost varied by more than 10x across models that were otherwise comparable in accuracy — a number that matters as much as the score if you plan to run AI code review at any real scale. Third, the spread from 27.6 to 60.5 is wide enough to show that "just use an LLM" is not a strategy; the model and the harness both matter.

## Why we think that happened

The competitive scores likely reflect how far general-purpose models have come at reasoning over code. Grounded in a repository, an LLM security scanner can catch patterns a hand-written rule misses, and F2 rewards that recall even when precision is imperfect. The cost spread is easier to explain: token counts, reasoning overhead, and per-token pricing differ sharply across providers.

We are less sure about the low end. The two Grok runs scored 27.6 and 28.2, and we cannot yet say whether that is instruction-following, harness friction, or corpus fit. One more explicit caveat: these are F2 numbers in standard mode; strict mode and the F3 headline will reward or penalize models differently, and we expect some rankings to move once those are published. We will not over-read a small, single-language, Python-only corpus — these numbers are early, not final.

## What's next

The roadmap is to widen the corpus beyond Python, re-run the models sitting at the edges, and publish cost-per-100k-LOC across the full board. Whether these early rankings hold is the open question.


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [Introducing the RealVuln benchmark framework](https://realvuln.com/journal/introducing-the-benchmark.html) · **Next:** [Reproducible by design: prompt versioning and the manifest](https://realvuln.com/journal/reproducible-by-design.html)

*This is issue 03 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*