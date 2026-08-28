---
title: "Scaling the roster: Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5 and DeepSeek-V4"
description: "RealVuln adds a wave of frontier LLM scanners — Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5, DeepSeek-V4 — and what the expanding field shows."
date: "2026-04-30"
slug: "scaling-the-scanner-roster"
author: "Faizan Raza"
tags: ["AI vulnerability scanner", "LLM vulnerability detection", "code security scanner", "static analysis tools", "AI code security"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/scaling-the-scanner-roster.html"
og_type: "article"
og_title: "Scaling the roster: Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5 and DeepSeek-V4 — RealVuln Benchmark"
og_description: "RealVuln adds a wave of frontier LLM scanners — Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5, DeepSeek-V4 — and what the expanding field shows."
twitter_card: "summary_large_image"
twitter_title: "Scaling the roster: Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5 and DeepSeek-V4"
twitter_description: "RealVuln adds a wave of frontier LLM scanners — Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5, DeepSeek-V4 — and what the expanding field shows."
---

## Why this matters

A three-scanner benchmark can only ever tell you how three scanners compare. The question people actually ask about AI code security is not "which tool wins" but "which *kind* of scanner should I trust for my codebase" — and answering that takes a roster broad enough to be a cross-section of the field, not a handful of models.

## What we did

This month we added five frontier LLMs to the roster. On 2026-04-21 we merged `feat: add opus-4-7, glm-5.1, and kimi-k2.6 agentic scanners`; on 2026-04-30 we merged `feat: add gpt-5.5 and deepseek-v4 (flash + pro) agentic scanners`. Each runs through the same agentic harness as every other scanner — the same pinned, coherent whole-application repositories, the same hand-labeled findings, the same false-positive traps, and the same F3/F2 scoring in standard and strict modes, with F3 the headline because it weights recall nine times over precision. We are deliberately holding these five out of the published tables for now: the runs are fresh, and we want a full re-run at pinned versions before any number carries the benchmark's name.

One quieter commit on 04-21 is worth noting for the record — a chore to gitignore private and runtime artifacts. Running dozens of third-party scanners means API keys and local state live on our machines, and we would rather document that mundane hygiene work than pretend it is not part of operating a benchmark.

## What we observed

The interesting thing about adding five scanners at once is what it does to the *shape* of the field. The roster now spans three families — rule-based static analysis tools, general-purpose LLMs used as code security scanners, and security-specialized agents — and a pattern keeps reappearing: security-specialized agents lead, general-purpose LLM vulnerability detection clusters in the middle, and rule-based SAST trails. The five newcomers are all general-purpose frontier models, so they mostly fill out that middle band and sharpen its boundaries. We are treating this three-tier ordering as an emerging observation, not a headline claim; the numbers are still settling, and five additions in nine days is a lot of signal to absorb.

## Why we think that happened

Rule-based static analysis is deterministic, which is both its strength and its ceiling: a rule matches or it does not, and on real-world code a large share of matches turn out to be noise — the command-injection findings in Python/Flask reported at roughly 99.5% false positives are the extreme case, not the exception. A general-purpose LLM escapes that ceiling because it reasons over context rather than pattern-matching alone, but it was never trained to triage security findings, and wrapping one in an agent loop improves rather than replaces that judgment. Security-specialized scanners sit at the intersection, which is consistent with them leading. We are honestly unsure how much of the gap is capability versus scaffolding and prompting we cannot fully observe from outside, and model versions churn fast enough that any single number is a snapshot rather than a verdict.

## What's next

We will keep widening the roster and re-running the whole field at pinned versions, so the three-tier pattern — if it holds — stops being an observation and becomes a measurement. The methodology is open, and we would genuinely welcome disagreement.

— Faizan Raza, for the RealVuln team


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [The paper, and why we score F3 (recall weighted nine times over precision)](https://realvuln.com/journal/the-paper-and-the-f3-metric.html) · **Next:** [The v2 corpus: adding 40 LLM-generated applications and measuring authorship](https://realvuln.com/journal/the-v2-corpus-llm-generated-code.html)

*This is issue 06 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*