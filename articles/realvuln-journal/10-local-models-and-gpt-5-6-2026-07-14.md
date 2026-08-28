---
title: "Local models and GPT-5.6: can open-weight scanners compete?"
description: "RealVuln adds open-weight local scanners (Qwen 3.6, Gemma 4, Ornith) and GPT-5.6 Codex CLI — testing whether self-hosted LLMs can scan code."
date: "2026-07-14"
slug: "local-models-and-gpt-5-6"
author: "Faizan Raza"
tags: ["open source LLM security scanner", "local LLM vulnerability detection", "AI code security", "sast vs dast", "LLM security scanner"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/local-models-and-gpt-5-6.html"
og_type: "article"
og_title: "Local models and GPT-5.6: can open-weight scanners compete? — RealVuln Benchmark"
og_description: "RealVuln adds open-weight local scanners (Qwen 3.6, Gemma 4, Ornith) and GPT-5.6 Codex CLI — testing whether self-hosted LLMs can scan code."
twitter_card: "summary_large_image"
twitter_title: "Local models and GPT-5.6: can open-weight scanners compete?"
twitter_description: "RealVuln adds open-weight local scanners (Qwen 3.6, Gemma 4, Ornith) and GPT-5.6 Codex CLI — testing whether self-hosted LLMs can scan code."
---

## Why this matters

Every team choosing a scanner for AI code security eventually hits the same fork in the road: ship source to a cloud API, or keep it in-house and run an open-weight model on your own hardware. The second path only makes sense if local LLM vulnerability detection actually holds up. That is precisely the kind of question an independent benchmark should answer with data rather than vibes.

## What we did

This week RealVuln added three open-weight, self-hostable scanners: Qwen 3.6 35B, Gemma 4 31B, and Ornith 1.0 35B (agentic-v1). The changes landed 2026-07-14 — "Add local-model scanners: Qwen 3.6 35B, Gemma 4 31B, Ornith 1.0 35B (agentic-v1)" and "Merge v2 benchmark and add local-model results" — with "feat: add GPT-5.6 Codex CLI benchmarks" following the same day or the 15th. They join an ongoing cadence: Claude Method (Sonnet 4.6 on the Claude Code harness) landed 2026-07-06, and Kimi K3 is queued for 2026-07-21.

This batch maps the decision surface between cloud frontier models and self-hosted open-weight ones. Everything is scored the same way: F3 (beta=3, recall weighted 9x over precision) as the headline metric, F2 reported alongside, in standard and strict modes, with false-positive traps counting against every entry equally. As with every release, the benchmark, dataset, and methodology are open (Apache-2.0) and reproducible.

## What we observed

We will not quote single scores here; the full table lives in the repo and the [Kolega-Dev/RealVuln](https://huggingface.co/datasets/Kolega-Dev/RealVuln) dataset. The pattern, though, is consistent enough to describe.

The open-weight models are real scanners, not toys. They surface genuine vulnerabilities across the whole, coherent Python applications in the benchmark, and they run entirely under your control. For teams with data-residency or confidentiality constraints, self-hosting is no longer an automatic disqualifier in the privacy-versus-performance tradeoff. But the gap to the frontier is visible, and it concentrates in two places: recall on the harder vulnerability classes, and false positives. The false-positive traps — a deliberate part of our methodology — are what separate a model that flags something plausible from one that flags something correct.

GPT-5.6 Codex CLI sits at the frontier end of the curve. It extends a trend we have seen since the first release: the leading LLM security scanners find a meaningful share of known vulnerabilities, while the surrounding noise varies a lot by harness and by model.

## Why we think that happened

The most defensible explanation is capacity, plus harness maturity. Frontier models have more room to reason about data flow across a whole codebase; the 31-35B local models are strong but work within a tighter budget. Harness matters just as much: how a model is allowed to search, plan, and verify changes the result more than raw parameter count alone, which is why we report the harness next to every entry rather than a bare model name.

We are also honest about what this does not yet prove. One week of local-model results is a snapshot, not a trend; quantization, prompting, and fine-tuning all move these numbers and remain uncontrolled here. Nor is this a sast vs dast argument — we are not ranking static against dynamic analysis, just scoring accuracy against real vulnerabilities. That neutrality is the point of an open benchmark: recall that the best tool in a 36-scanner study detected only 22.7% of known vulnerabilities, and NIST SATE found only 8-30% of tool warnings security-relevant. The field needs measurement more than it needs another feature list.

## What's next

Kimi K3 lands 2026-07-21, and we will keep adding rule-based SAST, general-purpose LLM, and security-specialized agent entries as they ship. If you maintain an open source LLM security scanner you think belongs on the board, the harness and methodology are open — send a pull request.


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [RealVuln 2.0.0: the full 66-repo, false-positive-aware release](https://realvuln.com/journal/v2-0-0-release.html) · **Next:** [Frontier and community scanners: Claude Opus 5 and the first external contribution (Rowan)](https://realvuln.com/journal/frontier-and-community-scanners.html)

*This is issue 10 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*