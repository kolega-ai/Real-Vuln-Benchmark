---
title: "Introducing the RealVuln benchmark framework"
description: "The RealVuln benchmark framework: how we label real vulnerabilities, match scanner findings on three fields, and score scanners fairly."
date: "2026-03-16"
slug: "introducing-the-benchmark"
author: "Faizan Raza"
tags: ["vulnerability scanner benchmark", "security scanner evaluation", "SAST benchmark", "code vulnerability detection", "static analysis tools"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/introducing-the-benchmark.html"
og_type: "article"
og_title: "Introducing the RealVuln benchmark framework — RealVuln Benchmark"
og_description: "The RealVuln benchmark framework: how we label real vulnerabilities, match scanner findings on three fields, and score scanners fairly."
twitter_card: "summary_large_image"
twitter_title: "Introducing the RealVuln benchmark framework"
twitter_description: "The RealVuln benchmark framework: how we label real vulnerabilities, match scanner findings on three fields, and score scanners fairly."
---

## Why this matters

Scanner accuracy is still argued with anecdotes and vendor tables. We wanted a security scanner evaluation where every claim about code vulnerability detection can be traced to a labeled line of source — an open, auditable vulnerability scanner benchmark instead of another feature checklist.

## What we did

On 2026-03-16 we pushed the commit that turns RealVuln from an idea into a framework: "RealVuln Benchmark: security scanner evaluation framework" (cdd59561), alongside the security policy and GitHub link commits the same day. The CHANGELOG's 0.1.0 milestone describes what that framework shipped with: a seed corpus of roughly 28 intentionally-vulnerable Python repositories carrying about 866 hand-labeled findings. We did the labeling ourselves rather than trusting any scanner's output as ground truth. Each finding is recorded with an id, a CWE, a file and line range, a severity, and a short evidence note, so anyone can audit a single label without re-deriving the whole dataset.

On top of that corpus sits the machinery that makes a static code analysis tool comparable. For static application security testing, a three-field matching engine treats a finding as a true positive only when file path, CWE, and line number (within +/-10) all agree. A Semgrep JSON parser with CWE normalization routes one of the most common tools through the same path as everything else. A multi-scanner HTML dashboard with Plotly charts keeps results readable, and a schema validator makes sure contributed labels can't silently corrupt the data.

Scoring is precision and recall with F2, plus the seed of what becomes F3 — we were already questioning whether recall-weighted scoring better reflects a defender's actual priorities. The headline, though, is the design philosophy: every number should reproduce exactly, and every number should be auditable line by line.

## What we observed

Three things stood out. First, labeling was far slower than we planned. "Intentionally vulnerable" repos are messy — fixes, regressions, and experiments mixed together — so file and line ranges drift the moment upstream changes. Second, matching on three fields at once is strict, much stricter than "same repo, same CWE," and that strictness reshapes the denominator more than we expected. Third, the dashboard surfaced disagreements that raw numbers hide: when a scanner and a label conflict, you can see exactly which line is in question and decide for yourself who is right.

## Why we think that happened

The +/-10 window was a judgment call, not a law of nature. It exists because there is often no single unambiguous line for a finding — a docstring, a function declaration, and the actual sink can each be defended as "the" line — and the tolerance absorbs that ambiguity rather than forcing one canonical choice. We are genuinely unsure whether ten lines is the right tolerance, and we expect reasonable people to disagree. Strict matching, by contrast, is deliberate: a SAST benchmark that credits near-misses as hits flatters every scanner and answers nothing. The messiness of the corpus is itself a finding — real code is not curated, and labels decay — which is why we pinned everything to a commit and added the schema validator. We can defend the philosophy; the specific constants remain open to challenge.

## What's next

We'll grow the corpus, publish the dataset, and run more scanners through the same matching and scoring path. The immediate task is scoring the first full runs and seeing whether the early results hold.


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [Why we built RealVuln: the false-positive problem no benchmark measured](https://realvuln.com/journal/why-we-built-realvuln.html) · **Next:** [First LLM scanner runs: the agentic models enter the leaderboard](https://realvuln.com/journal/first-llm-scanner-runs.html)

*This is issue 02 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*