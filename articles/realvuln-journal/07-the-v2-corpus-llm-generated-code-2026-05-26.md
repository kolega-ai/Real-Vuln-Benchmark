---
title: "The v2 corpus: adding 40 LLM-generated applications and measuring authorship"
description: "RealVuln v2 adds 40 LLM-generated, company-style apps — letting us measure how scanners perform on the AI-written code now entering production."
date: "2026-05-26"
slug: "the-v2-corpus-llm-generated-code"
author: "Faizan Raza"
tags: ["AI code security", "AI-generated code vulnerabilities", "LLM security", "vulnerability detection benchmark", "SAST vs LLM"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/the-v2-corpus-llm-generated-code.html"
og_type: "article"
og_title: "The v2 corpus: adding 40 LLM-generated applications and measuring authorship — RealVuln Benchmark"
og_description: "RealVuln v2 adds 40 LLM-generated, company-style apps — letting us measure how scanners perform on the AI-written code now entering production."
twitter_card: "summary_large_image"
twitter_title: "The v2 corpus: adding 40 LLM-generated applications and measuring authorship"
twitter_description: "RealVuln v2 adds 40 LLM-generated, company-style apps — letting us measure how scanners perform on the AI-written code now entering production."
---

## Why this matters

Code written by large language models is now the frontier of AI code security, and the scanners we rely on were not designed with it in mind. This release gives us a controlled way to ask the question that matters: do vulnerability detectors behave differently on AI-generated code than on human code?

## What we did

On 2026-05-26 we released the v2.0.0 corpus. The headline change: 40 LLM-generated, company-style Python application repositories are now official Type 1 targets in the RealVuln benchmark. Each repository ships with authorship metadata recording which model produced it — Claude Opus 4.7, GPT-5.5, GPT-5.5 x-high, and Kimi K2.6 — so scanner results can be sliced by who (or what) wrote the code. These are not synthetic in the OWASP/Juliet sense — isolated single-vulnerability snippets with no cross-file structure. Each is a coherent, multi-file application with real framework routing, ORM usage, and cross-file data flow. What is artificial is only the authorship, not the structure.

The LLM-generated corpus contains 746 reviewed seeded vulnerabilities and 160 false-positive traps. Those traps are not an afterthought: the whole point of a vulnerability detection benchmark is accuracy, not feature lists, and traps are how we keep precision honest.

Taken together, the dataset now spans 66 Python repositories, 1,443 vulnerable findings, and 280 false-positive traps.

We also tightened reproducibility. benchmark-manifest.json now pins every repository to a commit SHA and records a full SHA-256 hash of the ground-truth content, and each ground-truth file carries benchmark_version and ground_truth_version metadata, so a result can be traced to the exact corpus snapshot it was measured against.

## What we observed

This is a corpus release, not a results release, so the honest headline is that we have not yet run the full scanner sweep over the LLM-authored code — and we will not pretend otherwise.

What we can report from the review process itself is softer. The seeded vulnerabilities are not exotic: they are the categories we have always cared about — command injection in web handlers, unsafe deserialization, hard-coded credentials, path traversal — but they tend to arrive in a different shape. More verbose, more nested, more defensive-looking in the middle while still being wrong at the edges. Our reviewers repeatedly had to decide whether a finding was a genuine flaw or a confident-looking mistake, which is precisely the ambiguity this benchmark exists to measure.

The authorship metadata also surfaced something we had not planned to study and are not yet claiming: the same vulnerability class tends to be expressed differently across models. That is an observation, not a conclusion.

## Why we think that happened

The honest answer is that we do not fully know yet, and we want to be careful not to reverse-engineer a story from a corpus we have not finished measuring.

Our working hypothesis is that LLM-authored code sits in an uncomfortable middle for rule-based SAST tools. Those tools encode expectations about how human developers write — structure, idioms, error handling, ordering — and AI-generated code frequently violates those expectations while remaining syntactically correct. If that holds, we would expect false-positive behavior to shift on this corpus, in either direction. That is the SAST-vs-LLM gap people keep asking us about, and the point of v2 is to measure it rather than assert it.

We can say with more confidence why the provenance work matters. "Vibe-coded" code — written by prompting, accepted by copy-paste, and merged without every line being read — is becoming a default way production Python is produced. A benchmark that only measures human-authored code is answering yesterday's question. Measuring authorship is how we ask today's: whether a scanner's accuracy transfers when the author is a model.

## What's next

The next step is to run the scanner suite across the full v2 corpus and report F3 (beta=3) alongside F2 in standard and strict modes, split by authorship. We will publish those results even if they are unflattering to our earlier assumptions.

— Faizan Raza


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [Scaling the roster: Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5 and DeepSeek-V4](https://realvuln.com/journal/scaling-the-scanner-roster.html) · **Next:** [RealVuln 1.0.0: freezing the first release and opening the public site](https://realvuln.com/journal/v1-0-0-release.html)

*This is issue 07 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*