---
title: "Why we built RealVuln: the false-positive problem no benchmark measured"
description: "Why we started RealVuln: an open, independent benchmark measuring vulnerability-scanner accuracy and false positives that no existing benchmark covered."
date: "2026-03-05"
slug: "why-we-built-realvuln"
author: "Faizan Raza"
tags: ["SAST false positives", "vulnerability scanner benchmark", "static analysis accuracy", "false positive rate", "independent security benchmark"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/why-we-built-realvuln.html"
og_type: "article"
og_title: "Why we built RealVuln: the false-positive problem no benchmark measured — RealVuln Benchmark"
og_description: "Why we started RealVuln: an open, independent benchmark measuring vulnerability-scanner accuracy and false positives that no existing benchmark covered."
twitter_card: "summary_large_image"
twitter_title: "Why we built RealVuln: the false-positive problem no benchmark measured"
twitter_description: "Why we started RealVuln: an open, independent benchmark measuring vulnerability-scanner accuracy and false positives that no existing benchmark covered."
---

## Why this matters

Static analysis is one of the few security controls that runs before code ships, yet its value is quietly eroded by SAST false positives — and no open, independent security benchmark measured that static analysis accuracy directly. This entry explains why we started one.

## What we did

On March 5, 2026, we made the project's initial commit (b50f71e1) and founded RealVuln: an open, Apache-2.0, reproducible vulnerability-scanner benchmark. No existing benchmark measured scanner accuracy on real-world vulnerabilities inside whole, coherent applications — the options were either synthetic single-issue test cases (isolated, single-vulnerability snippets with no cross-file structure) or closed datasets. A few decisions were fixed from that first commit. We would test on coherent, whole applications rather than isolated snippets. We would score measured accuracy, not marketing feature checklists, with a headline metric that weights recall nine-to-one over precision and is reported in both standard and strict modes. And we would measure the thing every practitioner complains about but few benchmarks quantify: false positives, captured explicitly through false-positive traps — clean code deliberately shaped like a vulnerable pattern, so a scanner has to tell the difference rather than pattern-match. We also wanted the methodology open enough that anyone could re-run it and disagree with us. That commit contained no scanner results, deliberately; this entry is the "why" that precedes the "how."

## What we observed

The numbers that pushed us here are not our own, but they are the reason the project exists. One widely cited analysis reported a 99.5% false-positive rate for command-injection findings in Python/Flask applications — meaning the overwhelming majority of alerts on that class of bug pointed at code that was not vulnerable. NIST's SATE program found only 8-30% of tool warnings to be security-relevant, depending on the tool and year. And in a 36-scanner study, the best-performing tool detected only 22.7% of known vulnerabilities. Read together, these describe a tool class that is noisy where code is clean and quiet where code is broken: high false-positive rates on one side, low recall on the other. Both failures matter — a scanner that cries wolf gets ignored, and a scanner that stays silent gives a false sense of security.

## Why we think that happened

We cannot attribute those figures to a single cause with confidence. The underlying studies used different corpora, tool versions, and scoring rules, and we have not yet run our own measurements — that, in a sense, is the point of the project. But when we went looking for an existing vulnerability-scanner benchmark to trust, we kept hitting the same three gaps. Several of the best-known benchmarks run on synthetic test cases — isolated, single-vulnerability snippets with no cross-file structure (OWASP Benchmark, NIST Juliet) — which are valuable for exercising tool mechanics but tell us little about how a scanner behaves on a whole, coherent application. Some datasets are closed (SastBench), which makes independent reproduction impossible and results unverifiable. And some methodologies are vendor-controlled, which weakens neutrality even when the authors are well-intentioned. Into that gap stepped a new generation of LLM-based scanners claiming deeper reasoning about code semantics — and no open benchmark tested whether those claims hold on real vulnerabilities. We are not asserting those tools fail; we simply could not find a neutral instrument to check, so we are building one.

## What's next

The next work is concrete rather than editorial: assemble the labeled dataset, stand up the matching and scoring engine, and run the first scanners through it. For now the benchmark exists as a single commit, and the question it asks — how accurate are these scanners, really? — is open.

— Faizan Raza


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Next:** [Introducing the RealVuln benchmark framework](https://realvuln.com/journal/introducing-the-benchmark.html)

*This is issue 01 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*