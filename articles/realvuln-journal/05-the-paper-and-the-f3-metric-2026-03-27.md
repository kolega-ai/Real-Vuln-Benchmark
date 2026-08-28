---
title: "The paper, and why we score F3 (recall weighted nine times over precision)"
description: "Why RealVuln's headline metric is F3, not F1: in security, a missed vulnerability costs far more than a false positive. The metric decision, explained."
date: "2026-03-27"
slug: "the-paper-and-the-f3-metric"
author: "Faizan Raza"
tags: ["F3 metric", "recall vs precision", "vulnerability detection benchmark", "SAST false positives", "scanner accuracy benchmark"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/the-paper-and-the-f3-metric.html"
og_type: "article"
og_title: "The paper, and why we score F3 (recall weighted nine times over precision) — RealVuln Benchmark"
og_description: "Why RealVuln's headline metric is F3, not F1: in security, a missed vulnerability costs far more than a false positive. The metric decision, explained."
twitter_card: "summary_large_image"
twitter_title: "The paper, and why we score F3 (recall weighted nine times over precision)"
twitter_description: "Why RealVuln's headline metric is F3, not F1: in security, a missed vulnerability costs far more than a false positive. The metric decision, explained."
---

## Why this matters

This week we shipped two things at once: the full RealVuln paper draft, and the scoring change its headline numbers rest on. If you read only one methodological choice from this vulnerability detection benchmark, make it the F3 metric — because it quietly redefines what a scanner accuracy benchmark is actually rewarding.

## What we did

On 2026-03-26 we committed "feat: add complete RealVuln arXiv paper draft," landing the complete manuscript of *RealVuln: Benchmarking Rule-Based, General-Purpose LLM, and Security-Specialized Scanners on Real-World Code* (co-authored with John Pellew; [arXiv:2604.13764](https://arxiv.org/abs/2604.13764)). A day later, on 2026-03-27, came "feat: add F3 score (beta=3, recall 9:1) and default to strict F3," which changes the headline metric across the whole evaluation.

The mechanics are short. F1 weights precision and recall equally. F3, with beta=3, weights recall nine times over precision:

F3 = 10·P·R / (9P + R)

We also switched the default to strict scoring, where an unfinished repository counts as a miss instead of being set aside. In plain terms: a scanner has to actually find the vulnerabilities, and every one it leaves behind is now the heaviest penalty on the board.

## What we observed

This is a recall-vs-precision question, and the field's background data pushed us hard in one direction. Published work reports a 99.5% false-positive rate for command-injection findings in Python and Flask — a SAST false-positive problem at a scale where "found it" starts to lose meaning. NIST's SATE found only 8-30% of tool warnings security-relevant. And in a 36-scanner study, the best tool detected only 22.7% of known vulnerabilities. None of those are anomalies; they are the default state of the field.

Against that backdrop, F1 looked wrong for the job. F1 assumes a false positive and a false negative cost the same. In security they do not: a false positive costs an analyst minutes of triage, while a false negative can be a breach no one saw coming. Weighting recall nine times over precision is how we encode that asymmetry — and we chose nine because it is transparent and aggressive toward recall, not because we measured the true cost ratio, which differs by organization and by vulnerability class.

We also found the standard-versus-strict split mattered more than we expected. Some agentic scanners could not reliably produce output at all across repeated attempts — three tries, and a scan could still come back empty. A scan that fails to run gets no credit, and under strict scoring that failure counts as a miss, the same as never finding the vulnerability. Defaulting to strict made the gaps between tools sharper and, we think, more honest.

## Why we think that happened

We are confident about the direction of the change. Precision-first tooling has been rewarded for years, and a precision-weighted metric would keep rewarding exactly the behavior that produced a 99.5% false-positive rate. We are far less sure about the magnitude. Nine-to-one is a stated, defensible assumption rather than a measurement, and it will not match every team's breach-to-triage cost ratio. That is why we report F2 (beta=2) alongside F3, in both standard and strict modes: readers can see how sensitive a ranking is to the weighting, and if two scanners swap places between F2 and F3, that is a signal to investigate rather than a bug to hide. The strict default is honest in the same way — it makes numbers look lower than vendors would like, possibly including our own.

## What's next

Next we reconcile the rest of the evaluation harness with the strict-F3 default and run the full scanner set through it end to end to see whether the leaderboard shifts. We expect disagreement on the nine-to-one weighting, and we would rather have that argument in the open than bake it in silently.


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [Reproducible by design: prompt versioning and the manifest](https://realvuln.com/journal/reproducible-by-design.html) · **Next:** [Scaling the roster: Opus 4.7, GLM-5.1, Kimi K2.6, GPT-5.5 and DeepSeek-V4](https://realvuln.com/journal/scaling-the-scanner-roster.html)

*This is issue 05 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*