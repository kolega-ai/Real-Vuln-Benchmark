---
title: "Frontier and community scanners: Claude Opus 5 and the first external contribution (Rowan)"
description: "RealVuln adds Claude Opus 5 and its first community-contributed scanner, Rowan — a milestone for an open, independent benchmark."
date: "2026-08-04"
slug: "frontier-and-community-scanners"
author: "Faizan Raza"
tags: ["LLM vulnerability detection", "AI vulnerability scanner", "claude opus vulnerability scanner", "AI code security", "open source security scanner"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/frontier-and-community-scanners.html"
og_type: "article"
og_title: "Frontier and community scanners: Claude Opus 5 and the first external contribution (Rowan) — RealVuln Benchmark"
og_description: "RealVuln adds Claude Opus 5 and its first community-contributed scanner, Rowan — a milestone for an open, independent benchmark."
twitter_card: "summary_large_image"
twitter_title: "Frontier and community scanners: Claude Opus 5 and the first external contribution (Rowan)"
twitter_description: "RealVuln adds Claude Opus 5 and its first community-contributed scanner, Rowan — a milestone for an open, independent benchmark."
---

## Why this matters

A vulnerability benchmark ages the moment the models it measures stop being the ones people actually use, or the moment nobody outside its authors can add to it. Two recent milestones — a new frontier model and our first community-contributed scanner — test whether RealVuln can stay honest as the ground shifts beneath it.

## What we did

On 2026-07-31 we merged `feat: add Claude Opus 5 Python benchmark`, bringing an agentic-class, security-specialized model into the suite. Claude Opus 5 is not a rule engine; it is the kind of model that plans, explores, and decides where to look, which makes it a different object of study from the general-purpose LLMs we have mostly measured.

Then, on 2026-08-04, we received something we had been hoping for but could not schedule: the first external contribution. Hedgerow.dev submitted results and a parser for their scanner, Rowan, and we merged it to the leaderboard on 2026-08-24.

The mechanics mattered as much as the milestone. Rowan did not require a patch to our core evaluation code. Hedgerow dropped in Semgrep-compatible JSON output and a small parser, and the existing pipeline did the rest. That was the design bet: keep the contribution interface narrow, so adding an AI vulnerability scanner — or any scanner — does not require our permission.

## What we observed

Two patterns stand out, and we want to be careful not to overstate either.

First, the frontier keeps moving. Running Claude Opus 5 as a vulnerability scanner places it between our LLM vulnerability detection comparisons and something closer to a security agent, and that stretches our categories in useful ways. We are not going to summarize its scores here: a single snapshot at a single commit is exactly the kind of number that gets screenshotted and stripped of context. The results are on the leaderboard, next to the repositories and labels that produced them.

Second, the open-contribution model worked once. An outside team — not the authors — added an open source security scanner to a benchmark we run, and the whole contribution was a Semgrep-compatible JSON file plus a parser. That is the difference between a benchmark people can argue with and a benchmark people can only argue about.

## Why we think that happened

We think the contribution path worked because the surface area is deliberately small. Every scanner we run lands in the same output shape, so a contributor does not need to understand our scoring, our false-positive traps, or our F3 weighting to add a scanner. They only have to produce output we can parse; after that, the same strict and standard modes apply to them as to everyone else.

We are more hesitant about the frontier finding. Claude Opus 5's placement tells us something about the model, but a single benchmark pass is a weak instrument for a moving target. We do not yet know whether the agentic behavior helped, hurt, or merely changed where the errors land, and we would rather leave that open than offer a confident story we cannot back.

The larger point is about trust. We have said before that transparency is an invitation to find bias, not a defense against it. A benchmark nobody can extend is a benchmark nobody can trust. Accepting Rowan is not proof that RealVuln is unbiased; it is proof that someone outside the tent can now check. The CONTRIBUTING path — add a scanner, add a repository, or challenge a label — is how that invitation becomes concrete, and it is the part of this release we are proudest of.

## What's next

We will keep the contribution path open and review any external scanner, repository, or label challenge on the same footing as our own work. Next, we are tightening the parser review so that a third-party AI code security result receives the same scrutiny as the numbers it produces.

— Faizan Raza


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [Local models and GPT-5.6: can open-weight scanners compete?](https://realvuln.com/journal/local-models-and-gpt-5-6.html) · **Next:** [RealVuln 2.1.0: the current release and the dataset export](https://realvuln.com/journal/v2-1-0-release.html)

*This is issue 11 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*