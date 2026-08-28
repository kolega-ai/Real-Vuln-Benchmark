---
title: "Reproducible by design: prompt versioning and the manifest"
description: "How RealVuln makes every score reproducible: content-hash prompt versioning, a pinned manifest, and one-command scoring anyone can run."
date: "2026-03-23"
slug: "reproducible-by-design"
author: "Faizan Raza"
tags: ["open source vulnerability scanner", "reproducible benchmark", "security scanner benchmark", "static analysis tools", "benchmark methodology"]
series: "RealVuln Journal"
type: "article"
canonical: "https://realvuln.com/journal/reproducible-by-design.html"
og_type: "article"
og_title: "Reproducible by design: prompt versioning and the manifest — RealVuln Benchmark"
og_description: "How RealVuln makes every score reproducible: content-hash prompt versioning, a pinned manifest, and one-command scoring anyone can run."
twitter_card: "summary_large_image"
twitter_title: "Reproducible by design: prompt versioning and the manifest"
twitter_description: "How RealVuln makes every score reproducible: content-hash prompt versioning, a pinned manifest, and one-command scoring anyone can run."
---

## Why this matters

A security scanner benchmark is only as credible as someone else's ability to re-run it. If a published score cannot be reproduced by an independent party, it isn't a measurement of a scanner — it's a vendor claim, and we want RealVuln to be the opposite.

## What we did

On 2026-03-23 we landed the core of what we now think of as our "run it yourself" guarantee — the part that makes an independent benchmark of open source vulnerability scanners different from a marketing page. Four commits make up the push: "Add content-hash prompt versioning system", "Add reproducibility manifest, attribution, and mono-repo docs", "Add clone script, smoke test, and updated quickstart", and "Add CLI entrypoints and Makefile". A fifth commit, "Fix critical and important issues from code review", followed on 2026-03-24 to tighten what we had shipped.

The machinery is deliberately simple. Every LLM prompt is pinned by a SHA-256 content hash, so a prompt cannot change silently — any edit changes the hash, and the change shows up in version control rather than buried inside a model call. Every repository in the dataset is pinned to a specific commit SHA, so a scanner is always evaluated against exactly the code we evaluated, not whatever the upstream project looks like next week. A manifest records the ground-truth content hash for the dataset itself, so the vulnerability labels and the false-positive traps are pinned as firmly as the code and the prompts.

From there, the whole pipeline collapses to a handful of commands anyone can run: `clone` the repository, run `validate_gt.py` to confirm the ground-truth hashes match, then `score.py --repo <x> --all-scanners` to recompute the numbers and `dashboard.py` to view them. There is no hidden step, no internal-only evaluation script, no "trust us" file.

A related housekeeping note: the project switched to the MIT license on 2026-03-17. That was later superseded by Apache-2.0 at v2, which is the license the benchmark carries today.

## What we observed

The first thing we noticed is how much quietly drifted before we had hashes. During development a prompt would be reworded to fix a typo or "just to see," and a result would move a point or two with no record of why. Content-hash versioning turned those silent drifts into explicit diffs: you can now see, in the manifest and the commit history, exactly which prompt text produced which score. That single change made disagreements about results more productive, because both sides of an argument were finally looking at the same inputs.

Second, pinning exposed how sensitive scanner results are to things we had treated as trivia. It did not make every run identical — the same prompt against the same pinned code can still differ across runs, because LLM outputs are non-deterministic, which is why we report standard deviation whenever a scanner is run more than once. What pinning removes is the dominant source of silent drift: repositories are pinned to a commit SHA so they cannot move upstream, and a prompt edit now shows up in version control rather than disappearing into a model call. The results legitimately change only when an input changes — and that is now visible instead of mysterious.

Third, the false-positive traps benefited more than we expected. Because trap and true-positive labels live in the same pinned manifest, a claim that "your scanner scored X" can be checked against exactly the ground truth that produced X. It turns a benchmark number into something closer to a lab notebook.

## Why we think that happened

Our working explanation is that reproducibility, for an LLM-involved benchmark, is mostly an input-pinning problem rather than a determinism problem. LLM-based scanners are nondeterministic in ways a SHA-256 hash cannot fix — sampling, temperature, and model updates all sit outside the hash's reach. What the hash does fix is the part we control: the exact prompt text, the exact repository state, and the exact ground truth. By pinning those, we isolate the remaining nondeterminism to the model runtime itself instead of letting it hide in silently-edited inputs.

We should be honest about the limit. We are not claiming hashing makes every run bit-for-bit identical, and we have not fully quantified how much residual variance remains across model-serving versions. We think — but have not yet proven at scale — that pinning inputs removes the dominant source of unreproducible scores for the rule-based and static analysis tools in the benchmark. Quantifying that residual run-to-run variance remains open work. That distinction is part of the benchmark methodology, and we would rather state it than paper over it.

## What's next

Next we will make the manifest the single source of truth for every release and document the nondeterminism we have not yet pinned. The goal is that "run it yourself" stays a guarantee, not a slogan.


---

**In this series:** [All issues](https://realvuln.com/journal/index.html) · **Previous:** [First LLM scanner runs: the agentic models enter the leaderboard](https://realvuln.com/journal/first-llm-scanner-runs.html) · **Next:** [The paper, and why we score F3 (recall weighted nine times over precision)](https://realvuln.com/journal/the-paper-and-the-f3-metric.html)

*This is issue 04 of the RealVuln Journal. See the [leaderboard](https://realvuln.com/), [methodology](https://realvuln.com/methodology.html), and [dataset](https://realvuln.com/dataset.html). The benchmark is open source — [github.com/kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark).*