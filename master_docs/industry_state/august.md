# Industry State — August 2026

## Executive summary

The external benchmark landscape has improved materially since RealVuln v1, especially in the last 2–3 months. Several new datasets now use **real repositories and real CVEs**, but there is still **no external benchmark that fully matches our desired SAST evaluation model**: blind whole-repository scanning, pinned vulnerable versions, complete ground truth, arbitrary finding matching, and reliable false-positive measurement.

**Recommendation:** do not replace or merge these into the RealVuln leaderboard. Instead, add a separate **External Real-World Validation** track and run Kolega against the strongest independent CVE datasets. This gives us credible third-party validation without inheriting weaker benchmark assumptions.

## Most relevant benchmarks

| Benchmark | What it contains | Fit for Kolega | Recommendation |
|---|---|---|---|
| **VulnGym (Aug 2026)** | 23 real repositories, 184 reviewed GitHub advisories, 408 vulnerability entries with line-level traces | Closest new benchmark to repository-level vulnerability discovery; agents must explore real repositories rather than classify preselected snippets | **Highest priority. Run Kolega against it.** Strongest current external validation candidate |
| **HoF-Bench (Jul 2026)** | 95 real AI-discovered CVEs across 8 mature OSS repositories | Excellent real-production CVEs, but benchmark gives analyzers the target file(s), making detection easier than a normal blind scan | **High priority.** Run Kolega blind against the full repos; outperforming hinted baselines would be strong evidence |
| **RepoPairBench (Jul 2026)** | 100 validated Python CVE vulnerability/fix pairs across 48 CWEs | Real repositories and vulnerable/patched pairs; very useful for checking that a finding appears before the fix and disappears after it | **High priority.** Particularly easy/relevant for our Python-heavy evaluation stack |
| **CrossCommitVuln-Bench (Apr 2026)** | 15 real Python CVEs whose vulnerable state emerges across multiple commits | Small but deliberately difficult; Semgrep/Bandit perform poorly even on full snapshots | **Run as a challenge set.** Cheap supplementary evidence, not a headline benchmark |
| **BountyBench** | 25 real systems and 40 genuine bug-bounty vulnerabilities; Detect/Exploit/Patch tasks | Strong realism and true application environments, but small and more agent/pentest-oriented than SAST | **Secondary priority.** Worth testing if integration effort is reasonable |
| **CyberGym-E2E (Jun 2026)** | 920 real vulnerabilities across 139 open-source projects | Large and realistic, but designed around end-to-end detection, PoC generation and patching rather than conventional scanner enumeration | **Investigate, not immediate priority.** Potential future external track |
| **SEC-bench Pro (May 2026)** | 183 validated V8/SpiderMonkey vulnerabilities | Very real and difficult, but heavily focused on long-horizon browser-engine bug hunting and PoC generation | **Do not prioritise for SAST validation.** Useful later for advanced agent capability testing |
| **Antiproof / KEVBench (Jul 2026)** | New real-world vulnerability discovery evaluation; Antiproof reports 64/66 detections across BountyBench + KEVBench | Shows the field moving toward real-CVE discovery plus exploitability proof, but is less directly reusable as a standard SAST benchmark today | **Watch closely.** Relevant industry direction rather than first integration target |

## Recommended next step

Create an **External Real-World Validation** suite with four initial datasets:

1. **VulnGym** — primary repository-level external benchmark.
2. **HoF-Bench** — run blind, without its target-file hints.
3. **RepoPairBench** — scan both vulnerable and patched revisions.
4. **CrossCommitVuln-Bench** — small hard-mode challenge set.

Report these independently from RealVuln, e.g. **“Kolega rediscovered X/Y externally curated real-world CVEs.”** This directly addresses the strongest credibility concern with RealVuln — that Kolega and the benchmark share authorship — because repository selection, CVE ground truth and dataset construction come from independent research groups.

## Bottom line

The industry is clearly moving toward **whole-repository, real-CVE evaluation**, validating the direction already planned for RealVuln v2. However, the benchmark gap still exists: none of the current alternatives provides the full combination of blind production-style scanning, exhaustive vulnerability ground truth and robust false-positive scoring. We should therefore **use the best new datasets as independent validation, not adopt any one of them as our core benchmark.**

### Sources
- VulnGym: arXiv:2608.02001
- HoF-Bench: arXiv:2607.27030
- RepoPairBench / DREA: arXiv:2607.13439
- CrossCommitVuln-Bench: arXiv:2604.21917
- BountyBench: arXiv:2505.15216
- CyberGym-E2E: arXiv:2606.04460
- SEC-bench Pro: arXiv:2605.26548
- Antiproof: arXiv:2607.12316
