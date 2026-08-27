# Industry State — August 2026

## Executive summary

The external benchmark landscape has improved materially since RealVuln v1, especially in the last 2–3 months. Several new datasets now use **real repositories and real CVEs**, but there is still **no external benchmark that fully matches RealVuln's evaluation model**: blind whole-repository scanning, pinned vulnerable versions, complete ground truth, arbitrary finding matching, and reliable false-positive measurement.

**Direction:** don't replace or merge these into the RealVuln leaderboard as-is. Instead, a separate **External Real-World Validation** track could scan the strongest independent CVE datasets and report results alongside — not blended into — the core leaderboard, keeping RealVuln's own methodology assumptions intact.

## Most relevant benchmarks

| Benchmark | What it contains | Fit for a RealVuln validation track |
|---|---|---|
| **VulnGym (Aug 2026)** | 23 real repositories, 184 reviewed GitHub advisories, 408 vulnerability entries with line-level traces | Closest new benchmark to repository-level vulnerability discovery; scanners must explore real repositories rather than classify preselected snippets. Strongest current external validation candidate. |
| **HoF-Bench (Jul 2026)** | 95 real AI-discovered CVEs across 8 mature OSS repositories | Excellent real-production CVEs, but the official protocol gives scanners the target file(s), making detection easier than a normal blind scan. A blind full-repo scan would be a stronger, non-standard variant worth reporting separately. |
| **RepoPairBench (Jul 2026)** | 100 validated Python CVE vulnerability/fix pairs across 48 CWEs | Real repositories and vulnerable/patched pairs; useful for checking that a finding appears before the fix and disappears after it. Python-heavy, matching RealVuln's current corpus language. |
| **CrossCommitVuln-Bench (Apr 2026)** | 15 real Python CVEs whose vulnerable state emerges across multiple commits | Small but deliberately difficult; existing rule-based tools perform poorly even on full snapshots. Useful as a supplementary hard-mode challenge set rather than a headline benchmark. |
| **BountyBench** | 25 real systems and 40 genuine bug-bounty vulnerabilities; Detect/Exploit/Patch tasks | Strong realism and true application environments, but small and more agent/pentest-oriented than SAST. |
| **CyberGym-E2E (Jun 2026)** | 920 real vulnerabilities across 139 open-source projects | Large and realistic, but designed around end-to-end detection, PoC generation and patching rather than conventional scanner enumeration. A future track candidate, not immediate. |
| **SEC-bench Pro (May 2026)** | 183 validated V8/SpiderMonkey vulnerabilities | Very real and difficult, but heavily focused on long-horizon browser-engine bug hunting and PoC generation — a different task shape than SAST detection. |
| **Antiproof / KEVBench (Jul 2026)** | New real-world vulnerability discovery evaluation; Antiproof reports 64/66 detections across BountyBench + KEVBench | Shows the field moving toward real-CVE discovery plus exploitability proof. Worth tracking as an industry direction rather than an immediate integration target. |

## Candidate next step

A possible **External Real-World Validation** suite, with four initial datasets:

1. **VulnGym** — primary repository-level external benchmark.
2. **HoF-Bench** — run blind, without its target-file hints.
3. **RepoPairBench** — scan both vulnerable and patched revisions.
4. **CrossCommitVuln-Bench** — small hard-mode challenge set.

Reporting these independently from the core RealVuln leaderboard — e.g. "rediscovered X/Y externally curated real-world CVEs" — would let results be checked against ground truth built by unrelated research groups, since repository selection, CVE identification, and dataset construction in these datasets come from independent teams.

## Bottom line

The industry is clearly moving toward **whole-repository, real-CVE evaluation**, consistent with the direction already planned for RealVuln v2. However, the benchmark gap still exists: none of the current alternatives provides the full combination of blind production-style scanning, exhaustive vulnerability ground truth, and robust false-positive scoring. The most useful role for these datasets is as **independent validation alongside RealVuln, not as a replacement for its core methodology.**

### Sources
- VulnGym: arXiv:2608.02001
- HoF-Bench: arXiv:2607.27030
- RepoPairBench / DREA: arXiv:2607.13439
- CrossCommitVuln-Bench: arXiv:2604.21917
- BountyBench: arXiv:2505.15216
- CyberGym-E2E: arXiv:2606.04460
- SEC-bench Pro: arXiv:2605.26548
- Antiproof: arXiv:2607.12316
