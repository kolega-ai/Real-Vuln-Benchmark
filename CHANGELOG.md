# Changelog

All notable changes to the RealVuln Benchmark will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [3.0.0] - 2026-09-02

### Added
- **TypeScript/JavaScript corpus**: 74 pinned repositories (24 community intentionally
  vulnerable apps + 50 LLM-generated company-style apps) with 2,236 reviewed vulnerable
  findings, bringing the official dataset to 140 repositories across two languages.
- **Non-scoring ground-truth entries** (`"scoring": "non_scoring"` + `non_scoring_reason`):
  reviewed locations whose status is too discretionary to grade. The matcher never assigns
  them, leftover findings inside one are withheld as `NS` rather than counted as false
  positives, and missing one is never a false negative. `ScoreCard` gains `ns` / `ns_gt`.
  176 entries in this release (all TS/JS).
- **Per-language leaderboards**: the homepage and dashboard now carry Overall / Python /
  TypeScript-JS tabs crossed with the All / Human Authored / Vibe Coded authorship tabs.
  The Overall tab ranks only scanners that covered every language; a single-language
  run appears on its language tab, so every ranking is like-for-like.
- New authorship models for the LLM-generated corpus: DeepSeek V4 Pro and DeepSeek V4 Flash.
- `build_manifest.py` regenerates `benchmark-manifest.json` from ground truth
  (`--check` fails when it is stale); manifest schema 3.0 adds per-language totals,
  `non_scoring_entries`, LOC and `distinct_primary_cwes`.
- `compute_loc.py` counts C-style languages and reads from the pinned commit, skipping
  vendored third-party libraries checked into asset directories; every ground-truth file
  now records `loc` (741,034 in total, 607,252 TS/JS).
- `run_agentic.py --language tsjs --repos-dir`; the output validator repairs invalid JSON
  escapes before falling back to LLM repair; `salvage_from_opencode.py` re-validates
  stored session output for runs that failed only on validation.
- `run_codex.py` and `run_agentic_claude_code.py` gain `--language`/`--repos-dir`/`--effort`;
  `RunMetrics.reasoning_effort` records the setting per run. (The Codex CLI silently persists a
  `-c` override into `~/.codex/config.toml` as its new default, so the setting must be recorded
  per run rather than inferred from config afterward.)
- `dashboard.py --min-coverage` and per-language tab aggregates (`tab_aggregates`,
  `tab_repos`, `languages` in `reports/dashboard.json`).
- Semgrep (`--config auto`, OSS), DeepSeek V4 Flash, DeepSeek V4 Pro (agentic-v1, one run per repository,
  TS/JS prompt variant `prompts/system-prompt-tsjs.md`), GPT-5.6 Sol and Daybreak Blue (codex-cli,
  `model_reasoning_effort=high`, same TS/JS prompt; Daybreak Blue is an OpenAI Codex alias that
  currently resolves to the same weights as GPT-5.6 Sol under different system instructions, and
  scores far higher on the same repos and effort level) results for all 74 TS/JS
  repositories; Kolega DevSec Max V0.1.0 results for the TS/JS corpus. The Python results previously published under
  `kolega-devsec-max-v0.0.1` now live under `kolega-devsec-max-v0.1.0` (same scanner,
  unchanged results), giving it full 140-repository coverage; the `v0.0.1` slug is retired
  and remains in the frozen 2.1.0 release.
- `source_layout` ground-truth field for repositories whose source is not checked in as a
  plain tree (`realvuln-xvna` ships `xvna.zip`).

### Changed
- Official dataset: 140 repositories, 4,138 vulnerable findings, 280 false-positive traps,
  176 non-scoring entries. The Python subset (66 repos) is unchanged from 2.1.0, so Python
  per-language scores remain comparable with 2.x.
- Community TS/JS repositories are pinned to forks under `kolega-ai-dev`; generated
  repositories are published as single-snapshot public repositories under the same account.
- Dashboard and dataset pages report lines of code and languages for the whole corpus,
  not Python only. Cost/100k LOC is now computed per tab from that tab's repositories and
  keeps cents below $10 instead of rounding cheap models to "Free".

### Compatibility
- Major version: the official repo set changed. Overall (140-repo) scores must not be
  compared with 2.x scores. Ground-truth schema version stays 1.0; the only additions are
  the optional `scoring` / `non_scoring_reason` finding fields and the optional top-level
  `loc` / `source_layout` fields. The TS/JS corpus ships without false-positive traps.

## [2.1.0] - 2026-08-24

### Changed
- Hugging Face dataset export is now generated from ground truth (`export_hf_dataset.py`).
- Ground-truth correction: `damn-vulnerable-flask-app-003` reclassified as a false-positive trap.
- RealVuln Journal added to the public site.

## [2.0.0] - 2026-05-26

### Added
- Official v2 benchmark manifest with `benchmark_version` and `ground_truth_version` set to `2.0.0`.
- 40 LLM-generated, company-style Python application repos as official Type 1 benchmark targets.
- 746 reviewed seeded vulnerabilities and 160 false-positive traps across the LLM-generated corpus.
- Authorship metadata for Claude Opus 4.7, GPT-5.5, GPT-5.5 x-high, and Kimi K2.6 generated repos.
- Apache 2.0 license
- `CONTRIBUTING.md` with guidelines for adding repos, results, and parsers
- `CHANGELOG.md`
- `pyproject.toml` with dependency declaration and dev tooling config
- Test suite covering parser, matcher, and metrics modules
- Ruff and mypy configuration

### Changed
- Official dataset now contains 66 Python repos, 1,443 vulnerable findings, and 280 false-positive traps.
- `benchmark-manifest.json` now pins every official repo commit SHA and records a full SHA-256 ground-truth content hash.
- Ground-truth files now carry `benchmark_version` and `ground_truth_version` metadata.
- Ground-truth validation now enforces benchmark and GT version metadata.
- Normalized all ground truth and scan result directory names to `realvuln-{name}` format
- Parser registry falls back to `SemgrepParser` for unknown scanner slugs
- Removed internal MongoDB fetch scripts and Kolega-specific tooling

### Fixed
- Removed tracked `__pycache__` bytecode files from git

### Compatibility
- This is a major benchmark version. Scores against RealVuln 1.x and 2.x should be reported separately.

## [0.1.0] - 2025-03-09

### Added
- Initial benchmark framework with 28 target repositories
- Ground truth labels for 866 findings across Python repos
- Semgrep JSON parser with CWE normalization
- 3-field matching engine (file + CWE + line tolerance)
- F2-weighted scoring with per-CWE-family and per-severity breakdowns
- Single-repo scorer (`score.py`) with multi-run support
- Multi-scanner HTML dashboard (`dashboard.py`) with Plotly charts
- Ground truth schema validator (`validate_gt.py`)
- Scan results for semgrep, snyk, sonarqube, and multiple AI scanner variants
