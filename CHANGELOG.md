# Changelog

All notable changes to the RealVuln Benchmark will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
