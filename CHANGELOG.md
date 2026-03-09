# Changelog

All notable changes to the RealVuln Benchmark will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Apache 2.0 license
- `CONTRIBUTING.md` with guidelines for adding repos, results, and parsers
- `CHANGELOG.md`
- `pyproject.toml` with dependency declaration and dev tooling config
- Test suite covering parser, matcher, and metrics modules
- Ruff and mypy configuration

### Changed
- Normalized all ground truth and scan result directory names to `realvuln-{name}` format
- Parser registry falls back to `SemgrepParser` for unknown scanner slugs
- Removed internal MongoDB fetch scripts and Kolega-specific tooling

### Fixed
- Removed tracked `__pycache__` bytecode files from git

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
