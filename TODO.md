# TODO

Deferred improvements for the RealVuln Benchmark.

## Open-Source Readiness — LLM Bench (Priority: P0)

- [x] `llm-bench/README.md` — Quickstart, what it measures, 3 runner modes, how to read results
- [x] "Add Your Own" guides: new model, custom prompt, custom agent/runner, new repo
- [x] `.env.example` with all API keys documented (which keys for which models)
- [x] LICENSE file (already existed at repo root — Apache 2.0)
- [x] Dependency install instructions (standalone from parent `pyproject.toml`)
- [x] Cost warnings prominently in docs (`--models all --repos all --runs 3` can cost $500+)

## Pre-Release Checklist — Prompt Versioning Migration (Priority: P0)

- [x] Run backfill: `python3 llm-bench/scripts/backfill_prompt_version.py --label default-v1` (stamped 789 .metrics.json files)
- [x] Regenerate dashboard after backfill so scanner detail pages show prompt versions
- [x] Commit regenerated `reports/` files and updated `.metrics.json` files
- [x] Document breaking change: `build_prompt()` now returns `PromptInfo` instead of `str` — callers must use `.rendered`

## Open-Source Readiness — LLM Bench (Priority: P1)

- [x] Repo clone script: `clone_repos.py` (reads repo_url + commit_sha from ground truth, supports --status, --repo)
- [x] Smoke test: `smoke_test.py` (scores semgrep on realvuln-pygoat, checks TP/FP/FN/TN/F2 against known values)
- [x] Reference results: semgrep on realvuln-pygoat used as deterministic baseline in smoke test
- [x] Remove hardcoded `LITELLM_URL=http://omen:4100` — already configurable via env var, .env.example has localhost default
- [x] Document `opencode` CLI install for agentic runner — already in README runner-specific requirements table
- [ ] Provide Dockerfile for `realvuln-sandbox:latest` (needed by `run_eval.py`)

## Open-Source Readiness — LLM Bench (Priority: P2)

- [x] Reproducibility manifest: `benchmark-manifest.json` (GT content hash, prompt version, all repo URLs + commit SHAs)
- [x] `CONTRIBUTING.md` — already existed with comprehensive guide
- [x] Pin ground-truth versions — manifest includes GT content hash; commit SHAs already in each GT file
- [x] Document mono-repo structure — added to llm-bench README with directory tree
- [x] Attribution for third-party vulnerable repos — added table to root README

## CLI & Packaging (Priority: Medium)

- [x] CLI entrypoints via `[project.scripts]` in pyproject.toml: `realvuln-score`, `realvuln-dashboard`, `realvuln-validate`, `realvuln-clone`, `realvuln-smoke-test`
- [x] `Makefile` with targets: test, lint, format, typecheck, validate, smoke-test, score, dashboard, clone
