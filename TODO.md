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

- [ ] Repo clone script or manifest to populate `repos/` directory (27 repos + pinned commit SHAs)
- [ ] Ship reference results for 2-3 models so users can validate their setup
- [ ] Smoke test mode: run 1 model on 1 repo, compare against expected output
- [ ] Remove hardcoded `LITELLM_URL=http://omen:4100` — make configurable or document as optional
- [ ] Provide Dockerfile for `realvuln-sandbox:latest` (needed by `run_eval.py`)
- [ ] Document `opencode` CLI install for agentic runner

## Open-Source Readiness — LLM Bench (Priority: P2)

- [ ] Reproducibility manifest: lock GT version + repo commits + prompt version + model config
- [ ] `CONTRIBUTING.md` for community contributions
- [ ] Pin ground-truth versions (tag GT snapshots so old scores stay comparable)
- [ ] Document mono-repo structure (llm-bench depends on parent `scorer/`, `parsers/`, `config/`)
- [ ] Attribution for third-party vulnerable repos used in ground truth

## CI/CD (Priority: High)

- [ ] Add GitHub Actions workflow: validate ground truth, run pytest, lint with ruff
- [ ] Run scoring on a sample repo as a smoke test in CI
- [ ] Add badge for test status to README

## CLI & Packaging (Priority: Medium)

- [ ] Make installable as a CLI tool (`realvuln score`, `realvuln dashboard`, `realvuln validate`) via `[project.scripts]` in pyproject.toml
- [ ] Add a `Makefile` or `justfile` for common commands (`make test`, `make lint`, `make dashboard`)

## Data Management (Priority: Low)

- [ ] Evaluate whether scan-results/ should use Git LFS or a separate branch to keep clones fast
- [ ] Consider a data-only release artifact for large result sets
