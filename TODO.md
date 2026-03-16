# TODO

Deferred improvements for the RealVuln Benchmark.

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
