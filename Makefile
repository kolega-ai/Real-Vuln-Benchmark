.PHONY: install install-dev test lint format typecheck validate smoke-test score dashboard clone help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install base package
	pip install -e .

install-dev: ## Install with dev + llm-bench dependencies
	pip install -e ".[dev,llm-bench]"

test: ## Run pytest
	python3 -m pytest

lint: ## Run ruff linter
	python3 -m ruff check .

format: ## Auto-format with ruff
	python3 -m ruff format .

typecheck: ## Run mypy type checking
	python3 -m mypy parsers/ scorer/

validate: ## Validate all ground truth files
	python3 validate_gt.py

smoke-test: ## Run smoke test (scores semgrep on pygoat, checks known values)
	python3 smoke_test.py

score: ## Score all scanners on all repos
	python3 score.py --repo realvuln-pygoat --all-scanners

dashboard: ## Generate interactive HTML dashboard
	python3 dashboard.py --scanner-group all

clone: ## Clone all benchmark repos at pinned commits
	python3 clone_repos.py

clone-status: ## Show which benchmark repos are cloned
	python3 clone_repos.py --status
