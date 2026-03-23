# LLM Security Scanner Benchmark

Evaluate how well LLMs can find security vulnerabilities in real-world Python code. Part of the [RealVuln Benchmark](../README.md).

Each LLM is given a vulnerable Python repository and asked to produce a structured list of findings (file path, line number, CWE). Those findings are matched against hand-labeled ground truth and scored using the **F2 metric** (recall-weighted, beta=2) — because a missed vulnerability is worse than a false alarm.

## How It Works

```
Repository code  ──>  LLM (via runner)  ──>  Semgrep-format JSON findings
                                                       │
Ground truth  ─────────────────────────>  Matcher  <───┘
                                             │
                                        F2 Score + breakdown
```

**Matching rules:** A finding is a true positive if it matches a ground-truth entry on all three fields:
- **File path** — exact match
- **CWE** — the finding's CWE appears in the GT entry's `acceptable_cwes` list
- **Line number** — within ±10 lines of the GT entry's `start_line`/`end_line`

## Quickstart

### 1. Install

```bash
# From the repo root
pip install -e ".[llm-bench]"
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add keys for the providers you want to use
```

### 3. Run a single evaluation

```bash
# Single-turn (sends all code in one prompt, cheapest)
python3 llm-bench/scripts/run_pilot.py \
  --model claude-haiku-4-5 \
  --repos realvuln-pygoat \
  --runs 1

# Agentic (LLM explores the repo with tools — read files, grep, bash)
python3 llm-bench/scripts/run_agentic.py \
  --model claude-haiku-4-5-agentic \
  --repos realvuln-pygoat \
  --runs 1
```

### 4. View results

```bash
# Score a specific model/repo
python3 score.py --repo realvuln-pygoat --scanner claude-haiku-4-5-v1

# Aggregate all LLM results into a summary
python3 llm-bench/scripts/collect_results.py

# Generate interactive HTML dashboard
python3 llm-bench/scripts/generate_llm_dashboard.py
```

## Runner Modes

| Runner | Script | How it works | Best for |
|--------|--------|--------------|----------|
| **Pilot** | `run_pilot.py` | Single API call — all repo files sent in one prompt | Fast iteration, cheapest per run |
| **Agentic** | `run_agentic.py` | LLM uses tools (read, grep, bash) to explore the repo via [OpenCode CLI](https://github.com/opencode-ai/opencode) | Realistic agent evaluation |
| **Eval** | `run_eval.py` | OpenHands Docker sandbox with CodeActAgent | Isolated, reproducible runs |

All runners produce the same output format: `scan-results/{repo}/{scanner-slug}/run-N.json`.

### Common flags

```bash
--repos all               # Run on all 27+ repos
--runs 3                  # Multiple runs for reliability analysis
--dry-run                 # Show cost estimate without running
--max-concurrent 4        # Parallel runs
--max-total-cost 50       # Hard stop at $50 USD
--prompt-template path.md # Use a custom prompt
--prompt-label "v2-exp"   # Tag runs with a human-readable label
```

## Cost Estimates

Use `--dry-run` before any real run to see cost estimates.

| Model | Est. cost per repo (single-turn) | Est. cost per repo (agentic) |
|-------|----------------------------------|------------------------------|
| Claude Haiku 4.5 | ~$0.10 | ~$0.50 |
| GPT-4o mini | ~$0.02 | ~$0.10 |
| Claude Sonnet 4 | ~$0.50 | ~$2.00 |
| Claude Opus 4 | ~$2.50 | ~$10.00 |
| Gemini 2.5 Pro | ~$0.30 | ~$1.50 |

**Full benchmark cost:** Running all models across all 27 repos with 3 runs each can cost **$200-$500+**. Always use `--dry-run` first and consider `--max-total-cost` as a safety net.

## Adding Your Own

### Add a new model

1. Edit `llm-bench/config/models.yaml`:

```yaml
my-model:
  provider: anthropic          # anthropic | openai | google | together | litellm | moonshot | zai
  model_id: my-model-id       # API model identifier
  pricing:
    input_per_1m: 1.00         # USD per 1M input tokens
    output_per_1m: 5.00        # USD per 1M output tokens
  scanner_slug: my-model-v1   # Unique slug (used as result directory name)
  max_context: 200000         # Max context window in tokens
```

2. Set the API key in `.env` for the provider.

3. Run:
```bash
python3 llm-bench/scripts/run_pilot.py --model my-model --repos realvuln-pygoat --runs 1
```

### Use a custom prompt

Create a markdown file with the same placeholders as `llm-bench/prompts/system-prompt.md`:
- `{cwe_families}` — gets replaced with the CWE family list
- `{output_schema_example}` — gets replaced with the expected JSON format

```bash
python3 llm-bench/scripts/run_pilot.py \
  --model claude-haiku-4-5 \
  --repos realvuln-pygoat \
  --prompt-template my-prompt.md \
  --prompt-label "experiment-v2" \
  --runs 3
```

Each run records the prompt's content hash (`sha256:...`) in the metrics file, so results from different prompt versions are always distinguishable.

### Add a custom runner

Your runner must produce Semgrep-compatible JSON at `scan-results/{repo}/{scanner-slug}/run-N.json`:

```json
{
  "version": "1.0.0",
  "results": [
    {
      "check_id": "python.security.injection.sql-injection",
      "path": "app/views.py",
      "start": {"line": 42, "col": 1},
      "end": {"line": 42, "col": 60},
      "extra": {
        "message": "SQL injection via unsanitized user input",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-89: SQL Injection"],
          "confidence": "HIGH"
        }
      }
    }
  ]
}
```

Once the file is in place, use `score.py` to evaluate:
```bash
python3 score.py --repo realvuln-pygoat --scanner your-scanner-slug
```

### Add a new repo

1. Create `ground-truth/{repo-slug}/ground-truth.json` following the schema (see existing repos for examples).
2. Validate: `python3 validate_gt.py {repo-slug}`
3. Clone the repo into `repos/{repo-slug}` (or let the runner auto-clone from `repo_url` in the GT file).
4. Run any model against it:
```bash
python3 llm-bench/scripts/run_pilot.py --model claude-haiku-4-5 --repos {repo-slug} --runs 1
```

## Project Structure

```
llm-bench/
├── config/
│   ├── eval-config.yaml       # Evaluation defaults (timeout, iterations, sandbox)
│   └── models.yaml            # LLM model configs (provider, pricing, slugs)
├── harness/
│   ├── runner.py              # OpenHands integration & orchestration
│   ├── prompt_builder.py      # System prompt rendering & versioning
│   ├── metrics_collector.py   # Operational metrics (tokens, cost, timing)
│   ├── output_validator.py    # JSON extraction, validation & repair
│   ├── cost_calculator.py     # Token cost estimation
│   └── reliability.py         # Cross-run consistency analysis
├── prompts/
│   ├── system-prompt.md       # Default prompt template
│   └── output-schema.json     # JSON Schema for findings format
├── scripts/
│   ├── run_eval.py            # OpenHands Docker sandbox runner
│   ├── run_pilot.py           # Single-turn direct API runner
│   ├── run_agentic.py         # OpenCode CLI agentic runner
│   ├── collect_results.py     # Aggregate & score all runs
│   └── generate_llm_dashboard.py  # Interactive HTML dashboard
└── tests/
    ├── test_prompt_builder.py
    ├── test_output_validator.py
    ├── test_cost_calculator.py
    ├── test_pipeline_integration.py
    └── test_reliability.py
```

## Dependencies on parent project

The llm-bench harness imports from the parent RealVuln Benchmark:
- `scorer/` — F2 scoring and ground-truth matching
- `parsers/` — Scanner output normalization
- `config/cwe-families.json` — CWE groupings
- `ground-truth/` — Hand-labeled vulnerability data

Install the full project with `pip install -e ".[llm-bench]"` from the repo root.

## Runner-specific requirements

| Runner | Extra requirement |
|--------|-------------------|
| `run_pilot.py` | `pip install anthropic` (Anthropic models only) |
| `run_agentic.py` | [OpenCode CLI](https://github.com/opencode-ai/opencode) installed (`brew install opencode` or see their docs) |
| `run_eval.py` | Docker daemon running, `openhands-ai` package installed |

## Breaking changes (if upgrading)

**`build_prompt()` returns `PromptInfo` instead of `str`.** If you have code calling `build_prompt()` directly, update it:

```python
# Before
system_prompt = build_prompt(cwe_families)

# After
prompt_info = build_prompt(cwe_families)
system_prompt = prompt_info.rendered    # the prompt text
version_hash = prompt_info.version_hash # "sha256:..." content hash
```

The built-in runner scripts are already updated. The `.metrics.json` schema also has two new optional fields (`prompt_version`, `prompt_label`) — both default to empty strings, so existing files load fine.

## License

Apache 2.0 — see [LICENSE](../LICENSE).
