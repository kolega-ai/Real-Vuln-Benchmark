# Running GitHub SecLab Taskflow Agent Locally

## Prerequisites
- Python 3.13+
- GitHub PAT with `repo` and `read:org` scopes
- LiteLLM proxy (or direct OpenAI API key)

## Setup (one-time)

```bash
# Clone the taskflows repo (NOT the agent repo) — sibling to the benchmark dir
cd "$(dirname /path/to/RealVulnBenchmark)"
git clone https://github.com/GitHubSecurityLab/seclab-taskflows.git
cd seclab-taskflows

# Create venv
python3.13 -m venv .venv

# CRITICAL: symlink python binary (MCP servers look for 'python' not 'python3')
ln -sf "$(pwd)/.venv/bin/python3.13" "$(pwd)/.venv/bin/python"

# Install BOTH packages from git source (PyPI version has template bugs)
.venv/bin/pip install --force-reinstall git+https://github.com/GitHubSecurityLab/seclab-taskflow-agent.git git+https://github.com/GitHubSecurityLab/seclab-taskflows.git

# CRITICAL: Edit the INSTALLED config (not src/ — the agent reads from the installed package)
# Location: .venv/lib/python3.13/site-packages/seclab_taskflows/configs/model_config.yaml
# Adjust model names to match your LiteLLM proxy routes
cat > .venv/lib/python3.13/site-packages/seclab_taskflows/configs/model_config.yaml << 'EOF'
seclab-taskflow-agent:
  version: "1.0"
  filetype: model_config
models:
   code_analysis: openai/gpt-4o
   general_tasks: openai/gpt-4o-mini
   triage: openai/gpt-4o
model_settings:
  code_analysis:
    temperature: 1
EOF
```

## .env file

```bash
cat > .env << 'EOF'
MEMCACHE_STATE_DIR=./data
CODEQL_DBS_BASE_PATH=./data
DATA_DIR=./data
LOG_DIR=./logs
AI_API_ENDPOINT=http://localhost:4100/v1   # your LiteLLM proxy
AI_API_TOKEN=<litellm-api-key>
GH_TOKEN=<github-pat-with-repo-and-read:org-scopes>
EOF
```

## Running

```bash
cd /path/to/seclab-taskflows

# CRITICAL: Both of these are required every time
export $(cat .env | xargs)
export PATH="$(pwd)/.venv/bin:$PATH"

# Clear previous results (if re-running)
rm -rf data/repo_context.db

# Run the full audit pipeline (5 stages)
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.fetch_source_code -g repo=fportantier/vulpy
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.identify_applications -g repo=fportantier/vulpy
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.gather_web_entry_point_info -g repo=fportantier/vulpy
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.classify_application_local -g repo=fportantier/vulpy -g use_advisory=false
python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.audit_issue_local_iter -g repo=fportantier/vulpy -g use_advisory=false
```

## Check results

```bash
sqlite3 ./data/repo_context.db "SELECT issue_type, has_vulnerability, substr(notes, 1, 150) FROM audit_result"
```

## Check cost (via LiteLLM)

```bash
curl -s "http://localhost:4100/key/info" -H "Authorization: Bearer <litellm-master-key>" | python3 -m json.tool | grep spend
```

## Convert to RealVuln benchmark format

```bash
cd /path/to/RealVulnBenchmark
python3 tools/seclab_to_semgrep.py ../seclab-taskflows/data/repo_context.db fportantier/vulpy scan-results/realvuln-vulpy/seclab-taskflow-agent-v1/
python3 score.py --repo realvuln-vulpy --scanner seclab-taskflow-agent-v1
```

## Gotchas

1. **PyPI version is broken** — must install from git source. The PyPI version uses `GLOBALS_repo` template syntax but the taskflows use `globals.repo`.
2. **Must symlink `python` → `python3.13`** — MCP subprocess servers call `python` not `python3`.
3. **Must edit the INSTALLED config** at `.venv/lib/python3.13/site-packages/seclab_taskflows/configs/model_config.yaml` — editing `src/` does nothing.
4. **Must `export PATH`** with the venv bin dir — so MCP subprocesses find the right python.
5. **Must `export $(cat .env | xargs)`** — the agent reads env vars, not the .env file directly (despite what the README says).
6. **Model names must match LiteLLM** — e.g. `openai/gpt-5.4` not `gpt-4o`.
