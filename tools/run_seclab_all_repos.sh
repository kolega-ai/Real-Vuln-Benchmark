#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Run GitHub SecLab Taskflow Agent across all RealVuln benchmark repos
# Idempotent: skips repos that already have results in scan-results/
#
# Usage:
#   ./tools/run_seclab_all_repos.sh                  # run all repos
#   ./tools/run_seclab_all_repos.sh realvuln-vulpy   # run one repo
# =============================================================================

BENCHMARK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SECLAB_DIR="${SECLAB_DIR:-$(cd "$BENCHMARK_DIR/.." && pwd)/seclab-taskflows}"
SCANNER_NAME="seclab-taskflow-agent-v1"
KEYS_FILE="$BENCHMARK_DIR/tools/seclab_litellm_keys.json"
LITELLM_ENDPOINT="${AI_API_ENDPOINT:-http://localhost:4100/v1}"

# Required env vars
: "${GH_TOKEN:?Set GH_TOKEN to a GitHub PAT with repo and read:org scopes}"

# Repo name -> GitHub org/repo mapping (from ground-truth.json repo_url)
declare -A REPO_MAP
REPO_MAP=(
  ["realvuln-damn-vulnerable-flask-application"]="kolega-ai/realvuln-Damn-Vulnerable-Flask-Application"
  ["realvuln-damn-vulnerable-graphql-application"]="dolevf/Damn-Vulnerable-GraphQL-Application"
  ["realvuln-djangoat"]="Contrast-Security-OSS/DjanGoat"
  ["realvuln-dsvpwa"]="sgabe/DSVPWA"
  ["realvuln-dsvw"]="stamparm/DSVW"
  ["realvuln-dvblab"]="mamgad/DVBLab"
  ["realvuln-dvpwa"]="anxolerd/dvpwa"
  ["realvuln-extremely-vulnerable-flask-app"]="manuelz120/extremely-vulnerable-flask-app"
  ["realvuln-flask-xss"]="terrabitz/Flask_XSS"
  ["realvuln-insecure-web"]="brenesrm/insecure-web"
  ["realvuln-intentionally-vulnerable-python-application"]="kolega-ai/realvuln-Intentionally-Vulnerable-Python-Application"
  ["realvuln-lets-be-bad-guys"]="mpirnat/lets-be-bad-guys"
  ["realvuln-owasp-web-playground"]="kolega-ai-dev/realvuln-OWASP-Web-Playground.git"
  ["realvuln-pygoat"]="adeyosemanputra/pygoat"
  ["realvuln-python-app"]="RiieCco/owasp-bay-area"
  ["realvuln-python-insecure-app"]="kolega-ai/realvuln-python-insecure-app"
  ["realvuln-pythonssti"]="TheWation/PythonSSTI"
  ["realvuln-threatbyte"]="anotherik/ThreatByte"
  ["realvuln-vampi"]="erev0s/VAmPI"
  ["realvuln-vfapi"]="naryal2580/vfapi"
  ["realvuln-vulnerable-api"]="kolega-ai/realvuln-Vulnerable-API"
  ["realvuln-vulnerable-flask-app"]="we45/Vulnerable-Flask-App"
  ["realvuln-vulnerable-python-apps"]="realvuln/Vulnerable-Python-Apps"
  ["realvuln-vulnerable-tornado-app"]="kolega-ai/realvuln-Vulnerable_Tornado_App"
  ["realvuln-vulnpy"]="Contrast-Security-OSS/vulnpy"
  ["realvuln-vulpy"]="fportantier/vulpy"
)

# Get LiteLLM key for a repo
get_key() {
  python3 -c "import json; print(json.load(open('$KEYS_FILE'))['$1'])"
}

# Run the full seclab audit pipeline for one repo
run_repo() {
  local repo="$1"
  local gh_repo="${REPO_MAP[$repo]}"
  local api_key
  api_key=$(get_key "$repo")

  local results_dir="$BENCHMARK_DIR/scan-results/$repo/$SCANNER_NAME"
  local db_dir="$SECLAB_DIR/data/per_repo/$repo"
  local db_file="$db_dir/repo_context.db"

  # Idempotent: skip if results already exist
  if [ -f "$results_dir/results.json" ]; then
    echo "⏭️  SKIP $repo — results already exist at $results_dir/results.json"
    return 0
  fi

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "🔍 SCANNING: $repo ($gh_repo)"
  echo "   Key: ${api_key:0:10}..."
  echo "   DB: $db_file"
  echo "═══════════════════════════════════════════════════════"

  # Setup per-repo data directory
  mkdir -p "$db_dir"

  # Set env vars for this repo
  export AI_API_ENDPOINT="$LITELLM_ENDPOINT"
  export AI_API_TOKEN="$api_key"
  export GH_TOKEN="$GH_TOKEN"
  export MEMCACHE_STATE_DIR="$db_dir"
  export DATA_DIR="$db_dir"
  export LOG_DIR="$db_dir/logs"
  export CODEQL_DBS_BASE_PATH="$db_dir"
  export PATH="$SECLAB_DIR/.venv/bin:$PATH"

  mkdir -p "$LOG_DIR"

  # Clean previous DB for this repo
  rm -f "$db_file"

  cd "$SECLAB_DIR"

  echo "  [1/5] Fetching source code..."
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.fetch_source_code \
    -g repo="$gh_repo" 2>&1 | tail -3

  echo "  [2/5] Identifying applications..."
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.identify_applications \
    -g repo="$gh_repo" 2>&1 | tail -3

  echo "  [3/5] Gathering entry points..."
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.gather_web_entry_point_info \
    -g repo="$gh_repo" 2>&1 | tail -3

  echo "  [4/5] Classifying threats..."
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.classify_application_local \
    -g repo="$gh_repo" -g use_advisory=false 2>&1 | tail -3

  echo "  [5/5] Auditing issues..."
  python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.audit_issue_local_iter \
    -g repo="$gh_repo" -g use_advisory=false 2>&1 | tail -3

  # Convert results to Semgrep format
  echo "  [+] Converting to benchmark format..."
  cd "$BENCHMARK_DIR"
  python3 tools/seclab_to_semgrep.py "$db_file" "$gh_repo" "$results_dir"

  # Score
  echo "  [+] Scoring..."
  python3 score.py --repo "$repo" --scanner "$SCANNER_NAME" 2>&1 | head -5

  echo "✅ DONE: $repo"
}

# Main
cd "$BENCHMARK_DIR"

if [ $# -ge 1 ]; then
  # Run specific repo
  run_repo "$1"
else
  # Run all repos
  for repo in $(python3 -c "import json; [print(k) for k in sorted(json.load(open('$KEYS_FILE')).keys())]"); do
    run_repo "$repo" || echo "❌ FAILED: $repo — continuing..."
  done

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "🏁 ALL REPOS COMPLETE"
  echo "═══════════════════════════════════════════════════════"

  # Print cost summary (requires LITELLM_MASTER_KEY env var)
  if [ -n "${LITELLM_MASTER_KEY:-}" ]; then
    LITELLM_BASE="${LITELLM_ENDPOINT%/v1}"
    echo ""
    echo "💰 Cost per repo:"
    for repo in $(python3 -c "import json; [print(k) for k in sorted(json.load(open('$KEYS_FILE')).keys())]"); do
      key=$(get_key "$repo")
      spend=$(curl -s -X GET "$LITELLM_BASE/key/info?key=$key" \
        -H "Authorization: Bearer $LITELLM_MASTER_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['spend'])" 2>/dev/null || echo "?")
      echo "  $repo: \$$spend"
    done
  fi
fi
