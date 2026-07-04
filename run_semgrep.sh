#!/usr/bin/env bash
# Run semgrep --config auto on repos lacking scan-results/<repo>/semgrep/results.json
set -euo pipefail
cd "$(dirname "$0")"

# Homebrew semgrep is broken on py3.14 (protobuf). Use isolated venv (semgrep 1.150.0)
# and a scrubbed env so the global site-packages can't leak in.
SEMGREP="$(pwd)/.semgrep-venv/bin/semgrep"
run_semgrep() { env -i PATH=/usr/bin:/bin HOME="$HOME" "$SEMGREP" "$@"; }

for repo_path in repos/*-seeded-v2-*/; do
  repo=$(basename "$repo_path")
  out="scan-results/$repo/semgrep"
  if [[ -f "$out/results.json" && "${FORCE:-0}" != "1" ]]; then
    echo "skip  $repo (already scanned)"; continue
  fi
  mkdir -p "$out"
  echo "scan  $repo"
  run_semgrep --config auto --json --oss-only \
    -o "$out/results.json" "$repo_path" || echo "WARN  $repo failed"
done
