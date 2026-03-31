#!/usr/bin/env python3
"""Run GitHub SecLab Taskflow Agent across RealVuln benchmark repos.

Idempotent: skips repos that already have results.

Usage:
    python3 tools/run_seclab_all_repos.py                      # all repos
    python3 tools/run_seclab_all_repos.py realvuln-vulpy       # one repo
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Required env vars: GH_TOKEN, AI_API_ENDPOINT (LiteLLM proxy URL)
# Optional: SECLAB_DIR (defaults to ../seclab-taskflows relative to benchmark)
# Also requires: tools/seclab_litellm_keys.json with per-repo LiteLLM API keys

BENCHMARK_DIR = Path(__file__).resolve().parent.parent
SECLAB_DIR = Path(os.environ.get("SECLAB_DIR", str(BENCHMARK_DIR.parent / "seclab-taskflows")))
SCANNER_NAME = "seclab-taskflow-agent-v1"
KEYS_FILE = BENCHMARK_DIR / "tools" / "seclab_litellm_keys.json"
LITELLM_ENDPOINT = os.environ.get("AI_API_ENDPOINT", "http://localhost:4100/v1")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
PYTHON = str(SECLAB_DIR / ".venv" / "bin" / "python")


def check_prerequisites():
    """Validate required env vars and paths exist."""
    if not GH_TOKEN:
        sys.exit("ERROR: Set GH_TOKEN to a GitHub PAT with repo and read:org scopes")
    if not SECLAB_DIR.exists():
        sys.exit(f"ERROR: SecLab taskflows dir not found at {SECLAB_DIR}\n"
                 f"  Clone it: git clone https://github.com/GitHubSecurityLab/seclab-taskflows.git {SECLAB_DIR}\n"
                 f"  Or set SECLAB_DIR env var to point to your clone")
    if not KEYS_FILE.exists():
        sys.exit(f"ERROR: LiteLLM keys file not found at {KEYS_FILE}\n"
                 f"  Create it with per-repo API keys: {{\"realvuln-vulpy\": \"sk-...\", ...}}")


def load_repo_map():
    """Build repo_name -> github_org/repo from ground truth files."""
    repo_map = {}
    gt_dir = BENCHMARK_DIR / "ground-truth"
    for repo_dir in sorted(gt_dir.iterdir()):
        gt_file = repo_dir / "ground-truth.json"
        if gt_file.exists():
            with open(gt_file) as f:
                gt = json.load(f)
            url = gt.get("repo_url", "").rstrip("/")
            parts = url.split("/")
            if len(parts) >= 2:
                repo_map[repo_dir.name] = "/".join(parts[-2:])
    return repo_map


def load_keys():
    with open(KEYS_FILE) as f:
        return json.load(f)


def run_stage(stage_name, taskflow, gh_repo, env):
    """Run one seclab taskflow stage."""
    cmd = [
        PYTHON, "-m", "seclab_taskflow_agent",
        "-t", taskflow,
        "-g", f"repo={gh_repo}",
    ]
    if "classify" in taskflow or "audit_issue" in taskflow:
        cmd.extend(["-g", "use_advisory=false"])

    print(f"  [{stage_name}] ...", end=" ", flush=True)
    result = subprocess.run(
        cmd,
        cwd=str(SECLAB_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=3600,  # 1 hour max per stage
    )
    if result.returncode != 0:
        # Check if it's a non-critical failure
        if "CRITICAL: Required task not completed" in result.stderr or "CRITICAL: Required task not completed" in result.stdout:
            print("FAILED (non-critical, continuing)")
            return False
        print(f"FAILED (exit {result.returncode})")
        # Print last few lines of output for debugging
        output = result.stdout + result.stderr
        for line in output.strip().split("\n")[-5:]:
            print(f"    {line}")
        return False
    print("OK")
    return True


def run_repo(repo_name, repo_map, keys):
    gh_repo = repo_map.get(repo_name)
    if not gh_repo:
        print(f"❌ Unknown repo: {repo_name}")
        return False

    api_key = keys.get(repo_name)
    if not api_key:
        print(f"❌ No LiteLLM key for: {repo_name}")
        return False

    results_dir = BENCHMARK_DIR / "scan-results" / repo_name / SCANNER_NAME
    if (results_dir / "results.json").exists():
        print(f"⏭️  SKIP {repo_name} — results already exist")
        return True

    # Per-repo data directory
    db_dir = SECLAB_DIR / "data" / "per_repo" / repo_name
    db_dir.mkdir(parents=True, exist_ok=True)
    log_dir = db_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    db_file = db_dir / "repo_context.db"

    # Clean previous DB
    if db_file.exists():
        db_file.unlink()

    print()
    print("=" * 55)
    print(f"🔍 SCANNING: {repo_name} ({gh_repo})")
    print(f"   Key: {api_key[:10]}...")
    print("=" * 55)

    # Build env
    env = os.environ.copy()
    env.update({
        "AI_API_ENDPOINT": LITELLM_ENDPOINT,
        "AI_API_TOKEN": api_key,
        "GH_TOKEN": GH_TOKEN,
        "MEMCACHE_STATE_DIR": str(db_dir),
        "DATA_DIR": str(db_dir),
        "LOG_DIR": str(log_dir),
        "CODEQL_DBS_BASE_PATH": str(db_dir),
        "PATH": str(SECLAB_DIR / ".venv" / "bin") + ":" + env.get("PATH", ""),
    })

    stages = [
        ("1/5 Fetch source", "seclab_taskflows.taskflows.audit.fetch_source_code"),
        ("2/5 Identify apps", "seclab_taskflows.taskflows.audit.identify_applications"),
        ("3/5 Entry points", "seclab_taskflows.taskflows.audit.gather_web_entry_point_info"),
        ("4/5 Classify threats", "seclab_taskflows.taskflows.audit.classify_application_local"),
        ("5/5 Audit issues", "seclab_taskflows.taskflows.audit.audit_issue_local_iter"),
    ]

    for stage_name, taskflow in stages:
        ok = run_stage(stage_name, taskflow, gh_repo, env)
        if not ok and "Fetch" in stage_name:
            print(f"❌ ABORT {repo_name} — fetch failed")
            return False

    # Convert to benchmark format
    print("  [+] Converting...", end=" ", flush=True)
    try:
        subprocess.run(
            [sys.executable, str(BENCHMARK_DIR / "tools" / "seclab_to_semgrep.py"),
             str(db_file), gh_repo, str(results_dir)],
            cwd=str(BENCHMARK_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        print("OK")
    except subprocess.CalledProcessError as e:
        print(f"FAILED: {e.stderr[:200]}")
        return False

    # Score
    print("  [+] Scoring...", end=" ", flush=True)
    result = subprocess.run(
        [sys.executable, "score.py", "--repo", repo_name, "--scanner", SCANNER_NAME],
        cwd=str(BENCHMARK_DIR),
        capture_output=True,
        text=True,
    )
    # Print the score line
    for line in result.stdout.split("\n"):
        if SCANNER_NAME in line:
            print(line.strip())
            break
    else:
        print("OK")

    print(f"✅ DONE: {repo_name}")
    return True


def main():
    check_prerequisites()
    repo_map = load_repo_map()
    keys = load_keys()

    if len(sys.argv) >= 2:
        repos = [sys.argv[1]]
    else:
        repos = sorted(keys.keys())

    results = {}
    for repo in repos:
        try:
            ok = run_repo(repo, repo_map, keys)
            results[repo] = "OK" if ok else "FAILED"
        except Exception as e:
            print(f"❌ ERROR {repo}: {e}")
            results[repo] = f"ERROR: {e}"

    if len(repos) > 1:
        print()
        print("=" * 55)
        print("🏁 SUMMARY")
        print("=" * 55)
        for repo, status in results.items():
            print(f"  {repo}: {status}")

        # Cost summary (requires LITELLM_MASTER_KEY env var)
        master_key = os.environ.get("LITELLM_MASTER_KEY")
        if master_key:
            print()
            print("💰 Cost per repo:")
            import urllib.request
            for repo in repos:
                key = keys.get(repo, "")
                try:
                    req = urllib.request.Request(
                        f"{LITELLM_ENDPOINT.rstrip('/v1')}/key/info?key={key}",
                        headers={"Authorization": f"Bearer {master_key}"}
                    )
                    resp = urllib.request.urlopen(req)
                    data = json.loads(resp.read())
                    spend = data.get("info", {}).get("spend", 0)
                    print(f"  {repo}: ${spend:.4f}")
                except Exception:
                    print(f"  {repo}: ? (couldn't fetch)")


if __name__ == "__main__":
    main()
