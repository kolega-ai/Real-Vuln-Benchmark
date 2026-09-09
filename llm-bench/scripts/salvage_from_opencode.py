#!/usr/bin/env python3
"""Recover `validation_failed` agentic runs from OpenCode's local session store.

OpenCode keeps every assistant message of a session in its sqlite database. When
a run failed only because the harness could not extract the findings JSON from
the model's final message (e.g. an invalid escape that the validator now
repairs), the model output itself is intact — re-validating it recovers the run
without spending anything. Runs whose stored output still fails validation are
left as they are, for a normal retry.

Usage:
    python3 llm-bench/scripts/salvage_from_opencode.py --scanner deepseek-v4-flash-agentic-v1 --repos-dir repos-public
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LLM_BENCH_DIR))

from harness.output_validator import save_validated_output, validate_output  # noqa: E402

DB = Path.home() / ".local/share/opencode/opencode.db"


def final_text(conn: sqlite3.Connection, directory: str, after: float) -> str | None:
    """Concatenated assistant text of the most recent session run in `directory`."""
    ses = conn.execute(
        "select id from session where directory=? and time_created>=? order by time_created desc limit 1",
        (directory, after),
    ).fetchone()
    if not ses:
        return None
    rows = conn.execute(
        "select p.data from part p join message m on m.id=p.message_id "
        "where p.session_id=? and json_extract(p.data,'$.type')='text' "
        "and json_extract(m.data,'$.role')='assistant' order by p.time_created",
        (ses[0],),
    ).fetchall()
    return "".join(json.loads(r[0])["text"] for r in rows) or None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scanner", required=True, help="scanner slug under scan-results/<repo>/")
    ap.add_argument("--repos-dir", type=Path, default=PROJECT_ROOT / "repos")
    ap.add_argument("--since", type=float, default=0, help="epoch ms; ignore older sessions")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = sqlite3.connect(str(DB))
    recovered = unrecoverable = 0
    for mpath in sorted((PROJECT_ROOT / "scan-results").glob(f"*/{args.scanner}/run-*.metrics.json")):
        metrics = json.loads(mpath.read_text())
        result_path = mpath.with_name(mpath.name.replace(".metrics.json", ".json"))
        if metrics.get("exit_status") != "validation_failed" or result_path.exists():
            continue
        repo = mpath.parent.parent.name
        directory = str((args.repos_dir / repo).resolve())
        raw = final_text(conn, directory, args.since)
        if raw is None:
            print(f"{repo}: no stored session")
            unrecoverable += 1
            continue
        v = validate_output(raw)
        if not v.valid or v.data is None:
            print(f"{repo}: still invalid — {v.errors[:1]}")
            unrecoverable += 1
            continue
        n = len(v.data.get("results", []))
        print(f"{repo}: recovered {n} findings")
        recovered += 1
        if args.dry_run:
            continue
        save_validated_output(v.data, str(result_path))
        metrics["exit_status"] = "success"
        metrics["error_message"] = ""
        metrics["salvaged_from_opencode_session"] = True
        mpath.write_text(json.dumps(metrics, indent=2))
    print(f"recovered {recovered}, unrecoverable {unrecoverable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
