#!/usr/bin/env python3
"""Convert GitHub SecLab Taskflow Agent SQLite results to Semgrep-format JSON.

Usage:
    python tools/seclab_to_semgrep.py <repo_context.db> <github_repo> <output_dir>

Example:
    python tools/seclab_to_semgrep.py \
        ../seclab-taskflows/data/repo_context.db \
        fportantier/vulpy \
        scan-results/realvuln-vulpy/seclab-taskflow-agent-v1/
"""

import json
import re
import sqlite3
import sys
from pathlib import Path

# Map issue_type strings to CWE IDs
ISSUE_TYPE_TO_CWE = {
    "sql injection": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "stored xss": "CWE-79",
    "reflected xss": "CWE-79",
    "cross-site request forgery": "CWE-352",
    "csrf": "CWE-352",
    "broken access control": "CWE-284",
    "authorization": "CWE-284",
    "idor": "CWE-639",
    "session": "CWE-384",
    "session impersonation": "CWE-384",
    "session forgery": "CWE-384",
    "authentication bypass": "CWE-287",
    "authentication integrity": "CWE-287",
    "authentication": "CWE-287",
    "command injection": "CWE-78",
    "os injection": "CWE-78",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "open redirect": "CWE-601",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "insecure deserialization": "CWE-502",
    "pickle": "CWE-502",
    "xml external": "CWE-611",
    "xxe": "CWE-611",
    "hardcoded credential": "CWE-798",
    "hardcoded secret": "CWE-798",
    "hardcoded password": "CWE-798",
    "sensitive data": "CWE-200",
    "information disclosure": "CWE-200",
    "information leak": "CWE-200",
    "denial of service": "CWE-400",
    "code injection": "CWE-94",
    "template injection": "CWE-94",
    "ssti": "CWE-94",
    "missing auth": "CWE-306",
    "missing authentication": "CWE-306",
    "injection": "CWE-89",  # generic injection defaults to SQLi
}


def classify_cwe(issue_type: str, notes: str = "") -> str:
    """Map an issue_type string (and optionally notes) to a CWE identifier."""
    # Check issue_type first — normalize underscores to spaces so
    # DB values like "sensitive_data_exposure" match patterns like "sensitive data"
    lower = issue_type.lower().replace("_", " ")
    for pattern, cwe in ISSUE_TYPE_TO_CWE.items():
        if pattern in lower:
            return cwe
    # Fall back to scanning the notes for clues
    if notes:
        notes_lower = notes.lower()
        for pattern, cwe in ISSUE_TYPE_TO_CWE.items():
            if pattern in notes_lower:
                return cwe
    return "CWE-1035"  # fallback: generic software vulnerability


def extract_file_lines(notes: str) -> list[tuple[str, int]]:
    """Extract (file, line) pairs from notes text like 'bad/libuser.py:12'."""
    # Match patterns like path/to/file.py:123
    matches = re.findall(r'([a-zA-Z0-9_/.]+\.[a-zA-Z]+):(\d+)', notes)
    results = []
    seen = set()
    for filepath, line in matches:
        # Skip non-source files (but keep .html templates — they can have XSS)
        if '.txt' in filepath or '.md' in filepath or '.log' in filepath:
            continue
        key = (filepath, int(line))
        if key not in seen:
            seen.add(key)
            results.append(key)
    return results


def convert(db_path: str, github_repo: str, output_dir: str):
    """Convert audit_result rows to Semgrep-format JSON."""
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    # Case-insensitive match — the agent lowercases repo names
    rows = db.execute(
        "SELECT * FROM audit_result WHERE LOWER(repo) = LOWER(?) AND has_vulnerability = 1",
        (github_repo,)
    ).fetchall()

    if not rows:
        # Also try matching any repo in the DB (single-repo DBs)
        rows = db.execute(
            "SELECT * FROM audit_result WHERE has_vulnerability = 1"
        ).fetchall()

    if not rows:
        print(f"No vulnerabilities found for {github_repo}")
        return

    results = []
    for row in rows:
        issue_type = row["issue_type"]
        notes = row["notes"]
        cwe = classify_cwe(issue_type, notes)

        # Extract file:line locations from the notes
        # Keep first line per unique file to avoid over-counting
        locations = extract_file_lines(notes)
        seen_files: set[str] = set()
        deduped: list[tuple[str, int]] = []
        for filepath, line in locations:
            if filepath not in seen_files:
                seen_files.add(filepath)
                deduped.append((filepath, line))

        if not deduped:
            deduped = [("unknown", 1)]

        for filepath, line in deduped:
            results.append({
                "check_id": f"seclab.{issue_type.lower().replace(' ', '-').replace('/', '-')}",
                "path": filepath,
                "start": {"line": line, "col": 1, "offset": 0},
                "end": {"line": line, "col": 1, "offset": 0},
                "extra": {
                    "message": notes[:500],
                    "metadata": {
                        "cwe": [f"{cwe}: {issue_type}"],
                        "source": "seclab-taskflow-agent",
                    },
                    "severity": "WARNING",
                },
            })

    output = {
        "version": "1.0.0",
        "results": results,
        "errors": [],
        "paths": {"scanned": []},
    }

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    out_file = out_path / "results.json"

    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Converted {len(rows)} audit results → {len(results)} findings")
    print(f"Written to {out_file}")

    # Summary
    print(f"\nBy CWE:")
    from collections import Counter
    cwes = Counter(r["extra"]["metadata"]["cwe"][0] for r in results)
    for cwe, count in cwes.most_common():
        print(f"  {cwe}: {count} findings")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <repo_context.db> <github_repo> <output_dir>")
        print(f"Example: {sys.argv[0]} ../seclab-taskflows/data/repo_context.db fportantier/vulpy scan-results/realvuln-vulpy/seclab-taskflow-agent-v1/")
        sys.exit(1)

    convert(sys.argv[1], sys.argv[2], sys.argv[3])
