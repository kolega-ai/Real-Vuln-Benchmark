#!/usr/bin/env python3
"""Repeatable Python LOC counter for benchmark repos.

LOC = non-blank, non-comment Python *code* lines (docstring-only lines excluded),
counting application code under repos/<repo>/ and skipping dependency/build/cache
dirs. This is the figure the dashboard sums via the `loc` field in each
ground-truth.json (dashboard.py:load_repo_loc).

Calibration vs the historical hand-recorded realvuln values (within ~1%):
    realvuln-pygoat   recorded 2861  computed 2839
    realvuln-dvpwa    recorded  545  computed  530

Usage:
    python compute_loc.py                       # print LOC for every repos/* dir
    python compute_loc.py vc-codex-...          # specific repo(s)
    python compute_loc.py --glob 'vc-*'         # repos matching a glob
    python compute_loc.py --glob 'vc-*' --write # also write `loc` into each ground-truth.json
"""
from __future__ import annotations

import argparse
import io
import json
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOS = ROOT / "repos"
GT = ROOT / "ground-truth"

# directories that are never application code
SKIP_DIRS = {
    ".venv", "venv", "env", ".env", "node_modules", "site-packages", ".git",
    "__pycache__", "migrations", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "egg-info", "vendor", "third_party",
}


def code_loc(path: Path) -> int:
    """Non-blank, non-comment Python code lines (standalone docstrings excluded)."""
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    lines: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (
                tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT,
                tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER,
            ):
                continue
            # skip a line that is *only* a string literal (module/func docstring)
            if tok.type == tokenize.STRING and tok.line.strip() == tok.string.strip():
                continue
            lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # malformed file: fall back to non-blank, non-#comment lines
        return sum(1 for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("#"))
    return len(lines)


def repo_loc(repo_dir: Path) -> int:
    total = 0
    for p in repo_dir.rglob("*.py"):
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in p.parts):
            continue
        total += code_loc(p)
    return total


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="*", help="specific repo names (default: all under repos/)")
    ap.add_argument("--glob", help="select repos by glob, e.g. 'vc-*'")
    ap.add_argument("--write", action="store_true", help="write `loc` into each repo's ground-truth.json")
    args = ap.parse_args()

    if args.repos:
        repo_dirs = [REPOS / r for r in args.repos]
    elif args.glob:
        repo_dirs = sorted(REPOS.glob(args.glob))
    else:
        repo_dirs = sorted(d for d in REPOS.iterdir() if d.is_dir())

    total = 0
    written = 0
    for d in repo_dirs:
        if not d.is_dir():
            print(f"SKIP {d.name} (no source dir under repos/)")
            continue
        loc = repo_loc(d)
        total += loc
        note = ""
        if args.write:
            gt_path = GT / d.name / "ground-truth.json"
            if gt_path.exists():
                gt = json.loads(gt_path.read_text())
                gt["loc"] = loc
                gt_path.write_text(json.dumps(gt, indent=2, ensure_ascii=False) + "\n")
                written += 1
                note = "  -> wrote loc to ground-truth.json"
            else:
                note = "  (no ground-truth.json; not written)"
        print(f"{d.name:52s} {loc:7d}{note}")
    print(f"\nTOTAL Python code LOC: {total:,} across {len(repo_dirs)} repos"
          + (f"  ({written} GT files updated)" if args.write else ""))


if __name__ == "__main__":
    main()
