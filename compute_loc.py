#!/usr/bin/env python3
"""Repeatable LOC counter for benchmark repos (Python, TypeScript/JavaScript, and JVM).

LOC = non-blank, non-comment *code* lines (docstring-only lines excluded for
Python), counting production project source and skipping tests,
dependency/build/cache dirs.
The language is read from the repo's ground-truth.json. Files are read from the
pinned commit (`commit_sha`) when repos/<repo> is a git checkout, so untracked
local artifacts never inflate the count. This is the figure the dashboard sums
via the `loc` field in each ground-truth.json (dashboard.py:load_repo_loc).

Calibration vs the historical hand-recorded realvuln values (within ~1%):
    realvuln-pygoat   recorded 2861  computed 2839
    realvuln-dvpwa    recorded  545  computed  530

Usage:
    python compute_loc.py                       # print LOC for every repos/* dir
    python compute_loc.py vc-codex-...          # specific repo(s)
    python compute_loc.py --glob 'vc-*'         # repos matching a glob
    python compute_loc.py --glob 'vc-*' --write # write Java/JVM `loc` only
    python compute_loc.py --repos-root /path/to/pinned/checkouts --write

Legacy Python and TS/JS GT LOC values are intentionally frozen; --write updates
Java/JVM GT only unless --write-non-java is explicitly supplied.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import tokenize
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOS = ROOT / "repos"
GT = ROOT / "ground-truth"

# directories that are never application code
SKIP_DIRS = {
    ".venv", "venv", "env", ".env", "node_modules", "site-packages", ".git",
    "__pycache__", "migrations", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "egg-info", "vendor", "third_party",
    ".next", ".nuxt", ".cache", ".angular", "coverage", ".turbo", "out",
    ".react-router",
    "storybook-static", ".svelte-kit",
    # vendored front-end libraries checked into the tree
    "plugins", "bower_components", "jspm_packages",
    # Tool bootstrap and precompiled JTE output, not repository source.
    ".mvn", "jte-classes",
}

# language (GT `language`) -> source extensions counted
# Counted per repo's declared `language`, not its actual tech stack: a Django/
# Flask app's HTML templates and static assets are real frontend code but are
# not `.py`, so they are not counted, while a Next.js/Vue app's frontend is
# itself .tsx/.vue and is fully counted. This is why TS/JS totals run well
# ahead of Python's at a similar repo count -- an asymmetry in what counts as
# "code" per language, not a difference in how much frontend each corpus has.
LANG_EXTS = {
    "python": (".py",),
    "typescript": (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue"),
    "javascript": (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue"),
    # The Java leaderboard also contains Kotlin/JVM applications.
    "java": (".java", ".kt", ".kts"),
}
# generated / bundled artefacts that are not application code
SKIP_SUFFIXES = (".min.js", ".min.mjs", ".d.ts", ".bundle.js", ".chunk.js")
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "cypress",
             "playwright", "__mocks__", "test-suite", "integration-tests",
             "test-helpers"}
# third-party libraries copied into a static/asset directory instead of installed
ASSET_DIRS = {"public", "private", "static", "assets", "javascripts", "js", "lib", "libs", "vendor"}
VENDORED_LIB_NAMES = {
    "three.js", "angular.js", "jquery.js", "bootstrap.js", "adminlte.js", "freewall.js",
    # three.js example modules shipped alongside three.js
    "OrbitControls.js", "EffectComposer.js", "RenderPass.js", "ShaderPass.js",
    "MaskPass.js", "CopyShader.js",
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


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def c_style_loc(src: str) -> int:
    """Non-blank, non-comment lines for //- and /* */-commented languages.

    Block comments are removed before counting; a line that is only a `//`
    comment is skipped. String literals containing comment markers are rare
    enough in application code that this stays within the ~1% calibration the
    Python counter has.
    """
    src = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), src)
    return sum(
        1 for ln in src.splitlines()
        if ln.strip() and not ln.strip().startswith("//")
    )


def loc_of_text(src: str, suffix: str) -> int:
    if suffix == ".py":
        return code_loc_text(src)
    return c_style_loc(src)


def code_loc_text(src: str) -> int:
    lines: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (
                tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT,
                tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER,
            ):
                continue
            if tok.type == tokenize.STRING and tok.line.strip() == tok.string.strip():
                continue
            lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return sum(1 for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("#"))
    return len(lines)


def _wanted(rel: str, exts: tuple[str, ...]) -> bool:
    parts = rel.split("/")
    lower_parts = [part.lower() for part in parts]
    if lower_parts[0] in {"docs", "attacker-app", "security_examples", "fineract-command-test"}:
        return False
    production_root = next((i + 1 for i in range(len(lower_parts) - 1)
                            if lower_parts[i:i + 2] == ["src", "main"]), None)
    for i, part in enumerate(lower_parts[:-1]):
        if part in TEST_DIRS and not (production_root is not None and i > production_root):
            return False
    if any(part in {"test", "tests", "it", "integrationtest", "testfixtures"}
           for parent, part in zip(lower_parts, lower_parts[1:]) if parent == "src"):
        return False
    if lower_parts[0].startswith("fineract-e2e-tests") or lower_parts[:2] == ["framework", "testtools"]:
        return False
    name_lower = lower_parts[-1]
    if (name_lower.startswith("test_") or name_lower.endswith("_test.py")
            or name_lower == "conftest.py" or ".test." in name_lower
            or ".spec." in name_lower or name_lower in {"test.js", "test.ts", "jest.config.js", "vitest.config.ts", "playwright.config.ts", "cypress.config.ts", "karma.conf.js"}):
        return False
    for i, part in enumerate(parts[:-1]):
        if part == "env" and i > 0 and lower_parts[i - 1] in {"config", "configs"}:
            # Application environment configuration, e.g. NodeGoat config/env.
            continue
        if part == "plugins" and i > 0 and lower_parts[i - 1] == "src":
            # First-party source plugins, not bundled public/plugins assets.
            continue
        if part in {"vendor", "plugins"} and any(
            source_root in parts[:i] for source_root in ("java", "kotlin")
        ):
            # Java package names can describe first-party business concepts,
            # e.g. Broadleaf's common/vendor/service package.
            continue
        if part in SKIP_DIRS or part.endswith(".egg-info"):
            return False
    name = parts[-1]
    if name in SKIP_NAMES or name.endswith(SKIP_SUFFIXES):
        return False
    if name in VENDORED_LIB_NAMES and len(parts) > 1 and parts[-2] in ASSET_DIRS:
        return False
    return name.endswith(exts)


def repo_loc(repo_dir: Path, language: str = "python", commit: str | None = None) -> int:
    """LOC for one repo. Reads the pinned commit's tree when possible."""
    exts = LANG_EXTS.get(language.lower(), LANG_EXTS["python"])
    if commit and (repo_dir / ".git").exists():
        ls = subprocess.run(
            ["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", commit],
            capture_output=True, text=True,
        )
        if ls.returncode == 0:
            total = 0
            for rel in ls.stdout.splitlines():
                if not _wanted(rel, exts):
                    continue
                blob = subprocess.run(
                    ["git", "-C", str(repo_dir), "show", f"{commit}:{rel}"],
                    capture_output=True,
                )
                if blob.returncode != 0:
                    continue
                total += loc_of_text(blob.stdout.decode("utf-8", errors="ignore"), Path(rel).suffix)
            if total == 0 and "xvna.zip" in ls.stdout.splitlines():
                # XVNA's pinned repository contains only the application ZIP.
                blob = subprocess.run(
                    ["git", "-C", str(repo_dir), "show", f"{commit}:xvna.zip"],
                    capture_output=True,
                )
                if blob.returncode == 0:
                    with zipfile.ZipFile(io.BytesIO(blob.stdout)) as archive:
                        for name in archive.namelist():
                            if _wanted(name, exts) and not name.endswith("/"):
                                total += loc_of_text(
                                    archive.read(name).decode("utf-8", errors="ignore"),
                                    Path(name).suffix,
                                )
            return total
    total = 0
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        if not _wanted(str(p.relative_to(repo_dir)), exts):
            continue
        if p.suffix == ".py":
            total += code_loc(p)
        else:
            try:
                total += c_style_loc(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
    return total


def gt_meta(repo: str) -> tuple[str, str | None]:
    gt_path = GT / repo / "ground-truth.json"
    if not gt_path.exists():
        return "python", None
    gt = json.loads(gt_path.read_text())
    return (gt.get("language") or "python"), gt.get("commit_sha")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="*", help="specific repo names (default: all under repos/)")
    ap.add_argument("--glob", help="select repos by glob, e.g. 'vc-*'")
    ap.add_argument("--repos-root", type=Path, default=REPOS,
                    help="source checkout directory (default: benchmark repos/)")
    ap.add_argument("--write", action="store_true", help="write Java/JVM `loc` into ground truth")
    ap.add_argument("--write-non-java", action="store_true",
                    help="also overwrite legacy Python and TS/JS GT LOC values")
    args = ap.parse_args()

    if args.repos:
        repo_dirs = [args.repos_root / r for r in args.repos]
    elif args.glob:
        repo_dirs = sorted(args.repos_root.glob(args.glob))
    else:
        repo_dirs = sorted(d for d in args.repos_root.iterdir() if d.is_dir())

    total = 0
    written = 0
    for d in repo_dirs:
        if not d.is_dir():
            print(f"SKIP {d.name} (no source dir under repos/)")
            continue
        language, commit = gt_meta(d.name)
        loc = repo_loc(d, language, commit)
        total += loc
        note = ""
        if args.write and (language.lower() == "java" or args.write_non_java):
            gt_path = GT / d.name / "ground-truth.json"
            if gt_path.exists():
                gt = json.loads(gt_path.read_text())
                gt["loc"] = loc
                gt_path.write_text(json.dumps(gt, indent=2, ensure_ascii=False) + "\n")
                written += 1
                note = "  -> wrote loc to ground-truth.json"
            else:
                note = "  (no ground-truth.json; not written)"
        elif args.write:
            note = "  (legacy non-Java GT LOC preserved)"
        print(f"{d.name:52s} {loc:7d}{note}")
    print(f"\nTOTAL code LOC: {total:,} across {len(repo_dirs)} repos"
          + (f"  ({written} GT files updated)" if args.write else ""))


if __name__ == "__main__":
    main()
