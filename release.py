#!/usr/bin/env python3
"""Freeze the current built site as an immutable, citable version snapshot.

The live site is served by a single Cloudflare Worker out of ``reports/`` with
the *latest* release at the root (``realvuln.com/``) and every past release
frozen under ``reports/v/<version>/`` (``realvuln.com/v/<version>/``). A frozen
snapshot is written once and never regenerated, so a URL printed in the paper
keeps meaning the same thing after later releases ship.

Typical flow for a release::

    make dashboard                 # rescore + build the new site into reports/
    python release.py 2.0.0        # freeze reports/ root -> reports/v/2.0.0/
    # review, then deploy reports/ with wrangler

This script:
  1. Refuses to overwrite an existing ``reports/v/<version>/`` (use --force).
  2. Copies the canonical site files from ``reports/`` root into the snapshot.
  3. Injects an "archived release" banner into the snapshot's HTML.
  4. Regenerates ``reports/versions.json`` from every frozen snapshot, marking
     the requested version (or the highest semver) as ``latest``.

Run with ``--check`` to (re)build only ``versions.json`` from existing
snapshots without freezing anything.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
VERSIONS_DIR = REPORTS / "v"

# Files/dirs at reports/ root that belong to a self-contained site snapshot.
# Everything else at the root (wrangler.jsonc, robots.txt, sitemap.xml,
# versions.json, .deploy-trigger, the v/ tree itself) is a root-only concern
# and is deliberately excluded.
SNAPSHOT_GLOBS = ("*.html", "*.js", "*.css", "*.json")
SNAPSHOT_DIRS = ("scanners",)
ROOT_ONLY = {"wrangler.jsonc", "robots.txt", "sitemap.xml", "versions.json"}

BANNER_MARKER = "RV-ARCHIVE-BANNER"


def banner_html(version: str) -> str:
    return (
        f"<!-- {BANNER_MARKER} -->\n"
        '<div style="background:#3a2e12;color:#f0e6d2;border-bottom:1px solid #cfa45c;'
        'font:500 13px/1.5 system-ui,sans-serif;padding:8px 16px;text-align:center">'
        "You are viewing an <strong>archived release</strong> — RealVuln "
        f"<strong>v{version}</strong>. "
        '<a href="https://realvuln.com" style="color:#cfa45c;font-weight:700;'
        'text-decoration:underline">View the latest benchmark &rarr;</a>'
        "</div>\n"
    )


def inject_banner(text: str, version: str) -> str:
    if BANNER_MARKER in text or "<body>" not in text:
        return text
    return text.replace("<body>", "<body>\n" + banner_html(version), 1)


def semver_key(v: str) -> tuple:
    parts = re.split(r"[.\-+]", v)
    return tuple(int(p) if p.isdigit() else 0 for p in parts[:3])


def snapshot_files(src: Path) -> list[Path]:
    out: list[Path] = []
    for pat in SNAPSHOT_GLOBS:
        out += [p for p in src.glob(pat) if p.is_file() and p.name not in ROOT_ONLY]
    return out


def freeze(version: str, force: bool) -> None:
    dest = VERSIONS_DIR / version
    if dest.exists():
        if not force:
            raise SystemExit(
                f"refusing to overwrite existing snapshot {dest} "
                f"(a frozen release is immutable; pass --force only if you are "
                f"certain it was never published)"
            )
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    copied = 0
    for f in snapshot_files(REPORTS):
        text_dst = dest / f.name
        if f.suffix == ".html":
            text_dst.write_text(inject_banner(f.read_text(), version))
        else:
            shutil.copy2(f, text_dst)
        copied += 1
    for d in SNAPSHOT_DIRS:
        srcd = REPORTS / d
        if srcd.is_dir():
            dstd = dest / d
            shutil.copytree(srcd, dstd)
            for html in dstd.glob("*.html"):
                html.write_text(inject_banner(html.read_text(), version))
            copied += sum(1 for _ in dstd.rglob("*") if _.is_file())
    print(f"froze {copied} files into {dest.relative_to(ROOT)}")


def snapshot_meta(version_dir: Path) -> dict:
    version = version_dir.name
    meta: dict = {"version": version, "url": f"https://realvuln.com/v/{version}/"}
    dj = version_dir / "dashboard.json"
    if dj.is_file():
        d = json.loads(dj.read_text())
        meta.update(
            {
                "release_date": (d.get("generated_at") or "")[:10],
                "manifest_hash": d.get("ground_truth_content_hash"),
                "prompt_version": d.get("default_prompt_version"),
                "repos": len(d.get("repos", [])),
                "scanners": len(d.get("scanners", [])),
            }
        )
    return meta


def build_versions_json(latest: str | None = None) -> dict:
    snaps = sorted(
        (p for p in VERSIONS_DIR.iterdir() if p.is_dir()),
        key=lambda p: semver_key(p.name),
        reverse=True,
    )
    versions = [snapshot_meta(p) for p in snaps]
    if latest is None and versions:
        latest = versions[0]["version"]
    for v in versions:
        v["latest"] = v["version"] == latest
    payload = {"latest": latest, "versions": versions}
    (REPORTS / "versions.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote reports/versions.json (latest={latest}, {len(versions)} versions)")
    return payload


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("version", nargs="?", help="version to freeze, e.g. 2.0.0")
    ap.add_argument("--force", action="store_true", help="overwrite an existing snapshot (dangerous)")
    ap.add_argument("--check", action="store_true", help="only rebuild versions.json from existing snapshots")
    ap.add_argument("--latest", help="explicit version to mark as latest in versions.json")
    args = ap.parse_args()

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)

    if args.check:
        build_versions_json(args.latest)
        return

    if not args.version:
        ap.error("a version is required unless --check is given")

    freeze(args.version, args.force)
    build_versions_json(args.latest or args.version)


if __name__ == "__main__":
    main()
