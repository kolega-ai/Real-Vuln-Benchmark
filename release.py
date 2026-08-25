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
SEO_MARKER = "RV-ARCHIVE-SEO"
SITE_BASE_URL = "https://realvuln.com"


def archive_seo_html(rel_path: str) -> str:
    """<head> tags that keep a frozen snapshot citable but out of search results.

    A snapshot ships the same title and meta description as the live page it was
    copied from, so left alone the two compete for the same queries — which is
    what was cannibalising the live pages (the /v/1.0.0/ URLs drew impressions
    but effectively no clicks).

    ``noindex`` drops the duplicate from search listings while leaving the URL
    fully served, so a citation printed in the paper keeps resolving. ``follow``
    matters: crawlers still traverse the archive banner's link to the live site,
    so any accumulated authority flows there instead of being stranded. The
    canonical names the live equivalent as the version that should rank.
    """
    live = f"{SITE_BASE_URL}/" if rel_path == "index.html" else f"{SITE_BASE_URL}/{rel_path}"
    return (
        f"<!-- {SEO_MARKER} -->\n"
        '<meta name="robots" content="noindex,follow" />\n'
        f'<link rel="canonical" href="{live}" />\n'
    )


def inject_archive_seo(text: str, version: str, rel_path: str) -> str:
    """Apply archive <head> tags and mark the <title> as an archived version.

    Any canonical inherited from the live build is stripped first — it would
    otherwise point the snapshot at itself. The title prefix is belt-and-braces:
    until a crawler re-reads the page and honours the noindex, an already-listed
    snapshot at least stops presenting itself as the current results.
    """
    if SEO_MARKER in text or "</head>" not in text:
        return text
    text = re.sub(r'\s*<link rel="canonical"[^>]*>', "", text)
    text = text.replace("</head>", archive_seo_html(rel_path) + "</head>", 1)
    return re.sub(
        r"<title>(.*?)</title>",
        lambda m: f"<title>[v{version} archive] {m.group(1)}</title>",
        text,
        count=1,
        flags=re.S,
    )


def relativise_root_links(text: str) -> str:
    """Point root-relative links back inside the snapshot.

    The live pages link the brand and breadcrumb to "/" so they never reference
    the duplicate /index.html. Inside a frozen snapshot that would jump the
    reader out to the current site, which defeats the point of the archive: a
    reader should be able to browse the whole of v1.0.0 as it was. Relative
    links resolve within /v/<version>/, so rewrite them at freeze time.

    The archive banner's explicit link to the live site is absolute and
    unaffected, so leaving the archive stays possible and obvious.
    """
    return text.replace('href="/"', 'href="index.html"')


def prepare_snapshot_html(text: str, version: str, rel_path: str) -> str:
    """All snapshot-only HTML rewrites: banner, SEO tags, in-version links."""
    return relativise_root_links(
        inject_archive_seo(inject_banner(text, version), version, rel_path)
    )


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
            text_dst.write_text(
                prepare_snapshot_html(f.read_text(), version, f.name)
            )
        else:
            shutil.copy2(f, text_dst)
        copied += 1
    for d in SNAPSHOT_DIRS:
        srcd = REPORTS / d
        if srcd.is_dir():
            dstd = dest / d
            shutil.copytree(srcd, dstd)
            for html in dstd.glob("*.html"):
                html.write_text(
                    prepare_snapshot_html(
                        html.read_text(), version, f"{d}/{html.name}"
                    )
                )
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
