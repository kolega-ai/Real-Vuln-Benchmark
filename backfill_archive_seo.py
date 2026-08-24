#!/usr/bin/env python3
"""Add archive SEO <head> tags to snapshots frozen before release.py emitted them.

``release.py`` now writes a ``noindex,follow`` robots tag and a canonical
pointing at the live equivalent into every frozen snapshot (see
``release.py:archive_seo_html``). Snapshots frozen before that — v1.0.0 and
v2.0.0 — shipped the live pages' ``<title>`` and ``<meta description>``
verbatim and so compete with the live site for the same queries.

A frozen release is immutable, and this script deliberately keeps it that way in
every sense that matters: it touches only ``<head>`` metadata and the ``<title>``
prefix. No score, table, dataset figure or ``dashboard.json`` is read or written,
so the published numbers and every hash over them are untouched. URLs stay
served, so citations keep resolving.

Idempotent — reruns are a no-op once the marker is present.

    python backfill_archive_seo.py --dry-run   # report what would change
    python backfill_archive_seo.py             # apply
"""

from __future__ import annotations

import argparse
from pathlib import Path

from release import SEO_MARKER, VERSIONS_DIR, prepare_snapshot_html

ROOT = Path(__file__).resolve().parent


def snapshot_pages(version_dir: Path) -> list[Path]:
    """Every HTML page in a snapshot, root pages first then scanners/."""
    return sorted(version_dir.glob("*.html")) + sorted(
        version_dir.glob("scanners/*.html")
    )


def backfill(version_dir: Path, dry_run: bool) -> tuple[int, int]:
    version = version_dir.name
    changed = skipped = 0
    for page in snapshot_pages(version_dir):
        rel = page.relative_to(version_dir).as_posix()
        text = page.read_text()
        if SEO_MARKER in text:
            skipped += 1
            continue
        new = prepare_snapshot_html(text, version, rel)
        if new == text:
            skipped += 1
            continue
        if not dry_run:
            page.write_text(new)
        changed += 1
    return changed, skipped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "versions",
        nargs="*",
        help="versions to backfill (default: every frozen snapshot)",
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="report changes without writing"
    )
    args = ap.parse_args()

    if not VERSIONS_DIR.is_dir():
        raise SystemExit(f"no snapshots found at {VERSIONS_DIR}")

    dirs = (
        [VERSIONS_DIR / v for v in args.versions]
        if args.versions
        else sorted(p for p in VERSIONS_DIR.iterdir() if p.is_dir())
    )
    for d in dirs:
        if not d.is_dir():
            raise SystemExit(f"no such snapshot: {d}")
        changed, skipped = backfill(d, args.dry_run)
        verb = "would update" if args.dry_run else "updated"
        print(f"v{d.name}: {verb} {changed} page(s), {skipped} already tagged")


if __name__ == "__main__":
    main()
