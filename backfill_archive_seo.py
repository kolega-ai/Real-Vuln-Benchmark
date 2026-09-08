#!/usr/bin/env python3
"""Bring every frozen snapshot's <head> up to what release.py emits today.

``release.py`` writes a ``noindex,follow`` robots tag into every frozen snapshot
(see ``release.py:archive_seo_html``). Snapshots frozen before that — v1.0.0 and
v2.0.0 — shipped the live pages' ``<title>`` and ``<meta description>``
verbatim and so compete with the live site for the same queries.

It also repairs snapshots tagged by an *older* revision of release.py, which
paired the noindex with a ``rel="canonical"``. That combination is what Search
Console was reporting as "Duplicate without user-selected canonical": Google
reads noindex and canonical as conflicting instructions and discards the
canonical, and on 53 snapshot pages it pointed at a retired scanner URL that no
longer resolves anyway. ``release.py:inject_archive_seo`` now strips any
canonical it finds regardless of whether the page is already tagged, so a rerun
here is what removes them.

A frozen release is immutable, and this script deliberately keeps it that way in
every sense that matters: it touches only ``<head>`` metadata, the ``<title>``
prefix and the href of the paper-PDF link. No score, table, dataset figure or
``dashboard.json`` is read or written, so the published numbers and every hash
over them are untouched. URLs stay served, so citations keep resolving.

Idempotent — a page is rewritten only when the prepared HTML actually differs,
so reruns settle to "0 changed" once every snapshot is current.

    python backfill_archive_seo.py --dry-run   # report what would change
    python backfill_archive_seo.py             # apply
"""

from __future__ import annotations

import argparse
from pathlib import Path

from release import VERSIONS_DIR, prepare_snapshot_html

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
        text = page.read_text()
        new = prepare_snapshot_html(text, version)
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
