#!/usr/bin/env python3
"""Fill in the paper PDF's empty /Title, /Author, /Subject and /Keywords.

``main.tex`` now passes these to hyperref (``\\hypersetup{pdftitle=...}``), so
any future ``make paper`` produces them directly and this script is unnecessary.
It exists for the already-compiled, already-published PDF: the metadata is baked
into the binary at compile time, so editing the .tex cannot retroactively fix the
copy served at realvuln.com/assets/realvuln-paper.pdf. With an empty /Title,
search engines fall back to the filename as the result headline.

Rebuilding with pdflatex would regenerate the whole document from current data
and figures, which risks changing the rendered content of a paper that is already
cited. So this writes an **incremental update** instead: a revised Info object
and a new cross-reference stream are *appended*, and every original byte is left
untouched. The rendered pages are guaranteed identical because the page objects
are never rewritten.

Only the four empty fields are filled; /Producer, the dates and PTEX.Fullbanner
are carried over verbatim. Idempotent: a PDF that already has a title is skipped.

    python3 paper/scripts/set_pdf_metadata.py --dry-run
    python3 paper/scripts/set_pdf_metadata.py
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The compiled paper, plus the hosted copies it is mirrored into. site/assets is
# the source the build copies from; reports/assets is what the Worker serves.
MASTER = ROOT / "paper" / "main.pdf"
MIRRORS = (
    ROOT / "site" / "assets" / "realvuln-paper.pdf",
    ROOT / "reports" / "assets" / "realvuln-paper.pdf",
)

# Must match \hypersetup in paper/main.tex so a future rebuild is a no-op diff.
TITLE = "RealVuln: An Open Benchmark for Evaluating Security Scanners on Real-World Code"
AUTHOR = "Faizan Raza; John Pellew"
SUBJECT = "Security scanner benchmarking; static analysis; vulnerability detection"
KEYWORDS = (
    "RealVuln, benchmark, SAST, vulnerability detection, "
    "LLM security scanners, F3 score"
)


def pdf_string(s: str) -> bytes:
    r"""Encode a PDF literal string: escape \, ( and ), and require ASCII.

    Non-ASCII would need a UTF-16BE string with a BOM; all metadata here is
    ASCII, so this refuses rather than silently mangling anything else.
    """
    if not s.isascii():
        raise ValueError(f"non-ASCII metadata needs UTF-16BE encoding: {s!r}")
    for ch, esc in (("\\", r"\\"), ("(", r"\("), (")", r"\)")):
        s = s.replace(ch, esc)
    return f"({s})".encode("ascii")


def parse_xref_stream_dict(data: bytes) -> tuple[int, dict[str, str]]:
    """Return (startxref offset, key->raw value) for the trailing xref stream.

    Only the handful of trailer keys needed to write a valid incremental update
    are read; this is not a general PDF parser.
    """
    m = re.search(rb"startxref\s+(\d+)\s*%%EOF\s*$", data)
    if not m:
        raise SystemExit("no startxref/%%EOF found — not a well-formed PDF")
    start = int(m.group(1))
    head = data[start : start + 2048]
    if b"/Type /XRef" not in head and b"/Type/XRef" not in head:
        raise SystemExit(
            "trailing xref is not a cross-reference stream; this script only "
            "handles the PDF 1.5+ form that pdfTeX emits here"
        )
    fields: dict[str, str] = {}
    for key in ("Root", "Info", "ID", "W", "Size"):
        km = re.search(rb"/" + key.encode() + rb"\s*(\[[^]]*\]|[^/>\n]+)", head)
        if km:
            fields[key] = km.group(1).decode("latin-1").strip()
    return start, fields


def build_update(data: bytes) -> bytes | None:
    """Return the bytes to append, or None if the PDF already has a title."""
    prev, tr = parse_xref_stream_dict(data)

    if tr.get("W", "").replace(" ", "") not in ("[131]",):
        raise SystemExit(f"unexpected /W {tr.get('W')!r}; refusing to guess widths")

    info_ref = re.match(r"(\d+)", tr.get("Info", ""))
    if not info_ref:
        raise SystemExit("trailer has no /Info reference to update")
    info_num = int(info_ref.group(1))
    # Take the LAST definition of the object, not the first: this script appends
    # incremental updates, so after one run the file holds both the original
    # (empty) Info object and the revised one, and a reader resolves the latest.
    # Matching the first would re-patch an already-patched PDF on every run.
    revisions = list(
        re.finditer(
            rb"\n" + str(info_num).encode() + rb" 0 obj\n(<<.*?>>)\nendobj\n",
            data,
            re.S,
        )
    )
    if not revisions:
        raise SystemExit(f"could not locate Info object {info_num}")
    body = revisions[-1].group(1).decode("latin-1")

    if re.search(r"/Title\s*\((?!\s*\))", body):
        return None  # already titled — nothing to do

    for key, val in (
        ("Title", TITLE),
        ("Author", AUTHOR),
        ("Subject", SUBJECT),
        ("Keywords", KEYWORDS),
    ):
        new = "/" + key + " " + pdf_string(val).decode("latin-1")
        body, n = re.subn(rf"/{key}\s*\(\s*\)", lambda _m: new, body, count=1)
        if not n:
            raise SystemExit(f"no empty /{key} to fill in Info object")

    # Append: the revised Info object, then an xref stream describing both it and
    # itself, chained to the existing table via /Prev.
    out = bytearray()
    info_off = len(data)
    out += f"\n{info_num} 0 obj\n".encode() + body.encode("latin-1") + b"\nendobj\n"

    xref_num = int(tr["Size"])  # first free object number
    xref_off = len(data) + len(out)

    def entry(offset: int) -> bytes:
        return b"\x01" + offset.to_bytes(3, "big") + b"\x00"

    payload = entry(info_off) + entry(xref_off)
    out += (
        f"{xref_num} 0 obj\n<<\n/Type /XRef\n"
        f"/Index [{info_num} 1 {xref_num} 1]\n"
        f"/Size {xref_num + 1}\n/W [1 3 1]\n"
        f"/Root {tr['Root']}\n/Info {info_num} 0 R\n/ID {tr['ID']}\n"
        f"/Prev {prev}\n/Length {len(payload)}\n>>\nstream\n".encode()
        + payload
        + f"\nendstream\nendobj\nstartxref\n{xref_off}\n%%EOF\n".encode()
    )
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report without writing")
    args = ap.parse_args()

    data = MASTER.read_bytes()
    update = build_update(data)
    if update is None:
        print(f"{MASTER.name}: already has a /Title — nothing to do")
        return

    print(f"{MASTER.name}: appending {len(update)} bytes ({len(data)} preserved)")
    if args.dry_run:
        print("dry run — no files written")
        return

    MASTER.write_bytes(data + update)
    for dst in MIRRORS:
        if dst.is_file():
            shutil.copy2(MASTER, dst)
            print(f"  mirrored -> {dst.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
