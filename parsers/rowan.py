"""Parser for Open Rowan JSON output (`rowan scan -f json`).

Rowan emits absolute file paths and bare integer CWE ids, so both are
converted here to the benchmark's normalised form.
"""
from __future__ import annotations

import json
import re

from .base import BaseParser, NormalisedFinding, normalise_path

# Scans run against repos/{slug}/, so strip everything up to that point.
_REPO_ROOT_RE = re.compile(r"^.*?/repos/[^/]+/")


class RowanParser(BaseParser):
    """Parse Open Rowan JSON output.

    Deliberately does NOT deduplicate co-located findings. Rowan emits the same
    vulnerability under more than one rule id, so deduping is arguably the more
    correct normalisation -- but SemgrepParser (which every other scanner in
    this benchmark uses) does not dedupe, and giving one entry a normalisation
    the others do not get is worth ~0.7 F2. Symmetry beats correctness here.
    """

    scanner_name: str = "rowan"

    def __init__(self, scanner_slug: str = "rowan"):
        self.scanner_name = scanner_slug

    def parse(self, file_path: str) -> list[NormalisedFinding]:
        with open(file_path) as f:
            data = json.load(f)

        findings = []
        for result in data.get("findings", []):
            path = normalise_path(_REPO_ROOT_RE.sub("", result.get("file", "")))
            if not path:
                continue

            severity = (result.get("severity") or "").lower() or None

            for raw_cwe in result.get("cwe") or []:
                findings.append(
                    NormalisedFinding(
                        file=path,
                        cwe=f"CWE-{raw_cwe}",
                        line=result.get("line"),
                        function=None,
                        severity=severity,
                        rule_id=result.get("rule_id"),
                        message=result.get("message"),
                        scanner=self.scanner_name,
                    )
                )

        return findings
