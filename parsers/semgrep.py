"""Parser for Semgrep/Opengrep JSON output.

Covers Semgrep, Opengrep, and any scanner that conforms to the
Semgrep --json output format.
"""
from __future__ import annotations

import json
import re

from .base import BaseParser, NormalisedFinding, normalise_path


class SemgrepParser(BaseParser):
    """Parse Semgrep-format JSON output."""

    scanner_name: str = "semgrep"

    def __init__(self, scanner_slug: str = "semgrep"):
        self.scanner_name = scanner_slug

    def parse(self, file_path: str) -> list[NormalisedFinding]:
        with open(file_path) as f:
            data = json.load(f)

        findings = []
        for result in data.get("results", []):
            path = normalise_path(result.get("path", ""))
            if not path:
                continue

            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            # CWEs may be a list or a single string
            raw_cwes = metadata.get("cwe", [])
            if isinstance(raw_cwes, str):
                raw_cwes = [raw_cwes]

            severity = (extra.get("severity") or "").lower() or None

            finding_id = metadata.get("finding_id")

            # Alternative locations for attack-chain scanners
            raw_alts = metadata.get("alternative_locations", [])
            alt_locs = [
                (normalise_path(a["file"]), a["line"])
                for a in raw_alts
                if isinstance(a, dict) and "file" in a and "line" in a
            ] or None

            for raw_cwe in raw_cwes:
                cwe = _normalise_cwe(raw_cwe)
                if not cwe:
                    continue
                findings.append(
                    NormalisedFinding(
                        file=path,
                        cwe=cwe,
                        line=result.get("start", {}).get("line"),
                        function=None,
                        severity=severity,
                        rule_id=result.get("check_id"),
                        message=extra.get("message"),
                        scanner=self.scanner_name,
                        finding_id=finding_id,
                        alternative_locations=alt_locs,
                    )
                )

        return findings


def _normalise_cwe(raw: str) -> str | None:
    """Extract 'CWE-89' from formats like 'CWE-89: Improper Neutralization...'"""
    match = re.match(r"(CWE-\d+)", str(raw))
    return match.group(1) if match else None
