"""Base parser interface and normalised finding dataclass."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class NormalisedFinding:
    """Uniform internal representation of a scanner finding."""

    file: str  # Relative path from repo root, forward slashes
    cwe: str  # "CWE-89" format
    line: Optional[int]  # Start line, if available
    function: Optional[str]  # Function name, if available
    severity: Optional[str]  # critical | high | medium | low | info
    rule_id: Optional[str]  # Scanner's own rule identifier
    message: Optional[str]  # Scanner's description
    scanner: str  # Scanner slug, e.g. "semgrep"
    finding_id: Optional[str] = None  # Platform finding ID for linking
    # Alternative locations for scanners that report attack chains.
    # Each entry is (file, line). The matcher tries the primary (file, line)
    # first, then falls back to alternatives. Only one match counts.
    alternative_locations: Optional[list[tuple[str, int]]] = None


def normalise_path(path: str) -> str:
    """Normalise a file path for matching.

    Rules:
    - Backslashes converted to forward slashes
    - Strip any leading ./ or /
    - Relative to repo root
    - Case-sensitive (Linux filesystem semantics)
    """
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path.startswith("/"):
        path = path.lstrip("/")
    return path


class BaseParser(ABC):
    """All parsers implement this interface.

    Adding a scanner = subclass this + register in PARSER_REGISTRY.
    """

    scanner_name: str

    @abstractmethod
    def parse(self, file_path: str) -> list[NormalisedFinding]:
        """Read a scanner output file, return normalised findings."""
        ...
