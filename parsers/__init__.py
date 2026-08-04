"""Parser registry."""
from __future__ import annotations

from .base import BaseParser
from .rowan import RowanParser
from .semgrep import SemgrepParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "rowan": RowanParser,
    "semgrep": SemgrepParser,
    "opengrep": SemgrepParser,
    "sonarqube": SemgrepParser,
}


def get_parser(scanner_slug: str) -> BaseParser:
    """Return an instantiated parser for the given scanner slug.

    Falls back to SemgrepParser for unknown slugs, so any scanner
    producing Semgrep-format JSON works without explicit registration.
    """
    cls = PARSER_REGISTRY.get(scanner_slug, SemgrepParser)
    return cls(scanner_slug=scanner_slug)
