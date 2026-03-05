"""Parser registry."""
from __future__ import annotations

from .base import BaseParser
from .semgrep import SemgrepParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "semgrep": SemgrepParser,
    "opengrep": SemgrepParser,
    "kolega.dev-t3-sonnet-4-6-p1-r0": SemgrepParser,
    "kolega.dev-t2-sonnet-4-6-p1": SemgrepParser,
    "kolega.dev-t3-sonnet-4-6-p1": SemgrepParser,
    "kolega.dev-t3-sonnet-4-6-p3": SemgrepParser,
    "kolega.dev-t3-sonnet-4-6-p4": SemgrepParser,
    "kolega.dev-t3-gpt-5-2-p4": SemgrepParser,
    "kolega.dev-t3-gemini-3.1-pro-p4-r1": SemgrepParser,
    "kolega.dev-t3-gemini-3.1-pro-p4-r2": SemgrepParser,
    "kolega.dev-t3-opus-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t3-opus-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t3-opus-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t2-sonnet-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t2-sonnet-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t2-sonnet-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t4-sonnet-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t4-sonnet-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t4-sonnet-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t5-sonnet-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t5-sonnet-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t5-sonnet-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t6-c1-sonnet-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t6-c1-sonnet-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t6-c1-sonnet-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t6-c2-sonnet-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t6-c2-sonnet-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t6-c2-sonnet-4-6-p4-r3": SemgrepParser,
    "kolega.dev-t6-c2-gpt-5-2-p4-r1": SemgrepParser,
    "kolega.dev-t6-c2-gpt-5-2-p4-r2": SemgrepParser,
    "kolega.dev-t6-c2-gpt-5-2-p4-r3": SemgrepParser,
    "kolega.dev-t6-c2-gemini-3.1-pro-p4-r1": SemgrepParser,
    "kolega.dev-t6-c2-gemini-3.1-pro-p4-r2": SemgrepParser,
    "kolega.dev-t6-c2-gemini-3.1-pro-p4-r3": SemgrepParser,
    "kolega.dev-t6-c2-opus-4-6-p4-r1": SemgrepParser,
    "kolega.dev-t6-c2-opus-4-6-p4-r2": SemgrepParser,
    "kolega.dev-t6-c2-opus-4-6-p4-r3": SemgrepParser,
    "kolega.dev-rescan-p4-feedback": SemgrepParser,
    "kolega.dev-rescan-p4-feedback-v2": SemgrepParser,
    "kolega.dev-rescan-p4-feedback-v3-r1": SemgrepParser,
    "kolega.dev-rescan-p4-feedback-v3-r2": SemgrepParser,
    "kolega.dev-p7-r1": SemgrepParser,
    "kolega.dev-p7-r2": SemgrepParser,
    "kolega.dev-p7-r3": SemgrepParser,
    "kolega.dev-p8-r1": SemgrepParser,
    "kolega.dev-p8-r2": SemgrepParser,
    "kolega.dev-p8-r3": SemgrepParser,
    "kolega.dev-p9-r1": SemgrepParser,
    "kolega.dev-p9-r2": SemgrepParser,
    "kolega.dev-p9-r3": SemgrepParser,
    "kolega.dev-snapshot-r1": SemgrepParser,
    "kolega.dev-snapshot-r2": SemgrepParser,
    "kolega.dev-snapshot-r3": SemgrepParser,
    "sonarqube": SemgrepParser,
    "our-scanner": SemgrepParser,
}


def get_parser(scanner_slug: str) -> BaseParser:
    """Return an instantiated parser for the given scanner slug."""
    cls = PARSER_REGISTRY.get(scanner_slug)
    if not cls:
        raise ValueError(
            f"No parser for '{scanner_slug}'. "
            f"Available: {list(PARSER_REGISTRY.keys())}"
        )
    return cls(scanner_slug=scanner_slug)
