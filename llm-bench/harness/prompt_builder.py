"""Build the system prompt for LLM security auditor runs.

Renders the prompt template with CWE families context and output schema example.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

LLM_BENCH_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = LLM_BENCH_DIR.parent
PROMPT_TEMPLATE_PATH = LLM_BENCH_DIR / "prompts" / "system-prompt.md"


@dataclass(frozen=True)
class PromptInfo:
    """Immutable record of a rendered prompt with its content-hash version."""

    rendered: str
    version_hash: str  # "sha256:XXXXXXXXXXXX"
    template_path: str  # relative path to template used
    label: str  # human label, "" if unset


CWE_FAMILIES_PATH = PROJECT_ROOT / "config" / "cwe-families.json"


def load_cwe_families(path: Path | None = None) -> dict:
    """Load CWE families configuration."""
    p = path or CWE_FAMILIES_PATH
    with open(p) as f:
        return json.load(f)


def format_cwe_families(cwe_families: dict) -> str:
    """Format CWE families as a readable list for the prompt."""
    lines: list[str] = []
    for slug, info in cwe_families.get("families", {}).items():
        label = info["label"]
        cwes = ", ".join(info["cwes"])
        lines.append(f"- **{label}** ({cwes})")
    return "\n".join(lines)


def build_output_schema_example() -> str:
    """Build a concrete example of the expected output JSON."""
    example = {
        "version": "1.0.0",
        "results": [
            {
                "check_id": "python.security.injection.sql-injection",
                "path": "app/views.py",
                "start": {"line": 42, "col": 5, "offset": 1200},
                "end": {"line": 42, "col": 60, "offset": 1255},
                "extra": {
                    "message": "User input from request.GET['query'] is concatenated "
                    "directly into SQL string passed to cursor.execute(). "
                    "This allows SQL injection.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "confidence": "HIGH",
                        "category": "security",
                    },
                },
            }
        ],
    }
    return json.dumps(example, indent=2)


def build_prompt(
    cwe_families: dict | None = None,
    template_path: Path | None = None,
    label: str = "",
) -> PromptInfo:
    """Build the complete system prompt for an LLM security auditor run.

    Args:
        cwe_families: CWE families dict. Loaded from default path if None.
        template_path: Path to prompt template. Uses default if None.
        label: Optional human-readable label for this prompt version.

    Returns:
        PromptInfo with rendered prompt, content hash, and metadata.
    """
    if cwe_families is None:
        cwe_families = load_cwe_families()

    tmpl_path = template_path or PROMPT_TEMPLATE_PATH
    template = tmpl_path.read_text()

    rendered = template.replace("{cwe_families}", format_cwe_families(cwe_families))
    rendered = rendered.replace("{output_schema_example}", build_output_schema_example())

    hex_digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:12]
    return PromptInfo(
        rendered=rendered,
        version_hash=f"sha256:{hex_digest}",
        template_path=str(tmpl_path.relative_to(PROJECT_ROOT)),
        label=label,
    )
