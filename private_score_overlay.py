"""Merge published private receipts into public dashboard aggregates.

Only counts and repository names cross this boundary. Ground-truth rows and
submitted findings stay in the private scoring service.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path


RECEIPT_SCANNERS = {
    "kolega-python-large-official": "kolega-devsec-max-v0.1.0",
    "gpt-daybreak-blue-codex-cli": "gpt-daybreak-blue-codex-cli",
    "deepseek-v4.1-flash-agentic-v1": "deepseek-v4.1-flash-agentic-v1",
    "claude-sonnet-5-cc-agentic-v1": "claude-sonnet-5-cc-agentic-v1",
}
REPOS = ("airflow", "netbox", "odoo", "saleor", "sentry")
TABS = ("all", "python", "intentional", "python:intentional")
AUTHORITY = "large-five-v1.0.0"
AUTHORITY_SHA256 = "0feaa1f936e69d655ac5e520b8b57c5193c0b440c0896601de5199369710f414"
CONTRACT = "python-large-five-span-v1"
OFFICIAL_RUNS = {
    "kolega-python-large-official": "bd2cab542e0041e788e4cc6b480196f2",
    "gpt-daybreak-blue-codex-cli": "a77299a5bf3f47caada1993f6a0bd94b",
    "deepseek-v4.1-flash-agentic-v1": "53e78122c76242bd9d3d7c23eaf9ac95",
    "claude-sonnet-5-cc-agentic-v1": "ac16d907d76f4b9ebdde1537f52837d8",
}


def _metrics(row: dict) -> None:
    tp, fp, fn = (int(row[k]) for k in ("tp", "fp", "fn"))
    row["precision"] = round(tp / (tp + fp), 4) if tp + fp else 0
    row["recall"] = round(tp / (tp + fn), 4) if tp + fn else 0
    row["f2_score"] = round(100 * 5 * tp / (5 * tp + 4 * fn + fp), 1) if 5 * tp + 4 * fn + fp else 0
    row["f3_score"] = round(100 * 10 * tp / (10 * tp + 9 * fn + fp), 2) if 10 * tp + 9 * fn + fp else 0
    # The private receipt has no CVSS or severity breakdown. A mixed-corpus
    # weighted score would be false precision, so do not inherit public values.
    for key in ("cvss_precision", "cvss_recall", "cvss_f3_score"):
        row.pop(key, None)


def _validated_totals(receipt: dict) -> dict:
    scanner = receipt.get("scanner")
    if scanner not in OFFICIAL_RUNS or (receipt.get("authority"), receipt.get("authority_sha256"),
            receipt.get("contract"), receipt.get("run_id")) != (
            AUTHORITY, AUTHORITY_SHA256, CONTRACT, OFFICIAL_RUNS[scanner]):
        raise ValueError("Unexpected private score authority, contract, or run")
    if not receipt.get("published") or set(receipt.get("repo_scores", {})) != set(REPOS):
        raise ValueError("Private receipt must be published and contain exactly five repositories")
    totals = {k: sum(int(r[k]) for r in receipt["repo_scores"].values()) for k in ("tp", "fp", "fn", "gt")}
    if any(totals[k] != receipt[k] for k in totals) or totals["tp"] + totals["fn"] != totals["gt"]:
        raise ValueError("Private receipt aggregate does not match repository counts")
    if round(10 * totals["tp"] / (10 * totals["tp"] + totals["fp"] + 9 * totals["fn"]), 4) != receipt.get("f3"):
        raise ValueError("Private receipt F3 does not match its counts")
    if totals["gt"] != 1944:
        raise ValueError("Private receipt GT count changed")
    return totals


def apply_private_receipts(data: dict, receipts: list[dict]) -> dict:
    if {r.get("scanner") for r in receipts} != set(RECEIPT_SCANNERS) or len(receipts) != len(RECEIPT_SCANNERS):
        raise ValueError("Exactly one receipt is required for each released scanner")
    totals_by_slug = {RECEIPT_SCANNERS[r["scanner"]]: _validated_totals(r) for r in receipts}
    runs_by_slug = {RECEIPT_SCANNERS[r["scanner"]]: r["run_id"] for r in receipts}
    if data.get("private_score_receipt"):
        raise ValueError("Private receipt already applied")

    out = copy.deepcopy(data)
    out["private_score_receipt"] = OFFICIAL_RUNS["kolega-python-large-official"]
    out["private_score_receipts"] = runs_by_slug
    out["private_score_gt"] = 1944
    out["repos"].extend(f"private-{repo}" for repo in REPOS)
    for tab in TABS:
        out["tab_repos"][tab].extend(f"private-{repo}" for repo in REPOS)

    for tab in TABS:
        groups = [out["aggregates"]] if tab == "all" else [out["tab_aggregates"][tab]]
        if tab == "all" and "all" in out.get("tab_aggregates", {}):
            groups.append(out["tab_aggregates"]["all"])
        if tab == "intentional" and "intentional" in out.get("source_aggregates", {}):
            groups.append(out["source_aggregates"]["intentional"])
        for ag in groups:
            for slug, a in ag.items():
                a["repos_total"] += len(REPOS)
                a["private_gt_included"] = True
                cov = a.get("language_coverage") or {}
                if "python" in cov:
                    cov["python"][1] += len(REPOS)
                    if slug in totals_by_slug:
                        cov["python"][0] += len(REPOS)
                if slug in totals_by_slug:
                    a["repos_scored"] += len(REPOS)
                    a["private_receipt"] = runs_by_slug[slug]
                    for metric in ("micro", "strict_micro"):
                        for key in ("tp", "fp", "fn"):
                            a[metric][key] += totals_by_slug[slug][key]
                        _metrics(a[metric])
                else:
                    a["strict_micro"]["fn"] += 1944
                    _metrics(a["strict_micro"])
                # Receipts do not carry severity, weighted or per-scan cost data.
                a["per_severity"] = {}
                a["cost"] = {}
    return out


def load_and_apply(data: dict, receipt_path: Path) -> dict:
    receipts = json.loads(receipt_path.read_text())
    return apply_private_receipts(data, receipts if isinstance(receipts, list) else [receipts])
