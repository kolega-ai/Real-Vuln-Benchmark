"""Merge a published private receipt into public dashboard aggregates.

Only counts and repository names cross this boundary. Ground-truth rows and
submitted findings stay in the private scoring service.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path


SCANNER = "kolega-devsec-max-v0.1.0"
REPOS = ("airflow", "netbox", "odoo", "saleor", "sentry")
TABS = ("all", "python", "intentional", "python:intentional")
AUTHORITY = "large-five-v1.0.0"
AUTHORITY_SHA256 = "0feaa1f936e69d655ac5e520b8b57c5193c0b440c0896601de5199369710f414"
CONTRACT = "python-large-five-span-v1"
OFFICIAL_RUN = "775af0788f2f4f5087c922f85794fa2e"


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


def apply_private_receipt(data: dict, receipt: dict) -> dict:
    if (receipt.get("authority"), receipt.get("authority_sha256"), receipt.get("contract"), receipt.get("run_id")) != (AUTHORITY, AUTHORITY_SHA256, CONTRACT, OFFICIAL_RUN):
        raise ValueError("Unexpected private score authority, contract, or run")
    if not receipt.get("published") or set(receipt.get("repo_scores", {})) != set(REPOS):
        raise ValueError("Private receipt must be published and contain exactly five repositories")
    totals = {k: sum(int(r[k]) for r in receipt["repo_scores"].values()) for k in ("tp", "fp", "fn", "gt")}
    if any(totals[k] != receipt[k] for k in totals) or totals["tp"] + totals["fn"] != totals["gt"]:
        raise ValueError("Private receipt aggregate does not match repository counts")
    if round(10 * totals["tp"] / (10 * totals["tp"] + totals["fp"] + 9 * totals["fn"]), 4) != receipt.get("f3"):
        raise ValueError("Private receipt F3 does not match its counts")
    if data.get("private_score_receipt"):
        raise ValueError("Private receipt already applied")

    out = copy.deepcopy(data)
    out["private_score_receipt"] = receipt["run_id"]
    out["private_score_gt"] = totals["gt"]
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
                cov = a.get("language_coverage") or {}
                if "python" in cov:
                    cov["python"][1] += len(REPOS)
                    if slug == SCANNER:
                        cov["python"][0] += len(REPOS)
                if slug == SCANNER:
                    a["repos_scored"] += len(REPOS)
                    a["private_receipt"] = receipt["run_id"]
                    for metric in ("micro", "strict_micro"):
                        for key in ("tp", "fp", "fn"):
                            a[metric][key] += totals[key]
                        _metrics(a[metric])
                    # Public-only severity and cost are not mixed-corpus facts.
                    a["per_severity"] = {}
                    a["cost"] = {}
                else:
                    a["strict_micro"]["fn"] += totals["gt"]
                    _metrics(a["strict_micro"])
    return out


def load_and_apply(data: dict, receipt_path: Path) -> dict:
    return apply_private_receipt(data, json.loads(receipt_path.read_text()))
