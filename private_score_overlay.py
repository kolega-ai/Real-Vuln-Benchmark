"""Merge published private receipts into public dashboard aggregates.

Receipts carry only counts and repository names. Separately recorded run-cost
aggregates contain no ground-truth rows or submitted findings.
"""

from __future__ import annotations

import copy
import json
import re
from urllib.request import urlopen
from pathlib import Path


RECEIPT_API = "https://results.realvuln.com"
RECEIPT_ID = re.compile(r"[0-9a-f]{32}\Z")
REPOS = ("airflow", "netbox", "odoo", "saleor", "sentry")
PRIVATE_REPO_LOC = {
    "airflow": 639003, "netbox": 291915, "odoo": 680640,
    "saleor": 262936, "sentry": 816371,
}
# USD for the five accepted submissions, excluding failed or invalid attempts.
# Kolega: repository costs supplied by its operator on 2026-11-17 from external
# monitoring. The other three: saved per-repository run metrics for the exact
# submitted findings (private comparison, 2026-11-12). These are model/API
# equivalents, not a claim about the total billed campaign spend.
PRIVATE_RUN_COSTS = {
    "kolega-devsec-max-v0.1.0": {
        "airflow": 0.66, "netbox": 0.0438, "odoo": 0.0188,
        "saleor": 0.9079, "sentry": 0.0505,
    },
    "gpt-daybreak-blue-codex-cli": {
        "airflow": 5.766969, "netbox": 17.826306, "odoo": 10.435107,
        "saleor": 5.671202, "sentry": 16.085008,
    },
    "deepseek-v4.1-flash-agentic-v1": {
        "airflow": 0.448376142, "netbox": 0.01676523, "odoo": 0.008806566,
        "saleor": 0.43794219, "sentry": 0.025449306,
    },
    "claude-sonnet-5-cc-agentic-v1": {
        "airflow": 6.9037931, "netbox": 2.3976345, "odoo": 2.2759881,
        "saleor": 0.5518896, "sentry": 1.7877198,
    },
}
TABS = ("all", "python", "intentional", "python:intentional")
AUTHORITY = "large-five-cwe-v1.0.0"
AUTHORITY_SHA256 = "067f9e1f3aa3e416a50b60f6136c35ffc5dead1abc8b2cb3190905b0c7fe130d"
CONTRACT = "python-large-five-cwe-span-v2"


def attached_receipt_ids(submissions_dir: Path) -> dict[str, str]:
    """Read optional receipt IDs attached to public scanner submissions."""
    result = {}
    for path in sorted(submissions_dir.glob("*.json")):
        data = json.loads(path.read_text())
        if (not isinstance(data, dict) or set(data) != {"scanner", "private_receipt_id"}
                or data["scanner"] != path.stem or not isinstance(data["private_receipt_id"], str)
                or not RECEIPT_ID.fullmatch(data["private_receipt_id"])):
            raise ValueError(f"Invalid private receipt attachment: {path}")
        result[path.stem] = data["private_receipt_id"]
    return result


def resolve_attached_receipts(submissions_dir: Path, snapshot_path: Path,
                              *, fetch=None) -> list[dict]:
    """Fetch service-issued aggregates; keep only verified historical repo totals."""
    ids = attached_receipt_ids(submissions_dir)
    snapshot = json.loads(snapshot_path.read_text()) if snapshot_path.exists() else []
    previous = {row["run_id"]: row for row in snapshot}
    fetch = fetch or (lambda receipt_id: json.load(urlopen(
        f"{RECEIPT_API}/receipts/{receipt_id}", timeout=10)))
    receipts = []
    previous_order = [row["scanner"] for row in snapshot if row.get("scanner") in ids]
    order = previous_order + sorted(set(ids) - set(previous_order))
    for scanner in order:
        receipt_id = ids[scanner]
        live = fetch(receipt_id)
        if not isinstance(live, dict) or live.get("run_id") != receipt_id or live.get("scanner") != scanner:
            raise ValueError(f"Receipt does not belong to scanner: {scanner}")
        row = dict(live)
        cached = previous.get(receipt_id)
        if cached and "repo_scores" in cached:
            if any(cached.get(key) != live.get(key) for key in
                   ("scanner", "authority", "authority_sha256", "contract", "tp", "fp", "fn", "gt", "f3")):
                raise ValueError(f"Cached repository totals disagree with service: {scanner}")
            row["repo_scores"] = cached["repo_scores"]
        _validated_totals(row)
        receipts.append(row)
    return receipts


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
    if (receipt.get("authority"), receipt.get("authority_sha256"), receipt.get("contract")) != (
            AUTHORITY, AUTHORITY_SHA256, CONTRACT):
        raise ValueError("Unexpected private score authority or contract")
    if not receipt.get("published") or not isinstance(receipt.get("run_id"), str) or not RECEIPT_ID.fullmatch(receipt["run_id"]):
        raise ValueError("Private receipt must be published with a valid ID")
    totals = {k: int(receipt[k]) for k in ("tp", "fp", "fn", "gt")}
    if any(value < 0 for value in totals.values()) or totals["tp"] + totals["fn"] != totals["gt"]:
        raise ValueError("Private receipt aggregate does not match repository counts")
    if "repo_scores" in receipt:
        if set(receipt["repo_scores"]) != set(REPOS):
            raise ValueError("Repository totals must cover exactly five repositories")
        repo_totals = {k: sum(int(r[k]) for r in receipt["repo_scores"].values())
                       for k in ("tp", "fp", "fn", "gt")}
        if totals != repo_totals:
            raise ValueError("Private receipt aggregate does not match repository counts")
    if round(10 * totals["tp"] / (10 * totals["tp"] + totals["fp"] + 9 * totals["fn"]), 4) != receipt.get("f3"):
        raise ValueError("Private receipt F3 does not match its counts")
    if totals["gt"] != 1944:
        raise ValueError("Private receipt GT count changed")
    return totals


def apply_private_receipts(data: dict, receipts: list[dict]) -> dict:
    slugs = [r.get("scanner") for r in receipts]
    if len(set(slugs)) != len(slugs) or any(slug not in data["aggregates"] for slug in slugs):
        raise ValueError("Receipt scanner missing from public results or duplicated")
    totals_by_slug = {r["scanner"]: _validated_totals(r) for r in receipts}
    runs_by_slug = {r["scanner"]: r["run_id"] for r in receipts}
    if data.get("private_score_receipt"):
        raise ValueError("Private receipt already applied")

    out = copy.deepcopy(data)
    out["private_score_receipt"] = runs_by_slug.get("kolega-devsec-max-v0.1.0")
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
                # Receipts do not carry severity or weighted-score data. Preserve
                # public cost for receipt holders so the site can add the separately
                # recorded five-repository run cost. Unscored rows have no full
                # corpus cost and retain a blank cost field.
                a["per_severity"] = {}
                if slug not in totals_by_slug or slug not in PRIVATE_RUN_COSTS:
                    a["cost"] = {}
    return out


def load_and_apply(data: dict, receipt_path: Path) -> dict:
    receipts = json.loads(receipt_path.read_text())
    return apply_private_receipts(data, receipts if isinstance(receipts, list) else [receipts])
