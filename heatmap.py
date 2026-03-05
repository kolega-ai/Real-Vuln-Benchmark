"""Generate a colored HTML heatmap from a scorecard JSON.

Layout: scanners as rows (best on top), GT test cases as columns.
"""
import json
from pathlib import Path


def main():
    scorecard_path = Path("reports/realvuln-dvpwa/scorecard-2026-02-26.json")
    gt_path = Path("ground-truth/realvuln-dvpwa/ground-truth.json")

    with open(scorecard_path) as f:
        scorecard = json.load(f)
    with open(gt_path) as f:
        gt = json.load(f)

    # Build GT lookup
    gt_info = {}
    for finding in gt["findings"]:
        gt_info[finding["id"]] = {
            "cwe": finding["primary_cwe"],
            "file": finding["file"].split("/")[-1] if finding["file"] else "?",
            "severity": finding["severity"][0].upper(),
            "vuln_class": finding.get("vulnerability_class", ""),
            "is_vulnerable": finding["is_vulnerable"],
        }

    true_vuln_ids = sorted([fid for fid, info in gt_info.items() if info["is_vulnerable"]])
    fp_test_ids = sorted([fid for fid, info in gt_info.items() if not info["is_vulnerable"]])
    all_gt_ids = true_vuln_ids + fp_test_ids

    # Sort scanners by F2 score descending
    scanners_data = scorecard["scanners"]
    sorted_scanners = sorted(
        scanners_data.keys(),
        key=lambda s: scanners_data[s].get("f2_score", 0),
        reverse=True,
    )

    def abbreviate(name):
        return name.replace("kolega.dev-", "")

    # Build per-scanner lookup
    scanner_results = {}
    for scanner_name, sdata in scanners_data.items():
        results = {}
        for detail in sdata.get("details", []):
            gt_id = detail.get("ground_truth_id")
            cls = detail["classification"]
            if gt_id:
                results[gt_id] = cls
        scanner_results[scanner_name] = results

    desc_map = {
        "dvpwa-001": "SQLi student create",
        "dvpwa-002": "XSS review text",
        "dvpwa-003": "XSS student names",
        "dvpwa-004": "XSS course title/desc",
        "dvpwa-005": "XSS courses listing",
        "dvpwa-006": "XSS student detail",
        "dvpwa-007": "autoescape=False",
        "dvpwa-008": "MD5 password hash",
        "dvpwa-009": "CSRF disabled",
        "dvpwa-010": "httponly=False",
        "dvpwa-011": "Error info leak",
        "dvpwa-012": "Missing auth students",
        "dvpwa-013": "Missing auth courses",
        "dvpwa-014": "Session fixation",
        "dvpwa-015": "debug=True",
        "dvpwa-016": "Redis no password",
        "dvpwa-017": "No rate limit login",
        "dvpwa-018": "No rate limit forms",
        "dvpwa-019": "pwd_hash in context",
        "dvpwa-020": "DB DSN credential",
        "dvpwa-021": "No TLS on DB",
        "dvpwa-fp-001": "Safe param (user)",
        "dvpwa-fp-002": "Safe param (review)",
        "dvpwa-fp-003": "Safe param (course)",
        "dvpwa-fp-004": "Escaped template",
    }

    sev_colors = {"C": "#dc2626", "H": "#ea580c", "M": "#ca8a04", "L": "#2563eb"}

    # Compute detection rates
    det_rates = {}
    for gt_id in true_vuln_ids:
        count = sum(1 for s in sorted_scanners if scanner_results[s].get(gt_id) == "TP")
        det_rates[gt_id] = count / len(sorted_scanners)

    html = []
    html.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DVPWA Scanner Coverage Heatmap</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0f172a; color: #e2e8f0; padding: 24px;
  }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  .subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 20px; }
  .legend {
    display: flex; gap: 16px; margin-bottom: 20px; font-size: 12px;
    flex-wrap: wrap; align-items: center;
  }
  .legend-item { display: flex; align-items: center; gap: 5px; }
  .legend-box {
    width: 18px; height: 18px; border-radius: 3px; display: inline-block;
  }
  .container { overflow-x: auto; }
  table {
    border-collapse: collapse; font-size: 12px; white-space: nowrap;
  }
  th, td { padding: 0; text-align: center; }
  /* Scanner name column */
  .scanner-name {
    text-align: left; padding: 4px 10px; font-weight: 500;
    position: sticky; left: 0; background: #0f172a; z-index: 2;
    border-right: 2px solid #334155;
  }
  .scanner-name code {
    font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px;
    color: #e2e8f0;
  }
  /* Metric columns */
  .metric {
    padding: 4px 8px; font-variant-numeric: tabular-nums;
    color: #cbd5e1; font-size: 11px;
  }
  .metric-f2 { font-weight: 700; color: #f8fafc; }
  /* Heatmap cells */
  .cell {
    width: 32px; height: 28px; min-width: 32px;
  }
  .cell-tp { background: #16a34a; }
  .cell-fn { background: #dc2626; }
  .cell-tn { background: #1e293b; }
  .cell-fp-bad { background: #f59e0b; }
  /* Column header cells */
  .col-header {
    padding: 2px 4px; font-size: 10px; font-weight: 600;
    writing-mode: horizontal-tb; height: auto;
    border-bottom: 2px solid #334155;
  }
  .col-num { font-size: 11px; font-weight: 700; color: #f8fafc; }
  .col-cwe { color: #94a3b8; font-size: 9px; }
  .col-desc { color: #64748b; font-size: 9px; max-width: 32px; overflow: hidden; }
  .sev-badge {
    display: inline-block; font-size: 9px; font-weight: 700;
    padding: 1px 4px; border-radius: 3px; color: #fff;
  }
  /* Separator between vuln and FP columns */
  .sep-col { border-left: 3px solid #475569; }
  /* Detection rate row */
  .det-rate { font-size: 10px; font-weight: 600; color: #94a3b8; padding: 4px 2px; }
  .det-rate-cell {
    font-size: 10px; font-weight: 600; padding: 4px 2px;
    border-top: 2px solid #334155;
  }
  /* Row hover */
  tbody tr:hover .scanner-name { background: #1e293b; }
  tbody tr:hover { background: #1e293b; }
  /* Tooltip */
  .cell[title] { cursor: default; }
  /* Section headers in table */
  .section-gap { border-top: 2px solid #475569; }
</style>
</head>
<body>
<h1>DVPWA Scanner Coverage Heatmap</h1>
<div class="subtitle">21 ground-truth vulnerabilities + 4 false-positive test cases &middot; 22 scanners &middot; sorted by F2 score</div>

<div class="legend">
  <div class="legend-item"><div class="legend-box" style="background:#16a34a"></div> TP (found)</div>
  <div class="legend-item"><div class="legend-box" style="background:#dc2626"></div> FN (missed)</div>
  <div class="legend-item"><div class="legend-box" style="background:#1e293b; border:1px solid #334155"></div> TN (correct)</div>
  <div class="legend-item"><div class="legend-box" style="background:#f59e0b"></div> FP! (false alarm)</div>
</div>

<div class="container">
<table>
""")

    # --- THEAD: column number row ---
    html.append("<thead>")

    # Row 1: numbers
    html.append("<tr>")
    html.append('<th class="scanner-name" style="border-bottom:none"></th>')
    html.append('<th class="metric" style="border-bottom:none"></th>')  # F2
    html.append('<th class="metric" style="border-bottom:none"></th>')  # TP
    html.append('<th class="metric" style="border-bottom:none"></th>')  # Recall
    for i, gt_id in enumerate(all_gt_ids):
        sep_class = " sep-col" if gt_id == fp_test_ids[0] else ""
        html.append(f'<th class="col-header col-num{sep_class}">{i+1}</th>')
    html.append("</tr>")

    # Row 2: severity badges
    html.append("<tr>")
    html.append('<th class="scanner-name" style="border-bottom:none"></th>')
    html.append('<th class="metric" style="border-bottom:none"></th>')
    html.append('<th class="metric" style="border-bottom:none"></th>')
    html.append('<th class="metric" style="border-bottom:none"></th>')
    for gt_id in all_gt_ids:
        info = gt_info[gt_id]
        sep_class = " sep-col" if gt_id == fp_test_ids[0] else ""
        if info["is_vulnerable"]:
            sev = info["severity"]
            color = sev_colors.get(sev, "#64748b")
            html.append(f'<th class="col-header{sep_class}"><span class="sev-badge" style="background:{color}">{sev}</span></th>')
        else:
            html.append(f'<th class="col-header{sep_class}"><span class="sev-badge" style="background:#475569">FP</span></th>')
    html.append("</tr>")

    # Row 3: CWE
    html.append("<tr>")
    html.append('<th class="scanner-name">Scanner</th>')
    html.append('<th class="metric">F2</th>')
    html.append('<th class="metric">TP</th>')
    html.append('<th class="metric">Rec</th>')
    for gt_id in all_gt_ids:
        info = gt_info[gt_id]
        sep_class = " sep-col" if gt_id == fp_test_ids[0] else ""
        cwe_num = info["cwe"].replace("CWE-", "")
        html.append(f'<th class="col-header col-cwe{sep_class}">{cwe_num}</th>')
    html.append("</tr>")

    html.append("</thead>")

    # --- TBODY: scanner rows ---
    html.append("<tbody>")

    for idx, scanner in enumerate(sorted_scanners):
        sd = scanners_data[scanner]
        abbr = abbreviate(scanner)
        section_class = ' class="section-gap"' if idx == len(sorted_scanners) - 1 and scanner == "sonarqube" else ""

        # Add visual gap before sonarqube
        tr_style = ""
        if scanner == "sonarqube":
            tr_style = ' style="border-top: 3px solid #475569"'

        html.append(f"<tr{tr_style}>")
        html.append(f'<td class="scanner-name"><code>{abbr}</code></td>')
        html.append(f'<td class="metric metric-f2">{sd["f2_score"]}</td>')
        html.append(f'<td class="metric">{sd["tp"]}</td>')
        html.append(f'<td class="metric">{sd["recall"]:.2f}</td>')

        for gt_id in all_gt_ids:
            result = scanner_results[scanner].get(gt_id, "--")
            info = gt_info[gt_id]
            sep_class = " sep-col" if gt_id == fp_test_ids[0] else ""
            desc = desc_map.get(gt_id, gt_id)

            if info["is_vulnerable"]:
                if result == "TP":
                    html.append(f'<td class="cell cell-tp{sep_class}" title="{gt_id}: {desc} — Found"></td>')
                else:
                    html.append(f'<td class="cell cell-fn{sep_class}" title="{gt_id}: {desc} — Missed"></td>')
            else:
                if result == "TN" or result == "--":
                    html.append(f'<td class="cell cell-tn{sep_class}" title="{gt_id}: {desc} — Correct (not flagged)"></td>')
                else:
                    html.append(f'<td class="cell cell-fp-bad{sep_class}" title="{gt_id}: {desc} — False alarm!"></td>')

        html.append("</tr>")

    html.append("</tbody>")

    # --- TFOOT: detection rate ---
    html.append("<tfoot>")
    html.append("<tr>")
    html.append('<td class="scanner-name det-rate">Detection rate</td>')
    html.append('<td class="det-rate-cell"></td>')
    html.append('<td class="det-rate-cell"></td>')
    html.append('<td class="det-rate-cell"></td>')

    for gt_id in all_gt_ids:
        info = gt_info[gt_id]
        sep_class = " sep-col" if gt_id == fp_test_ids[0] else ""
        if info["is_vulnerable"]:
            rate = det_rates[gt_id]
            pct = int(rate * 100)
            # Color gradient: 0% = red, 50% = yellow, 100% = green
            if rate < 0.5:
                r, g = 220, int(rate * 2 * 180)
            else:
                r, g = int((1 - rate) * 2 * 220), 163
            html.append(f'<td class="det-rate-cell{sep_class}" style="color:rgb({r},{g},50)">{pct}%</td>')
        else:
            tn_count = sum(1 for s in sorted_scanners if scanner_results[s].get(gt_id) in ("TN", None, "--"))
            html.append(f'<td class="det-rate-cell{sep_class}" style="color:#94a3b8">{tn_count}/{len(sorted_scanners)}</td>')

    html.append("</tr>")
    html.append("</tfoot>")

    html.append("</table>")
    html.append("</div>")

    # --- Insights section ---
    never_found = [
        gt_id for gt_id in true_vuln_ids
        if all(scanner_results[s].get(gt_id) != "TP" for s in sorted_scanners)
    ]
    always_found_kolega = [
        gt_id for gt_id in true_vuln_ids
        if all(scanner_results[s].get(gt_id) == "TP" for s in sorted_scanners if s != "sonarqube")
    ]

    html.append("""
<div style="margin-top: 24px; display: flex; gap: 24px; flex-wrap: wrap;">
  <div style="background: #1e293b; border-radius: 8px; padding: 16px; flex: 1; min-width: 250px;">
    <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px; color: #dc2626;">Never Found (0%)</div>
""")
    for gt_id in never_found:
        info = gt_info[gt_id]
        html.append(f'    <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;">{gt_id} &middot; {info["cwe"]} &middot; {desc_map.get(gt_id, "")}</div>')
    html.append("""  </div>
  <div style="background: #1e293b; border-radius: 8px; padding: 16px; flex: 1; min-width: 250px;">
    <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px; color: #16a34a;">Always Found (100% kolega.dev)</div>
""")
    for gt_id in always_found_kolega:
        info = gt_info[gt_id]
        html.append(f'    <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;">{gt_id} &middot; {info["cwe"]} &middot; {desc_map.get(gt_id, "")}</div>')
    html.append("""  </div>
</div>
""")

    html.append("</body></html>")

    output_path = Path("reports/realvuln-dvpwa/heatmap.html")
    output_path.write_text("\n".join(html))
    print(f"Heatmap written to {output_path}")


if __name__ == "__main__":
    main()
