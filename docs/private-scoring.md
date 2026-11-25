# Private ground truth scoring

The five large Python repositories contribute to the main 208-repository leaderboard. Their ground truth stays in a versioned, private S3 object. Anyone can submit CWE-labelled findings to the public scorer at `https://results.realvuln.com`; no account, token or registration is needed.

## Submit findings

1. Read `GET https://results.realvuln.com/meta` for the current authority, pinned commits and limits. Scan those exact commits.
2. POST a normalized JSON results file to `https://results.realvuln.com/score`:

```bash
curl -sS -H 'content-type: application/json' --data-binary @submission.json https://results.realvuln.com/score
```

The JSON envelope contains `scanner`, `authority`, `source_commits` and `findings`. The `authority` and `source_commits` must equal `/meta`. Each finding contains `repo`, repository-relative `file`, one to three standard `cwes` (for example `CWE-79`), and either `line` or `start_line` plus `end_line`. A span may cover at most 50 lines. Paths and lines refer to the pinned source tree. The service rejects other finding fields. Semgrep output can be converted to this shape using its path, start/end lines and CWE metadata.

```json
{
  "scanner": "example-scanner",
  "authority": "large-five-cwe-v1.0.0",
  "source_commits": {"airflow": "<commit from /meta>", "netbox": "<commit from /meta>", "odoo": "<commit from /meta>", "saleor": "<commit from /meta>", "sentry": "<commit from /meta>"},
  "findings": [{"repo": "airflow", "file": "path/in/repository.py", "start_line": 10, "end_line": 12, "cwes": ["CWE-79"]}]
}
```

The service accepts up to 20,000 findings, 200 findings per file and 5 MB per submission. It permits 10 score attempts per source IP per UTC day, with an additional burst limit. Score attempts and API request metadata are logged without finding bodies; submitted locations are scored in memory and discarded. Only aggregate receipts and submission hashes are stored. Receipt IDs are unguessable but visible to anyone holding the ID.

## Read and publish a receipt

The POST response contains a receipt ID, aggregate TP/FP/FN, recall and F3. Read it at `GET https://results.realvuln.com/receipts/<receipt-id>` or on the [private scores page](https://realvuln.com/private-scores.html). A receipt is initially unpublished. **For a benchmark submission, include your public-repository result files as usual and add the optional receipt attachment below. Do not attach or commit the five private-repository result files.** If you want the receipt considered before a PR is ready, [open a GitHub issue](https://github.com/kolega-ai/Real-Vuln-Benchmark/issues/new) with its ID and requested scanner name. Maintainers review and publish the receipt using operator credentials. Participants cannot publish receipts through this API.

Create `submissions/<scanner-slug>.json` in your benchmark PR:

```json
{"scanner": "your-scanner-slug", "private_receipt_id": "your-32-character-receipt-id"}
```

The scanner slug must match the public result directory and the receipt. The normal public scoring run must include that scanner in `reports/dashboard.json`. A maintainer publishes the selected receipt before merging the PR. On merge, the deployment build retrieves it from the service, verifies its authority, scanner and score arithmetic, and automatically pools its TP/FP/FN into that scanner's 208-repository headline. The attachment is **optional**: without it, the five unscanned repositories remain misses in strict scoring. No maintainer needs to copy private counts into the dashboard.

The service matches exact repository and file, a standard CWE accepted by the GT row, and a reported line or span within ±10 lines of the GT location. Matching is one-to-one. F3 is `10 × TP / (10 × TP + FP + 9 × FN)`. Unreported GT rows count as misses. The receipt's pinned commits are asserted by the participant; the service does not execute or verify the scanner. Repeated score queries can reveal some information about withheld labels, so quotas limit this risk but cannot remove it completely.

## Current published scores

The first four submitted result files were rescored against the same CWE authority and matcher. TraceHunt's receipt uses that authority and matcher too. The earlier category-based receipts remain accessible by ID as history; the leaderboard uses these current receipts.

| Scanner | Private five F3 | Private TP / FP / FN | Current receipt | Main 208-repo F3 |
| --- | ---: | ---: | --- | ---: |
| Kolega DevSec Max | 59.94% | 1,408 / 4,587 / 536 | `1daf0fa9de2548fc96030dc0665c7bae` | 70.67% |
| AccuKnox TraceHunt 1.0 Preview | 12.87% | 270 / 3,206 / 1,674 | `8e6f875f496a4e5790c83542df790f69` | 49.42% |
| Daybreak Blue | 1.42% | 25 / 63 / 1,919 | `1f85bb121add49cfa52e06bbfa24ce3d` | 48.11% |
| DeepSeek V4.1 Flash | 0.51% | 9 / 33 / 1,935 | `2d35315a13494a69ab5a94fcbc74ec46` | 34.19% |
| Sonnet 5 | 0.34% | 6 / 12 / 1,938 | `8c07ce1b9330460997c8457ceaf4cf8a` | 28.39% |

Kolega's previous 60.02% receipt used the old private-category matcher. It is retained for audit but not pooled into the current headline. The saved submission had explicit CWEs on 1,791 findings; the original detector CWE mapping supplied labels for the remaining 4,204 during replay. The other three raw submissions already contained CWE labels. Only counts and per-repository aggregates enter this public repository; neither finding files nor private GT are published.
