# Private scoring receipts

The main RealVuln leaderboard includes five large Python repositories scored by a private authority. Their ground truth, taxonomy and submitted finding locations stay in the private service. The public site receives only aggregate, service-issued receipts. The first dev service scores internal submissions; external registration is not open yet.

## Submission

1. A participant runs their scanner on the specified pinned repositories.
2. The participant sends normalized locations (`repo`, `file`, category, line or bounded span, optional CWE labels) to the private API over HTTPS. The dashboard never accepts finding files.
3. The service scores locations in memory, returns an unpublished receipt and discards the submitted locations. It stores the receipt and a hash of the normalized submission, not the findings.
4. The service gives the participant a one-use publication secret with the unpublished receipt. The participant can publish that receipt by ID and secret; the reusable scoring token never enters the public page. The page lists published receipts from the API without ranking them.

The private service necessarily sees locations while scoring. A participant who cannot disclose even transient normalized locations needs a separately agreed trusted execution arrangement; a self-reported score is not verifiable. A receipt proves the service computed the score for a submission. It does not attest that the scanner independently found the locations or completed every repository. This distinction is shown beside the published receipts.

## Score and integrity

The private authority fixes five repository commits and a versioned GT snapshot. A receipt records the authority version and hash, source commits, matcher version, submitted-location hash, true matches, unmatched alerts, misses, recall and F3. The F3 formula is `10 × TP / (10 × TP + FP + 9 × FN)`. Matching is one-to-one: an alert can match at most one GT row. The current internal contract accepts source spans of at most 50 lines and a ±10-line location tolerance. Excluded GT lineage does not enter the denominator.

Publishing a receipt exposes aggregate counts but no vulnerability locations, labels, snippets or submitted finding files. The receipt's source-commit field is a participant assertion, not execution proof. Because GT is withheld, external readers cannot independently reproduce the score from public data. The authority hash commits to a fixed private snapshot for later confidential audit; it does not reveal that snapshot or independently certify its quality.

## Launch preview

Kolega's official private submission scored **F3 0.6002 (60.02%)** and recall **0.7253**: 1,410 matches, 4,585 unmatched findings and 534 misses against 1,944 scored rows on five pinned repositories. The production private scorer scored all 5,995 submitted finding locations and issued published receipt `bd2cab542e0041e788e4cc6b480196f2`. Combined with Kolega DevSec Max's 203 public-repository counts, the main leaderboard covers **208 repositories**, with **7,559 matches, 17,817 unmatched findings, 1,503 misses and F3 70.69%**. The five-repository 60.02% is its component score, displayed on the same dashboard.

The dashboard also shows aggregate F3, recall, matches, unmatched findings and misses for Sentry, Odoo, NetBox, Airflow and Saleor. The receipt contains only those per-repository totals, never finding or GT locations.

The current large-repository authority has no row-level CWE labels and its matching contract uses private category IDs, whereas the public matcher gates on CWE. The pooled F3 uses the same TP/FP/FN formula, but its matching identity differs across the two subsets. External scanners cannot fairly submit under the current private contract without receiving the private taxonomy. Before external onboarding, a new private authority needs reviewed row-level standard identities, a versioned matcher, and like-for-like rescoring of every entrant. The receipt transport and dashboard can stay the same. CVSS-weighted and severity-filtered mixed-corpus metrics are withheld until the private receipt carries the required aggregates.

`build_site.py` writes `private-score-config.js` from `REALVULN_PRIVATE_SCORE_API`. The production value is `https://results.realvuln.com`; only an HTTPS API origin may be supplied. The dev endpoint is absent from this repository.

The withheld authority has its own version and source pins. Its aggregate counts are merged into the main ranking; no ground truth row, finding location, private category list, or scanner output belongs in this repository or its Git history. Scanners without a five-repository receipt have five additional unscanned repositories counted as misses in strict mode.
