# Private scoring receipts

The main RealVuln leaderboard includes five large Python repositories scored by a private authority. Their ground truth, taxonomy and submitted finding locations stay in the private service. The public site receives only aggregate, service-issued receipts. The production service scores registered submissions; open external registration is not available yet.

## Submission

1. A participant runs their scanner on the specified pinned repositories.
2. The participant sends normalized locations (`repo`, `file`, category, line or bounded span, optional CWE labels) to the private API over HTTPS. The dashboard never accepts finding files.
3. The service scores locations in memory, returns an unpublished receipt and discards the submitted locations. It stores the receipt and a hash of the normalized submission, not the findings.
4. The service gives the participant a one-use publication secret with the unpublished receipt. The participant can publish that receipt by ID and secret; the reusable scoring token never enters the public page. The page lists published receipts from the API.

The private service necessarily sees locations while scoring. A participant who cannot disclose even transient normalized locations needs a separately agreed trusted execution arrangement; a self-reported score is not verifiable. A receipt proves the service computed the score for a submission. It does not attest that the scanner independently found the locations or completed every repository. This distinction is shown beside the published receipts.

## Score and integrity

The private authority fixes five repository commits and a versioned GT snapshot. A receipt records the authority version and hash, source commits, matcher version, submitted-location hash, true matches, unmatched alerts, misses, recall and F3. The F3 formula is `10 × TP / (10 × TP + FP + 9 × FN)`. Matching is one-to-one: an alert can match at most one GT row. The current internal contract accepts source spans of at most 50 lines and a ±10-line location tolerance. Excluded GT lineage does not enter the denominator.

Publishing a receipt exposes aggregate counts but no vulnerability locations, labels, snippets or submitted finding files. The receipt's source-commit field is a participant assertion, not execution proof. Because GT is withheld, external readers cannot independently reproduce the score from public data. The authority hash commits to a fixed private snapshot for later confidential audit; it does not reveal that snapshot or independently certify its quality.

## Published scores

Kolega's official private submission scored **F3 0.6002 (60.02%)** and recall **0.7253**: 1,410 matches, 4,585 unmatched findings and 534 misses against 1,944 scored rows on five pinned repositories. The production private scorer scored all 5,995 submitted finding locations and issued published receipt `bd2cab542e0041e788e4cc6b480196f2`. Combined with Kolega DevSec Max's 203 public-repository counts, the main leaderboard covers **208 repositories**, with **7,559 matches, 17,817 unmatched findings, 1,503 misses and F3 70.69%**. The five-repository 60.02% is its component score, displayed on the same dashboard.

Three additional registered scanners have production receipts from the same frozen five-repository authority and matcher. Their standard-CWE output was translated into private scoring categories by a versioned, privately held adapter fixed before submission. The adapter and result-file provenance are retained privately. All four receipts contain only aggregate and per-repository totals, never finding or GT locations.

| Scanner | Private five F3 | Private TP / FP / FN | Receipt | Main 208-repo F3 |
| --- | ---: | ---: | --- | ---: |
| Kolega DevSec Max | 60.02% | 1,410 / 4,585 / 534 | `bd2cab542e0041e788e4cc6b480196f2` | 70.69% |
| Daybreak Blue | 2.45% | 43 / 45 / 1,901 | `a77299a5bf3f47caada1993f6a0bd94b` | 48.31% |
| DeepSeek V4.1 Flash | 0.91% | 16 / 26 / 1,928 | `53e78122c76242bd9d3d7c23eaf9ac95` | 34.27% |
| Sonnet 5 | 0.46% | 8 / 10 / 1,936 | `ac16d907d76f4b9ebdde1537f52837d8` | 28.41% |

These are scores of submitted result files. The receipts do not attest independent scanner operation, complete source coverage, or the submitter's identity. Unreported private GT rows count as misses.

The current large-repository authority has no row-level CWE labels and its matching contract uses private category IDs, whereas the public matcher gates on CWE. The pooled F3 uses the same TP/FP/FN formula, but its matching identity differs across the two subsets. Open external submissions need a publicly specified standard input identity and like-for-like rescoring of every entrant; the current private adapter is frozen for these four released results. CVSS-weighted and severity-filtered mixed-corpus metrics are withheld until the private receipt carries the required aggregates.

`build_site.py` writes `private-score-config.js` from `REALVULN_PRIVATE_SCORE_API`. The production value is `https://results.realvuln.com`; only an HTTPS API origin may be supplied. The dev endpoint is absent from this repository.

The withheld authority has its own version and source pins. Its aggregate counts are merged into the main ranking; no ground truth row, finding location, private category list, or scanner output belongs in this repository or its Git history. Scanners without a five-repository receipt have five additional unscanned repositories counted as misses in strict mode.
