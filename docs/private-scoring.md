# Private scoring receipts

The private benchmark uses a separate authority and scoring contract from the public corpus. Its ground truth, taxonomy and matching details stay in a private service. The public site displays only aggregate, service-issued receipts. The first dev service scores internal submissions; external registration is not open yet.

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

Kolega's `python-large` hybrid profile produced the published dev receipt `5e1866eda9274e55ac9eaa2a4b17a11b` on five pinned repositories: F3 **0.5684**, recall **0.6847**, 1,331 matches, 4,588 unmatched findings and 613 misses against 1,944 scored rows. The private run record verifies five successful scan outputs and an exact local scorer match. This receipt remains a dev preview under the internal category contract, separate from the public benchmark ranking and from saved-output research projections.

The current large-repository authority has no row-level CWE labels and its matching contract uses private category IDs. External scanners cannot fairly submit under that contract without receiving the private taxonomy. Before external onboarding, a new private authority needs reviewed row-level standard identities, a versioned matcher, and like-for-like rescoring of every entrant. The receipt transport and dashboard can stay the same.

`build_site.py` writes `private-score-config.js` from `REALVULN_PRIVATE_SCORE_API`. Leave it unset until the production API is approved and configured. Only an HTTPS API origin may be supplied. The dev endpoint is intentionally absent from this repository.

The withheld authority has its own version and source pins. Scores from it must never be merged into the public benchmark ranking. No ground truth row, finding location, private category list, or scanner output belongs in this repository or its Git history.
