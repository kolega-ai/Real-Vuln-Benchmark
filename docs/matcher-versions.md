# Scorer matching versions

Both versions use the same file, acceptable CWE, and ±10-line eligibility rules
for primary and alternate ground-truth locations.

- `greedy-v1` reproduces the legacy assignment policy. It assigns findings in input order and
  prefers positive rows over traps. Saved and archived scores use their original policy.
- `maximum-v2` is the default. It finds a one-to-one assignment that
  maximizes true positives, then matched traps, then minimizes total line
  distance to the closest eligible region. Missing line data remains eligible
  where the current rules permit it and ranks after known distances. Findings
  and ground-truth IDs are sorted before assignment, and equal-cost paths use
  that canonical traversal order. CVSS applies only when computing metrics.

Non-scoring rows are excluded from assignment. An otherwise unmatched finding
may still be withheld under the existing non-scoring location rule.
For multi-run `maximum-v2` summaries, round the mean TP once and subtract
from the fixed number of positive ground-truth rows to report FN. Per-run
metrics and the mean of run-level F-scores keep their existing definitions.

```sh
python3 score.py --repo realvuln-djangoat --scanner snyk
python3 dashboard.py --scanner-group all
python3 dashboard.py --scanner-group all --matcher greedy-v1
```

Generated JSON records `matcher_version`. Explicit legacy runs default to separate filenames. Public report snapshots retain their original scores.
