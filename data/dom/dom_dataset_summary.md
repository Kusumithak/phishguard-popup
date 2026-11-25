# DOM dataset summary

Crawled rows: 339. Dead, blocked or timed out: 17 (5.0%).
After one-row-per-domain: **76 phishing, 60 benign** (186 duplicate domains removed).
Domains seen with both labels: 0; kept, review them.

| Date | Phishing | Benign |
|---|---|---|
| 2026-11-25 | 76 | 60 |

## Suggested time split (newest 7 days = untouched test set)

Train: 0 rows (0 phishing). Test: 136 rows (76 phishing).

> Fewer than 8 crawl days: a 7-day test window would leave almost nothing to train on. Crawl for more days, or agree a smaller window with Role 1.

> **The DOM set is small (76 phishing pages)** compared with the URL set. State this in the report and give wide confidence intervals; with this few pages Role 1 should keep a hand-set or strongly regularised DOM weight.
