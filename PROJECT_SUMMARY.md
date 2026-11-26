# PhishGuard Popup — Project and Progress Summary

Reviewed from the local clone on 2026-11-26. This document describes the checked-out `main` branch at commit `2c2c048`.

## What the project does

PhishGuard is a Manifest V3 Chrome/Edge extension that scans HTTP/HTTPS pages locally for phishing risk. The browser extension combines URL-based machine learning, URL heuristics, and page-structure checks. It displays an in-page warning when its risk score is high enough, and its popup shows a scan report and evidence.

The repository describes the privacy model as local-only: it does not send URLs or page contents to a service, and the DOM scanner inspects structure without reading values typed into forms. The extension requests broad HTTP/HTTPS host access so it can scan pages automatically.

## How the code is organized

- `manifest.json` declares the MV3 service worker, popup, permissions, and HTTP/HTTPS host access.
- `background.js` listens for navigations (including SPA history changes), coordinates URL and DOM stages, persists per-tab reports in session storage, and shows/dismisses warning banners.
- `ml/inference.js` extracts nine hostname-oriented features and runs the shipped logistic-regression model in `ml/model.json`. If model loading fails, the rest of the scanner can fall back to rules and DOM scoring.
- `rules.js` scores URL indicators such as brand look-alikes, punycode, mixed scripts, raw IP hosts, suspicious terms, URL structure, and risky TLDs.
- `content.js` probes page structure and emits rule findings, stats, and 37 numeric DOM features. It checks form destinations, password-field visibility, iframes, links, resources, redirects, and inline-script characteristics; it does not inspect typed values.
- `hybrid.js` combines the layer scores and applies explicit score floors for extreme URL signals and selected strong DOM findings.
- `popup.html`, `popup.css`, and `popup.js` render the current tab's report, score breakdown, evidence, and copy-report action.
- `tools/` contains the DOM crawler, feed and CSV utilities, self-test, false-positive report generation, and report-filling scripts.
- `tools/evaluate_url_model.js` evaluates the checked-in URL model and URL heuristics on labeled CSV data without fetching URLs. It reuses the extension's inference function and reports bootstrap intervals and threshold tradeoffs.
- `tests/` contains Node-based tests and safe HTML fixtures for URL rules and DOM tooling.
- `data/dom/` and `out/dom_features.csv` contain a labeled DOM feature dataset and derived reports. Large raw URL datasets and private page snapshots are not included.
- `docs/ROLE3_DOM.md` describes the DOM collection workflow and its safety limits; the report template and section document findings and limitations.

## Scan flow and decisions

1. A navigation or SPA URL change starts a scan.
2. The extension computes URL features, the local model score, and deterministic URL heuristics.
3. Raw IP or punycode hosts can trigger an immediate high-risk warning; a sufficiently strong brand-look-alike signal can also do so. URL scores in the 35–49 range can show an early subtle warning.
4. The page gets a structural DOM scan as it loads. The final fused score uses 30% model, 30% URL heuristics, and 40% DOM when the model is available; otherwise it uses 50% URL heuristics and 50% DOM.
5. Decisions are SAFE below 35, SUSPICIOUS at 35–49, and PHISHING at 50+. Hard URL signals floor the score at 80. A DOM score of 70+ or selected strong DOM findings floor it at 60. Warnings do not downgrade during the same navigation.
6. The popup presents the report and can copy an evidence summary.

The README cautions that the heuristic/DOM scores and their fusion weights still need validation against a sufficiently large labeled evaluation set. DOM checks can also miss forms that appear only after user interaction or outside the observation period.

## What has happened in Git so far

The local clone is on `main`, tracking `origin/main`, and was clean immediately after cloning. The checked-out tip is merge commit `2c2c048` (2026-11-25), which merged PR #1 from `role-3-dom`.

| Commit | Date | Recorded change |
|---|---|---|
| `4b67374` | 2026-11-17 | Initial PhishGuard extension: popup, background/content scanning, hybrid scoring, URL rules, initial model and tests. |
| `0a182d4` | 2026-11-25 | Added a reproducible URL model pipeline, feature/parity tests, scripts, and initial results. |
| `c19d88a` | 2026-11-25 | Integrated candidate URL-model results and benchmark/report artifacts. |
| `cf482c2` | 2026-11-25 | Added Role 1 evaluation-status notes explaining why a learned fusion candidate was not promoted. This commit is on `origin/url-model`, not the checked-out `main` tip. |
| `e02cb4d` | 2026-11-25 | Added Role 3 DOM features, crawler and CSV tooling, dataset/reports, fixtures, and DOM-related tests on `role-3-dom`. |
| `2c2c048` | 2026-11-25 | Merged the Role 3 DOM work into `main`; this is the current checkout. |

The clone also has remote-tracking branches `origin/url-model` and `origin/role-3-dom`; the local working branch is only `main`. The `url-model` branch contains extra evaluation artifacts/status notes that are not present on `main`.

## Current progress and unfinished work

- The browser extension, URL rules, local model inference, DOM feature extraction, crawler, and offline reporting tools are present in the repository.
- Role 3 documents a one-day crawl dated 2026-11-25. Its deduplicated dataset has 76 phishing and 60 benign domains. The false-positive report records 3/76 phishing pages and 1/60 benign pages crossing its hand-set red-banner threshold. These are small, indicative counts, not a validated accuracy claim.
- The Role 3 docs say a time-based holdout cannot be formed from one crawl day and call for additional same-day phishing crawls over multiple days. They also call for adding the user's own college login portals to the benign seed list and rerunning the generated reports.
- The `origin/url-model` status document says not to promote a candidate or change `hybrid.js`: labeled training/evaluation data, out-of-fold predictions, and a separate untouched test set are missing from that branch's checkout. It says threshold selection at FPR <= 0.1%, stacker/calibration work, final test evaluation, and ablations/curves were not performed.
- The shipped URL model's original training data and training code are absent per `data/README.md` and the main README, so that model cannot currently be reproduced from this checkout.
- The original checkout's README recommended only `node tests/rules.test.js`, and its `npm test` script was a placeholder. The local workspace improvement now maps `npm test` to `tests/run_all.js`, adds `npm run evaluate:url-model`, aligns the README with the actual nine URL features, and aligns the package version with the extension. `out/url_model_evaluation.md` contains an exploratory report for the supplied one-day dataset.

## Review notes to reconcile

- The Role 3 report section and dataset summary use slightly different row descriptions/count contexts: the report section describes 265 phishing + 74 benign crawled URLs and then 76 + 60 after deduplication, while the dataset summary reports 339 crawled rows and 17 dead/blocked/timeouts. The false-positive report's “Rows crawled: 136” refers to the deduplicated per-domain set, so labels should clearly distinguish raw crawls from deduplicated rows.
- Documentation notes one known benign false positive: a password form posting to a sibling subdomain can trigger `password_form_cross_origin`.

## Local setup

Load the `phishguard-popup` folder as an unpacked extension from `chrome://extensions` or `edge://extensions` with Developer mode enabled. After editing files, refresh the extension card. Install development dependencies with `npm ci`, run tests with `npm test`, and generate the offline evaluation with `npm run evaluate:url-model`. Tests were not run during this improvement turn; the evaluator was run to generate the explicitly exploratory report.
