# Role 3: DOM layer and DOM data

## Status: what is finished and what only a live crawl can finish

| Deliverable | Status |
|---|---|
| Updated `content.js` (37 DOM features, two false-positive fixes, reload guard) | **Done and tested** |
| Crawler, offline re-extract, CSV format, feature schema | **Done.** Verified on 60 benign pages (58 fetched). |
| Safe detection self-test (fake phishing-style pages, no real site) | **Done** (`tools/selftest.js`, `tests/fixtures/`) |
| Daily feed builder and merge/summary tools | **Done and unit-tested**, but the feed download itself is untested here (feed URLs can change) |
| Benign login harness (about 50 pages) | **Seed list of 60 done.** You still add 5-10 of your own college portals. |
| DOM false-positive report | **Tool done; first run done.** Re-run after the fixes and keep before and after. |
| **Labeled DOM CSV with real phishing pages** | **Needs you**: crawl same-day phishing URLs for 2-3 weeks inside a sandbox. |
| Report text | **Generated** by `tools/finish_role3.js` into `docs/ROLE3_REPORT_SECTION_FILLED.md`. |

## Files

| File | Purpose |
|---|---|
| `content.js` | Returns `domScore`, `findings`, `stats` plus `features` (37 numeric DOM features). |
| `data/dom/dom_feature_schema.json` | Name and meaning of every feature (a test fails if it drifts from `content.js`). |
| `tools/crawl_dom.js` | Playwright crawler: snapshots, labeled CSV, `--reextract` to rescore snapshots offline. |
| `tools/selftest.js` | Real-Chrome check using fake pages only. |
| `tools/fetch_feeds.js` | Builds today's `crawl_input_<date>.csv` (OpenPhish + Phishing.Database + benign seed). Downloads text lists only. |
| `tools/finish_role3.js` | One command: merge, summary, FP report and the filled report section. |
| `tools/merge_dom_csv.js` | Merges daily CSVs into `dom_labeled.csv` (one row per domain) and writes `dom_dataset_summary.md`. |
| `tools/fp_report.js` | DOM false-positive report. |
| `tools/finish_role3.js` | **One command for the final outputs**: merge, false-positive report, and report section filled from your numbers. |
| `tools/fill_report.js` | Fills `docs/ROLE3_REPORT_TEMPLATE.md` (never guesses: missing numbers stay `[FILL: name]`). |
| `tests/run_all.js` | Runs every test. |

## Rule changes made because of what the tests and crawl showed

1. **`hidden_password_field`** fired on GitHub's login page (red banner). It now fires only on stealth hiding (opacity 0, off-screen, 1px), not on `display:none` fields in closed modals or inactive login steps, and not on hidden inputs that merely have "pass" in their name (e.g. passkey). Trade-off: a phishing page hiding its password with `display:none` is no longer caught by this rule.
2. **`javascript:` form actions** were read as a different origin ("null"), flagging single-page-app logins. They are now treated as submitting to the current page.
3. **Extension reload**: old tabs no longer throw "Extension context invalidated".

**Known remaining false positive (documented, not fixed):** a password form posting to a sibling subdomain (`www.x.com` to `auth.x.com`) still raises `password_form_cross_origin`. `dom_n_password_forms_cross_site` is 0 for it, so the learned model can separate it. Decide with the FP report how often it occurs before changing the hand rule.

## Finish in one session (the short path)

Keep every deliverable; only the order is compressed.

1. `node tests/run_all.js` then `node tools/selftest.js` (both must pass).
2. Add your own college portals to `data/dom/benign_login_seed.csv` with source `benign_seed:college`.
3. Save the old report: rename `data/dom/dom_fp_report.md` to `dom_fp_report_before.md`.
4. Crawl (phishing part inside a sandbox), naming outputs `dom_features_<date>.csv`:
   - benign: `node tools/crawl_dom.js --input data/dom/benign_login_seed.csv --out data/dom/dom_features_benign.csv`
   - phishing: `node tools/fetch_feeds.js --max 100 --benign 0`, then crawl that file in the sandbox.
5. `node tools/finish_role3.js` produces `dom_labeled.csv`, `dom_dataset_summary.md`, `dom_fp_report.md` and `docs/ROLE3_REPORT_SECTION.md`.
6. Read the report section; complete or delete any `[FILL: ...]` line; push; hand the files to Role 1.

Only crawl files made with the current `content.js`; `merge_dom_csv.js` refuses files with a different column layout.

## Setup (once)

```powershell
npm i -D jsdom playwright tldts
npx playwright install chromium
node tests/run_all.js
node tools/selftest.js          # real Chrome, fake pages only
```

## SAFETY: read before crawling phishing URLs

- Crawl phishing URLs only inside a disposable VM or Docker container with no logged-in profile, no credentials and no shared folders. Do not run the crawler on your normal Windows profile.
- `fetch_feeds.js` only downloads text. `crawl_dom.js` is the step that opens the URLs.
- The crawler never fills, clicks or submits, aborts every non-GET/HEAD request, and blocks downloads, popups and dialogs. This does not replace the sandbox.
- Never commit `data/dom/snapshots/` (already in `.gitignore`).

## Daily workflow (weeks 1-3)

```powershell
node tools/fetch_feeds.js --max 100 --benign 30              # or use Role 2's feed
# --- inside the sandbox, same day: phishing pages die within hours ---
node tools/crawl_dom.js --input data/dom/crawl_input_2026-11-24.csv --out data/dom/dom_features_2026-11-24.csv
```

When `content.js` changes, rescore old snapshots without the network:
```powershell
node tools/crawl_dom.js --reextract --input data/dom/crawl_input_2026-11-24.csv --out data/dom/dom_features_2026-11-24.csv
```

## Finish in one command (run after every crawl)

```powershell
node tools/finish_role3.js --college 8        # 8 = how many of your own college portals are in the seed list
```
This reads every `data/dom/dom_features*.csv` and writes:
- `data/dom/dom_labeled.csv` (one row per domain, dead pages dropped)
- `data/dom/dom_dataset_summary.md` (counts per day, suggested time split, small-set warning)
- `data/dom/dom_fp_report.md` (false-positive report)
- `docs/ROLE3_REPORT_SECTION_FILLED.md` (the report text with all numbers filled from your data, including the before/after table)

With 0 phishing rows it says so in the report instead of inventing numbers. Give Role 1: `dom_labeled.csv`, `dom_feature_schema.json`, `dom_dataset_summary.md`, `dom_fp_report.md`, `content.js`, and the filled report section.

## CSV columns (shared format)

`url, label, domain, date, source, fetch_ok, http_status, final_url, redirected_cross_site, scan_ms, snapshot_file, error`, then `flag_*` (7 rule flags, 0/1), `dom_hand_score`, then 37 `dom_*` features. `label` 1 = phishing. `domain` is eTLD+1 via `tldts` (matches Python `tldextract`). `scan_ms` feeds Role 1's latency figure.

## Known limits (state these honestly)

- DOM feature tests run in jsdom (no layout); the real-Chrome check is `tools/selftest.js` plus your crawl.
- Only inline scripts and same-origin iframes are readable.
- The brand list has about 27 brands; "same site" inside `content.js` is a small approximation of the Public Suffix List.
- Legitimate sites hotlink CDNs and favicons, so `ext_resource_ratio` and `favicon_foreign` are weak alone.
- Headless crawlers miss kits that fingerprint bots or geo-block, and pages with a fast meta refresh may have navigated away before the scan (default settle is 2 s).
- Phishing pages are only crawlable while alive, so the DOM set is much smaller than the URL set.
