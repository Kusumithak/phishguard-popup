# Phishing-kit fingerprint evaluation

> Descriptive offline results. Pages were scored from the supplied fingerprint CSV; no site was opened or fetched.

## Data and exclusions

- Input rows: 136; scored rows: 134.
- Empty kit_fp rows dropped: 2 phishing and 0 benign.
- Scored labels: **74 phishing and 60 benign**. Smallest resolvable FPR is **1/60 = 1.67%**.
- The evaluator requires one row per registrable domain and rejects duplicate domains to preserve the leave-one-domain-out design.

## Descriptive single-linkage clustering

A cluster joins pages connected by a chain of pairwise distances at or below the stated radius.

| Radius | Class | Clusters | Cluster-size distribution (size: cluster count) | Pages in clusters of size ≥2 (95% Wilson) |
|---:|---|---:|---|---:|
| 0 | Phishing | 52 | 1 page(s): 47 cluster(s); 2 page(s): 1 cluster(s); 3 page(s): 1 cluster(s); 5 page(s): 1 cluster(s); 8 page(s): 1 cluster(s); 9 page(s): 1 cluster(s) | 36.5% (27/74; 95% Wilson 26.4–47.9%) |
| 0 | Benign | 50 | 1 page(s): 46 cluster(s); 2 page(s): 2 cluster(s); 3 page(s): 1 cluster(s); 7 page(s): 1 cluster(s) | 23.3% (14/60; 95% Wilson 14.4–35.4%) |
| 4 | Phishing | 52 | 1 page(s): 47 cluster(s); 2 page(s): 1 cluster(s); 3 page(s): 1 cluster(s); 5 page(s): 1 cluster(s); 8 page(s): 1 cluster(s); 9 page(s): 1 cluster(s) | 36.5% (27/74; 95% Wilson 26.4–47.9%) |
| 4 | Benign | 48 | 1 page(s): 43 cluster(s); 2 page(s): 3 cluster(s); 4 page(s): 1 cluster(s); 7 page(s): 1 cluster(s) | 28.3% (17/60; 95% Wilson 18.5–40.8%) |
| 8 | Phishing | 42 | 1 page(s): 34 cluster(s); 2 page(s): 3 cluster(s); 4 page(s): 1 cluster(s); 5 page(s): 2 cluster(s); 9 page(s): 1 cluster(s); 11 page(s): 1 cluster(s) | 54.1% (40/74; 95% Wilson 42.8–64.9%) |
| 8 | Benign | 39 | 1 page(s): 33 cluster(s); 2 page(s): 3 cluster(s); 5 page(s): 1 cluster(s); 7 page(s): 1 cluster(s); 9 page(s): 1 cluster(s) | 45.0% (27/60; 95% Wilson 33.1–57.5%) |
| 12 | Phishing | 31 | 1 page(s): 24 cluster(s); 2 page(s): 1 cluster(s); 4 page(s): 1 cluster(s); 5 page(s): 1 cluster(s); 8 page(s): 1 cluster(s); 9 page(s): 1 cluster(s); 11 page(s): 2 cluster(s) | 67.6% (50/74; 95% Wilson 56.3–77.1%) |
| 12 | Benign | 29 | 1 page(s): 22 cluster(s); 2 page(s): 5 cluster(s); 6 page(s): 1 cluster(s); 22 page(s): 1 cluster(s) | 63.3% (38/60; 95% Wilson 50.7–74.4%) |

### Mixed-label radius-4 clusters

These groups are false-positive review candidates. Only benign registrable domains are named; phishing domains and URLs are intentionally omitted.

| Representative fingerprint | Total | Phishing count | Benign count | Benign registrable domains |
|---|---:|---:|---:|---|
| `0c144cf555fcaa0a` | 5 | 1 | 4 | `apple.com`, `discord.com`, `proton.me`, `salesforce.com` |
| `408506a907857855` | 9 | 1 | 8 | `gitlab.com`, `leetcode.com`, `linkedin.com`, `medium.com`, `microsoftonline.com`, `npmjs.com`, `stackoverflow.com`, `udemy.com` |
| `548549404428aac3` | 3 | 1 | 2 | `slack.com`, `x.com` |
| `7d7b9516d903553d` | 3 | 1 | 2 | `google.com`, `zoho.in` |

## Test 1 — leave-one-domain-out nearest neighbour

ROC-AUC: **0.747 (95% stratified bootstrap 0.659–0.827; 2000 resamples)**.
At zero false positives, threshold **score ≥ 9.000001** gives recall 36.5% (27/74; 95% Wilson 26.4–47.9%) and FPR 0.0% (0/60; 95% Wilson 0.0–6.0%).

| FPR cap | Chosen score threshold | TP / FP | Recall (95% Wilson) | Observed FPR (95% Wilson) |
|---:|---:|---:|---:|---:|
| 0.00% | 9.000001 | 27 / 0 | 36.5% (27/74; 95% Wilson 26.4–47.9%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 1.67% | 9.000000 | 29 / 1 | 39.2% (29/74; 95% Wilson 28.9–50.6%) | 1.7% (1/60; 95% Wilson 0.3–8.9%) |
| 5.00% | 6.000000 | 31 / 2 | 41.9% (31/74; 95% Wilson 31.3–53.3%) | 3.3% (2/60; 95% Wilson 0.9–11.4%) |
| 10.00% | 4.000000 | 34 / 4 | 45.9% (34/74; 95% Wilson 35.1–57.2%) | 6.7% (4/60; 95% Wilson 2.6–15.9%) |

| Rule T | True positives | False positives | Recall (95% Wilson) | FPR (95% Wilson) |
|---:|---:|---:|---:|---:|
| 0 | 27 | 0 | 36.5% (27/74; 95% Wilson 26.4–47.9%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 2 | 27 | 1 | 36.5% (27/74; 95% Wilson 26.4–47.9%) | 1.7% (1/60; 95% Wilson 0.3–8.9%) |
| 4 | 27 | 1 | 36.5% (27/74; 95% Wilson 26.4–47.9%) | 1.7% (1/60; 95% Wilson 0.3–8.9%) |
| 6 | 31 | 1 | 41.9% (31/74; 95% Wilson 31.3–53.3%) | 1.7% (1/60; 95% Wilson 0.3–8.9%) |
| 8 | 33 | 4 | 44.6% (33/74; 95% Wilson 33.8–55.9%) | 6.7% (4/60; 95% Wilson 2.6–15.9%) |
| 12 | 37 | 9 | 50.0% (37/74; 95% Wilson 38.9–61.1%) | 15.0% (9/60; 95% Wilson 8.1–26.1%) |

## Test 2 — leave-one-radius-4-cluster-out

ROC-AUC: **0.599 (95% stratified bootstrap 0.505–0.695; 2000 resamples)**.
At zero false positives, threshold **score ≥ 9.000001** gives recall 14.9% (11/74; 95% Wilson 8.5–24.7%) and FPR 0.0% (0/60; 95% Wilson 0.0–6.0%).
If removing the query cluster leaves no reference of one class, that class's nearest distance is set to 65 (one greater than the maximum Hamming distance of 64), so absence of a reference is not treated as a close match.

| FPR cap | Chosen score threshold | TP / FP | Recall (95% Wilson) | Observed FPR (95% Wilson) |
|---:|---:|---:|---:|---:|
| 0.00% | 9.000001 | 11 / 0 | 14.9% (11/74; 95% Wilson 8.5–24.7%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 1.67% | 9.000000 | 13 / 1 | 17.6% (13/74; 95% Wilson 10.6–27.8%) | 1.7% (1/60; 95% Wilson 0.3–8.9%) |
| 5.00% | 6.000000 | 15 / 2 | 20.3% (15/74; 95% Wilson 12.7–30.8%) | 3.3% (2/60; 95% Wilson 0.9–11.4%) |
| 10.00% | 4.000000 | 20 / 4 | 27.0% (20/74; 95% Wilson 18.2–38.1%) | 6.7% (4/60; 95% Wilson 2.6–15.9%) |

| Rule T | True positives | False positives | Recall (95% Wilson) | FPR (95% Wilson) |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0.0% (0/74; 95% Wilson 0.0–4.9%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 2 | 0 | 0 | 0.0% (0/74; 95% Wilson 0.0–4.9%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 4 | 0 | 0 | 0.0% (0/74; 95% Wilson 0.0–4.9%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 6 | 4 | 0 | 5.4% (4/74; 95% Wilson 2.1–13.1%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
| 8 | 17 | 3 | 23.0% (17/74; 95% Wilson 14.9–33.7%) | 5.0% (3/60; 95% Wilson 1.7–13.7%) |
| 12 | 24 | 10 | 32.4% (24/74; 95% Wilson 22.9–43.7%) | 16.7% (10/60; 95% Wilson 9.3–28.0%) |

### Test 2 phishing results by kit novelty

Novel means the page was a singleton in the full radius-4 clustering. Recall uses Test 2's global zero-FP score threshold.

| Phishing subset | Pages | Detected | Recall (95% Wilson) |
|---|---:|---:|---:|
| Has a radius-4 sibling | 31 | 11 | 35.5% (11/31; 95% Wilson 21.1–53.1%) |
| Singleton / novel kit | 43 | 0 | 0.0% (0/43; 95% Wilson 0.0–8.2%) |

## Hand-built DOM score baseline

Existing `dom_hand_score` only: ROC-AUC **0.539 (95% stratified bootstrap 0.503–0.578; 2000 resamples)**; recall at zero false positives, threshold **score ≥ 35.000001**, is 0.0% (0/74; 95% Wilson 0.0–4.9%). FPR is 0.0% (0/60; 95% Wilson 0.0–6.0%).

## Existing brand-title DOM features

These are counts of pages whose stored feature flag equals 1; no new title or logo matching was added.

| Feature | Phishing pages firing (95% Wilson) | Benign pages firing (95% Wilson) |
|---|---:|---:|
| dom_brand_in_title | 13.5% (10/74; 95% Wilson 7.5–23.1%) | 23.3% (14/60; 95% Wilson 14.4–35.4%) |
| dom_brand_domain_mismatch | 13.5% (10/74; 95% Wilson 7.5–23.1%) | 0.0% (0/60; 95% Wilson 0.0–6.0%) |
## Threshold selected for the optional extension matcher

Chosen **T = 0** because it is the largest tested distance in {0, 2, 4, 6, 8, 12} with zero benign false positives in Test 1. At this T, Test 1 yields 27/74 phishing matches (36.5% (27/74; 95% Wilson 26.4–47.9%)) and 0/60 benign false positives (0.0% (0/60; 95% Wilson 0.0–6.0%)). T was not selected using Test 2, the DOM score, or any other metric.

## Limitations

- This dataset covers one crawl day; clustering within one day can overstate how often kits are reused over time.
- The scored set is small (74 phishing and 60 benign pages); Wilson intervals and bootstrap intervals are wide and should be shown with rates.
- Benign WordPress and login-framework templates can resemble phishing pages and appear in mixed-label clusters.
- Attackers can randomise the DOM, and phishing pages can cloak content from headless browsers.
- Fingerprints were computed from saved pages re-rendered offline. The live-versus-saved parity check on the safe fixtures was not run in this environment because Playwright is unavailable.
- Results are descriptive, not evidence of production performance. The dataset is small, and thresholds were selected on this same sample for descriptive operating points.
