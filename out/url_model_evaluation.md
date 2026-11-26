# Shipped URL detector: offline evaluation

> **Exploratory only.** This report scores the checked-in model against the supplied labeled URLs. It is not an untouched test result, does not establish real-world accuracy, and must not be used to claim a production false-positive rate. The current DOM dataset covers only 1 crawl day(s).

Generated from `data/dom/dom_labeled.csv` with `ml/model.json`. No URL was fetched or opened.

## Data used

- Rows scored: **136** (76 phishing, 60 benign)
- Crawl dates represented: 2026-11-25
- Unfetched rows skipped: 0; malformed rows skipped: 0
- Domain policy: input must contain no duplicate registrable domains; duplicate rows stop the run to prevent domain leakage.
- Model features: host_length, deep_subdomain_count, digit_ratio, hyphen_count, has_userinfo, has_https, has_ip, host_keyword_count, has_punycode
- Observed benign sample resolution: one false positive changes FPR by 1.667 percentage points.

## Ranking metrics

| Scorer | ROC-AUC (95% bootstrap CI) | Average precision (95% bootstrap CI) |
|---|---:|---:|
| Shipped logistic model | 0.8729 (0.8100–0.9323) | 0.9090 (0.8657–0.9498) |
| URL heuristics | 0.3826 (0.2954–0.4775) | 0.6054 (0.5547–0.6682) |

Average precision uses the observed sample prevalence (55.9%); it will change with class balance.

Intervals are reproducible, stratified percentile bootstrap intervals (2000 resamples; seed 20261126). They quantify sampling variation within this collected set only and do not account for temporal or source bias.

## Fixed threshold (0.50)

| Scorer | TP | FP | TN | FN | Recall | FPR | Precision |
|---|---:|---:|---:|---:|---:|---:|---:|
| Shipped logistic model | 50 | 7 | 53 | 26 | 65.8% | 11.7% | 87.7% |
| URL heuristics | 0 | 0 | 60 | 76 | 0.0% | 0.0% | 0.0% |

## Empirical model operating points

Each row uses the lowest observed score threshold that meets the requested FPR cap, maximizing recall on this same dataset. These are descriptive points, not validated deployment thresholds.

| Requested FPR cap | Threshold | Observed FPR | Recall | Precision |
|---:|---:|---:|---:|---:|
| 0.1% | 0.7978 | 0.0% | 43.4% | 100.0% |
| 1.0% | 0.7978 | 0.0% | 43.4% | 100.0% |
| 5.0% | 0.6760 | 5.0% | 48.7% | 92.5% |

### Heuristic comparison

| Requested FPR cap | Threshold | Observed FPR | Recall | Precision |
|---:|---:|---:|---:|---:|
| 0.1% | 0.3000 | 0.0% | 2.6% | 100.0% |
| 1.0% | 0.3000 | 0.0% | 2.6% | 100.0% |
| 5.0% | 0.1200 | 1.7% | 13.2% | 90.9% |

## Interpretation and limits

- This dataset is small, collected on very few days, and was not reserved as an untouched final test set. Same-dataset threshold selection is optimistic.
- The one-day crawl cannot measure temporal generalization; the benign/phishing mix is not a natural browsing prevalence. Precision here is therefore not a user-facing precision estimate.
- The URL model's original training data and training pipeline are not present in this checkout, so this evaluates the shipped artifact but cannot reproduce its training.
- Collect multiple days, keep domains disjoint between development and final test sets, freeze the threshold before the final run, and report confidence intervals before making accuracy claims.
