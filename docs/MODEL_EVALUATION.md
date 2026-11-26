# URL model evaluation workflow

PhishGuard now has an offline evaluator for the URL model that is actually shipped in `ml/model.json`. It calls the same feature extraction and logistic scoring function used by the extension, so the benchmark does not maintain a second copy of the model math.

## Run it

From the project root:

```powershell
npm run evaluate:url-model
```

By default, the command reads `data/dom/dom_labeled.csv` and writes `out/url_model_evaluation.md`. To use another labeled file:

```powershell
node tools/evaluate_url_model.js --input path\to\labeled.csv --output out\evaluation.md
```

The CSV must contain `url`, `label`, `domain`, and `fetch_ok`. Labels use `1` for phishing and `0` for benign. Unfetched rows are skipped. The evaluator requires both classes and one row per registrable domain; duplicate domains stop the run to avoid overstating performance through domain leakage. It reads URL text only and never opens or fetches a URL.

## What the report contains

- ROC-AUC and average precision for the shipped model and URL heuristics.
- Reproducible, stratified 95% percentile bootstrap intervals for those ranking metrics.
- Confusion counts, recall, false-positive rate, and precision at a fixed 0.50 score threshold.
- Empirical operating points at 0.1%, 1%, and 5% false-positive-rate caps.
- Dataset size, class counts, crawl dates, skipped rows, and the one-false-positive resolution of the benign sample.

The operating points are descriptive because they choose a threshold on the same data they score. The report labels this explicitly. They are not validated deployment thresholds. Bootstrap intervals measure sampling variation within this dataset only; they do not account for collection-source or temporal bias.

## Current evidence limits

The checked-in DOM-derived URL set is small and covers one crawl day. Its sampled class balance is unlike normal browsing, so precision is not a prediction of how often a warning is correct for a user. At this size, a single benign false positive moves the measured FPR substantially. The model's cited source dataset and training pipeline are not included, so this workflow evaluates the deployed artifact but cannot reproduce training.

For a defensible final evaluation, collect multiple dates, remove duplicate and related domains across partitions, use a development set for any threshold selection, freeze the model and threshold, and score a domain-disjoint untouched test set once. Report uncertainty intervals and the exact dataset snapshot with the resulting metrics.
