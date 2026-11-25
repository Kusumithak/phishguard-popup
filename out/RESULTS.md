# URL Model Results

## Evaluation setup

Split: **domain-grouped random; NOT a time split**. The dataset has 1 collection day.
Test set: 36 phishing and 267 benign URLs (303 rows).
Smallest resolvable FPR: `1/267 = 0.00374532` (0.37%, about 0.4%).
At the 0.1% FPR target, the test set can only report zero false positives: one false positive is already about 0.4% FPR.

The candidate is the full-feature GB model. It was selected by OOF PR-AUC only; the test set was not used for model selection.
OOF PR-AUC: LR `0.928428`, GB `0.972474`.

## Test-set metrics

| Feature set | Model | ROC-AUC | PR-AUC | Recall @ 0.1% FPR | Recall @ 1% FPR | Recall @ 5% FPR | Precision @ 0.5% prevalence, 0.1% FPR | Precision @ 0.5% prevalence, 1% FPR | Precision @ 0.5% prevalence, 5% FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | LR | 0.960206 | 0.908031 | 0.583333 | 0.833333 | 0.888889 | 1.000000 | 0.358582 | 0.084032 |
| baseline | GB | 0.964784 | 0.919213 | 0.722222 | 0.861111 | 0.888889 | 1.000000 | 0.366158 | 0.097816 |
| host | LR | 0.950114 | 0.904039 | 0.861111 | 0.861111 | 0.861111 | 1.000000 | 1.000000 | 0.161468 |
| host | GB | 0.947201 | 0.915410 | 0.861111 | 0.861111 | 0.888889 | 1.000000 | 1.000000 | 0.084032 |
| full | LR | 0.969101 | 0.919887 | 0.750000 | 0.833333 | 0.888889 | 1.000000 | 0.358582 | 0.117009 |
| full | GB | 0.978985 | 0.975659 | 0.972222 | 0.972222 | 0.972222 | 1.000000 | 1.000000 | 1.000000 |

Baseline contains the eight non-scheme features shared with the shipped nine-feature model. `has_https` is excluded by the hard rule against scheme features.

The old shipped model is not included: its `has_https` input violates that same feature rule, so scoring it would not be a compliant comparison.

## Limitations

- Benign Tranco URLs use synthetic paths. The host-only versus full-feature gap may partly reflect this path construction.
- Phishing dates are first-seen collection dates, not confirmed domain creation dates.
- The dataset contains one collection day, so this evaluation cannot measure temporal generalization.
- URL-only features cannot inspect page content or DOM behavior.
- Hashed character n-gram buckets can collide.
- The test set is small (36 phishing and 267 benign URLs); recall at very low FPR is noisy.

## Handoff notes

The join key is `url`. `url_oof_train.csv` carries OOF probabilities for fusion training. `url_test_pred.csv` is reserved for the single final evaluation and must not be used for fitting or model selection.
