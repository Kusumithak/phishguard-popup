
# PhishGuard – Evaluation Report

## 1. Objective

The objective of this evaluation is to analyse the performance of the PhishGuard phishing detection framework by comparing its individual detection layers and combined fusion system.

The evaluation focuses on:
- Machine Learning URL detection
- URL heuristic detection
- DOM-based detection
- Hybrid URL and DOM fusion
- DOM feature ablation analysis

## 2. Dataset

The evaluation was performed using the available labelled DOM dataset.

| Category | Count |
|---|---:|
| Total samples | 136 |
| Phishing URLs | 76 |
| Benign URLs | 60 |

All 136 rows were included in the offline evaluation.

## 3. Evaluation Methodology

The following configurations were evaluated:

- ML_ONLY: Machine learning URL prediction.
- URL_RULES_ONLY: URL heuristic rules.
- DOM_ONLY: DOM feature scoring.
- URL_ONLY: Hybrid engine without DOM signals.
- FULL_FUSION: Complete hybrid detection system.
- REDUCED_DOM_FUSION: Hybrid system without external resource ratio and foreign favicon features.

ROC-AUC was used to compare the ability of each configuration to distinguish phishing from benign samples.

Confusion-matrix metrics were also calculated for configurations with defined verdict thresholds.

## 4. Overall Results

| Configuration | ROC-AUC |
|---|---:|
| ML_ONLY | 0.6976 |
| URL_RULES_ONLY | 0.4434 |
| DOM_ONLY | 0.4851 |
| URL_ONLY | 0.7019 |
| FULL_FUSION | 0.6746 |
| REDUCED_DOM_FUSION | 0.7185 |

REDUCED_DOM_FUSION achieved the highest ROC-AUC of 0.7185 among the evaluated configurations.

## 5. Full Fusion vs Reduced DOM Fusion

| Metric | Full Fusion | Reduced DOM Fusion |
|---|---:|---:|
| ROC-AUC | 0.6746 | 0.7185 |
| Accuracy (Phishing verdict) | 58.82% | 55.15% |
| Precision | 72.73% | 85.71% |
| Recall | 42.11% | 23.68% |
| F1-score | 53.33% | 37.11% |
| False Positive Rate | 20.00% | 5.00% |

Reduced DOM fusion improved AUC, precision and false-positive rate, but reduced phishing recall.

Therefore, higher AUC does not automatically mean better phishing detection at every decision threshold.

## 6. DOM Feature Ablation Analysis

Individual DOM features were removed one at a time to study their effect on the full fusion system.

| Removed Feature | ROC-AUC |
|---|---:|
| External resource ratio | 0.7033 |
| Foreign favicon | 0.7127 |
| Void links ratio | 0.6614 |
| Meta refresh | 0.6950 |
| Eval/atob hits | 0.6886 |
| Brand-domain mismatch | 0.6432 |
| Password external form | 0.6816 |

Removing external resource ratio and foreign favicon individually improved AUC compared with full fusion.

Removing void links ratio and brand-domain mismatch reduced AUC, suggesting that these features may contribute useful information on this dataset.

## 7. Observations

- The ML-only configuration achieved an AUC of 0.6976.
- URL rules-only and DOM-only had lower standalone AUC values.
- Full fusion improved phishing recall compared with URL-only detection at the current phishing threshold.
- Reduced DOM fusion achieved the highest AUC in this experiment.
- Individual feature ablation showed that different DOM features affect performance differently.

## 8. Limitations

- The dataset contains only 136 unique domains.
- The evaluation is preliminary and offline.
- The dataset represents a limited collection of phishing and benign samples.
- CSV-based DOM features may differ from the features extracted by the live browser extension.
- Results should not be treated as proof of generalisation to unseen websites.
- Further testing on larger and independent datasets is required.

## 9. Conclusion

The evaluation demonstrates that combining machine learning, URL heuristics and DOM analysis changes the detection performance of PhishGuard.

Reduced DOM fusion achieved the highest ROC-AUC of 0.7185 in the current experiment. However, its lower phishing recall indicates that additional threshold and fusion-weight evaluation is necessary.

Further validation using larger datasets is required before selecting a final production configuration.
