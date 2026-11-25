# PhishGuard Role 1 Evaluation Status

## Decision

Do not promote a candidate or change `hybrid.js`. This checkout does not contain the labeled training/evaluation data or out-of-fold predictions needed to fit and validate a learned fusion model.

## Verified from the repository

- `data/README.md` names PhiUSIIL as the shipped model's training dataset and says the raw CSV and training script are not present.
- `ml/inference.js` loads a nine-feature logistic regression model from `ml/model.json`.
- `hybrid.js` uses hand-set weights: 30% ML, 30% URL rules, and 40% DOM when ML is available; 50% URL rules and 50% DOM otherwise.
- The shipped decision bands are SAFE below 35, SUSPICIOUS from 35 to 49, and PHISHING at 50 or above.

## Not run

This checkout has no OOF predictions, labeled validation set, or untouched test set. Therefore we did not fit stacked logistic regression or calibration, select a threshold at FPR <= 0.1%, run the final test, or compute ablations, ROC/PR curves, a reliability curve, or latency. Existing numerical results in the supplied deck could not be reproduced from the available files and were removed from its evaluation slides.

## Resume requirements

Restore the dataset and training pipeline, provide domain-grouped OOF URL/rule/DOM predictions and a separate labeled test set, then fit the stacker and calibration on OOF data. Select the threshold on validation data at FPR <= 0.1%, freeze the candidate, and evaluate the untouched test set once. Consider promotion only after the results are reproducible.
