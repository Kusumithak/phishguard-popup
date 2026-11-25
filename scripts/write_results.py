#!/usr/bin/env python3
"""Render out/RESULTS.md from saved metrics, split metadata, and OOF predictions."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def average_precision(rows, column):
    ordered = sorted(((float(row[column]), int(row["label"])) for row in rows),
                     key=lambda pair: pair[0], reverse=True)
    positives = sum(label for _, label in ordered)
    if positives == 0:
        raise ValueError("OOF predictions contain no positive rows")
    tp = fp = previous_tp = 0
    result = 0.0
    index = 0
    while index < len(ordered):
        end = index
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            if ordered[end][1]:
                tp += 1
            else:
                fp += 1
            end += 1
        if tp > previous_tp:
            result += (tp - previous_tp) / positives * (tp / (tp + fp))
            previous_tp = tp
        index = end
    return result


def main():
    metrics = read_csv(OUT / "metrics.csv")
    oof = read_csv(OUT / "url_oof_train.csv")
    with (OUT / "split_info.json").open(encoding="utf-8") as stream:
        split = json.load(stream)
    with (OUT / "url_test_pred.csv").open(newline="", encoding="utf-8") as stream:
        test_rows = list(csv.DictReader(stream))

    expected = {(feature_set, model) for feature_set in ("baseline", "host", "full") for model in ("lr", "gb")}
    actual = {(row["feature_set"], row["model"]) for row in metrics}
    if actual != expected:
        raise ValueError(f"metrics.csv must contain baseline/host/full x lr/gb; found {sorted(actual)}")

    test_benign = int(split["test_benign"])
    test_phish = int(split["test_phish"])
    min_fpr = 1 / test_benign
    oof_pr = {name: average_precision(oof, f"prob_{name}") for name in ("lr", "gb")}
    primary = max(oof_pr, key=oof_pr.get)
    if primary != "gb":
        raise ValueError(f"saved OOF probabilities select {primary}, but the candidate is expected to be GB")

    lines = [
        "# URL Model Results",
        "",
        "## Evaluation setup",
        "",
        f"Split: **domain-grouped random; NOT a time split**. The dataset has {split['phishing_days']} collection day.",
        f"Test set: {test_phish} phishing and {test_benign} benign URLs ({len(test_rows)} rows).",
        f"Smallest resolvable FPR: `1/{test_benign} = {min_fpr:.8f}` ({100 * min_fpr:.2f}%, about 0.4%).",
        "At the 0.1% FPR target, the test set can only report zero false positives: one false positive is already about 0.4% FPR.",
        "",
        "The candidate is the full-feature GB model. It was selected by OOF PR-AUC only; the test set was not used for model selection.",
        f"OOF PR-AUC: LR `{oof_pr['lr']:.6f}`, GB `{oof_pr['gb']:.6f}`.",
        "",
        "## Test-set metrics",
        "",
        "| Feature set | Model | ROC-AUC | PR-AUC | Recall @ 0.1% FPR | Recall @ 1% FPR | Recall @ 5% FPR | Precision @ 0.5% prevalence, 0.1% FPR | Precision @ 0.5% prevalence, 1% FPR | Precision @ 0.5% prevalence, 5% FPR |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for feature_set in ("baseline", "host", "full"):
        for model in ("lr", "gb"):
            row = next(item for item in metrics if item["feature_set"] == feature_set and item["model"] == model)
            lines.append(
                f"| {feature_set} | {model.upper()} | {float(row['roc_auc']):.6f} | {float(row['pr_auc']):.6f} | "
                f"{float(row['recall@fpr0.001']):.6f} | {float(row['recall@fpr0.01']):.6f} | {float(row['recall@fpr0.05']):.6f} | "
                f"{float(row['precision@fpr0.001_prev0.5%']):.6f} | {float(row['precision@fpr0.01_prev0.5%']):.6f} | {float(row['precision@fpr0.05_prev0.5%']):.6f} |"
            )
    lines += [
        "",
        "Baseline contains the eight non-scheme features shared with the shipped nine-feature model. `has_https` is excluded by the hard rule against scheme features.",
        "",
        "The old shipped model is not included: its `has_https` input violates that same feature rule, so scoring it would not be a compliant comparison.",
        "",
        "## Limitations",
        "",
        "- Benign Tranco URLs use synthetic paths. The host-only versus full-feature gap may partly reflect this path construction.",
        "- Phishing dates are first-seen collection dates, not confirmed domain creation dates.",
        "- The dataset contains one collection day, so this evaluation cannot measure temporal generalization.",
        "- URL-only features cannot inspect page content or DOM behavior.",
        "- Hashed character n-gram buckets can collide.",
        f"- The test set is small ({test_phish} phishing and {test_benign} benign URLs); recall at very low FPR is noisy.",
        "",
        "## Handoff notes",
        "",
        "The join key is `url`. `url_oof_train.csv` carries OOF probabilities for fusion training. `url_test_pred.csv` is reserved for the single final evaluation and must not be used for fitting or model selection.",
        "",
    ]
    (OUT / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT / 'RESULTS.md'} from metrics.csv; rows={len(metrics)}; OOF primary={primary}.")


if __name__ == "__main__":
    main()
