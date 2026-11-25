#!/usr/bin/env python3
"""Attach OOF/test/model URL probabilities to an input CSV without fetching URLs."""
import argparse
import csv
from contextlib import nullcontext
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "training"))
from url_pipeline import score_model  # noqa: E402


def score_with_model(model, url):
    return score_model(model, url)


def read_probabilities(path):
    result = {}
    if not path.exists():
        return result
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            result[row["url"]] = float(row["ml_prob"])
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_csv", help="CSV path, or - to read stdin")
    p.add_argument("output_csv", help="CSV path, or - to write stdout")
    p.add_argument("--model", type=Path, default=ROOT / "out" / "model.json")
    p.add_argument("--oof", type=Path, default=ROOT / "out" / "url_oof_train.csv")
    p.add_argument("--test", type=Path, default=ROOT / "out" / "url_test_pred.csv")
    args = p.parse_args()

    oof = read_probabilities(args.oof)
    test = read_probabilities(args.test)
    model = None
    input_context = open(args.input_csv, newline="", encoding="utf-8") if args.input_csv != "-" else nullcontext(sys.stdin)
    with input_context as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            p.error("input CSV must have a `url` column")
        rows = list(reader)
    if args.output_csv != "-":
        Path(args.output_csv).parent.mkdir(parents=True, exist_ok=True)
    output_context = open(args.output_csv, "w", newline="", encoding="utf-8") if args.output_csv != "-" else nullcontext(sys.stdout)
    with output_context as output:
        writer = csv.DictWriter(output, fieldnames=["url", "ml_prob", "prob_source"])
        writer.writeheader()
        counts = {"oof": 0, "test": 0, "model": 0}
        for row in rows:
            url = row["url"]
            if url in oof:
                probability, source = oof[url], "oof"
            elif url in test:
                probability, source = test[url], "test"
            else:
                if model is None:
                    with args.model.open(encoding="utf-8") as model_file:
                        model = json.load(model_file)
                probability, source = score_with_model(model, url), "model"
            writer.writerow({"url": url, "ml_prob": probability, "prob_source": source})
            counts[source] += 1
    print(f"Wrote {len(rows)} rows to {args.output_csv}; sources={counts}",
          file=sys.stderr if args.output_csv == "-" else sys.stdout)


if __name__ == "__main__":
    main()
