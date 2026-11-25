"""Creates a synthetic scorer fixture for parity smoke tests only."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "training"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

from test_features import URLS  # noqa: E402
from score_urls import score_with_model  # noqa: E402
from url_pipeline import BASELINE, extract, lexicon  # noqa: E402


def main():
    model_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    urls = list(URLS)
    domains = ["example.com", "example.org", "paypal-login.xyz", "amazonaws.com", "google.co.in"]
    paths = ["/", "/login", "/account/verify", "/search?q=a%2Fb", "/path//double"]
    for i in range(200 - len(urls)):
        urls.append(f"https://node{i}.{domains[i % len(domains)]}{paths[i % len(paths)]}")
    if model_path is not None:
        model = json.loads(model_path.read_text(encoding="utf-8"))
    else:
        model = {
            "type": "lr",
            "version": 1,
            "features": BASELINE,
            "lexicon": lexicon(),
            "mean": [0.0] * len(BASELINE),
            "scale": [1.0] * len(BASELINE),
            "coef": [0.025, 0.12, 0.4, 0.08, 0.3, 0.7, 0.09, 0.45],
            "intercept": -1.1,
        }
    rows = [{"url": url, "features": extract(url), "score": score_with_model(model, url)} for url in urls]
    print(json.dumps({"model": model, "rows": rows}, ensure_ascii=False))


if __name__ == "__main__":
    main()
