# URL Model Results

## Run status

Training and evaluation did not run because source collection could not resolve external hosts and the required Python packages could not be installed. This file contains no model metrics.

The requested dataset path is `C:\Users\praka\Desktop\ckd\phishguard-popup\data\urls.csv`. It was not created (0 rows). No phishing snapshots were written (0 collection days); downloaded phishing rows were 0 from OpenPhish, 0 from Phishing.Database, and 0 from PhishTank. Tranco benign rows were 0. The benign:phishing ratio is undefined because there are no phishing rows.

Commands and observed failures:

- `py -m venv .venv` failed with `No installed Python found!`; Python 3.12 was then used directly to create `.venv`.
- `.\.venv\Scripts\python -m pip install -r requirements.txt` failed because DNS resolution for PyPI failed (`getaddrinfo failed`), ending with `No matching distribution found for numpy`.
- `.\.venv\Scripts\python training\url_pipeline.py collect` reported `[Errno 11001] getaddrinfo failed` for OpenPhish, Phishing.Database, PhishTank, and Tranco.
- `.\.venv\Scripts\python training\url_pipeline.py build` exited because `data/raw\tranco_top.csv` is missing.
- `.\.venv\Scripts\python training\url_pipeline.py train` exited with `ModuleNotFoundError: No module named 'numpy'`.

The Phishing.Database source URL in the script now matches its current README link: `https://phish.co.za/latest/phishing-links-ACTIVE.txt`. Its endpoint returned HTTP 503 when checked through the web tool; the local collection run could not resolve DNS. The project's README lists `phishing-links-ACTIVE.txt` as its active URL feed. OpenPhish's community README documents the feed URL used by the script and its 12-hour update cadence. PhishTank's official documentation lists an unkeyed downloadable CSV but limits unkeyed downloads to a few per day, so the pipeline includes the feed for the once-daily run. See the [Phishing.Database README](https://github.com/Phishing-Database/Phishing.Database/blob/master/README.md), [OpenPhish public feed README](https://github.com/openphish/public_feed/blob/main/README.md), and [PhishTank developer information](https://phishtank.org/developer_info.php).

## Shipped model reference

`ml/model.json` has nine inputs and `data/README.md` identifies PhiUSIIL as its training dataset. The input names and definitions in `ml/inference.js` are:

| Feature | Definition |
|---|---|
| `host_length` | Hostname length after lowercasing, removing a trailing dot, and removing leading `www.` |
| `deep_subdomain_count` | Subdomain levels beyond the first, using the inference module's short second-level suffix list |
| `digit_ratio` | Hostname digits divided by hostname length |
| `hyphen_count` | Number of hyphens in the hostname |
| `has_userinfo` | 1 when URL username or password is non-empty |
| `has_https` | 1 when scheme is HTTPS; excluded from the new feature sets by the task's hard rule |
| `has_ip` | 1 for IPv4 or colon-containing IP hostname |
| `host_keyword_count` | Count of exact suspicious keyword tokens in the hostname |
| `has_punycode` | 1 when hostname contains `xn--` |

The strict baseline therefore contains the eight non-scheme features. The old shipped-model comparison cannot be computed without a test set and would use its prohibited `has_https` feature.

## Metrics

No split was created. This is not a time split or a domain-grouped split. `n_test_benign` and the minimum resolvable FPR are unavailable because there is no test set. No LR/GB metrics, coefficient ranking, or primary model selection were produced.

| Feature set | LR | GB |
|---|---|---|
| baseline | Not run | Not run |
| host | Not run | Not run |
| full | Not run | Not run |

Top LR coefficients and shortcut-artifact checks: unavailable because no model was trained. Candidate selection by OOF PR-AUC: not run. Synthetic fixtures are used only for feature/scoring smoke tests and are not evaluation data.

## Handoff notes

The intended join key is `url`. `url_oof_train.csv` is for fusion training; `url_test_pred.csv` is reserved for the single final evaluation. Neither file exists until training succeeds. The DOM teammate's phishing URL input would be `data/urls.csv`; the DOM set is expected to be smaller than the URL set.

## Data limitations

Tranco supplies domains only, so benign paths produced by `build` are synthetic. Phishing dates are first-seen collection dates. A single or small number of collection days cannot support a time split. URL-only features cannot inspect page content. Hashed n-gram buckets can collide. Recall at very low FPR is noisy when the test set is small.
