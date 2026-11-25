#!/usr/bin/env python3
"""
PhishGuard - Role 2 (URL data + URL model)

  python url_pipeline.py collect            # download phishing feeds + Tranco (run DAILY for phishing)
  python url_pipeline.py build              # merge snapshots -> data/urls.csv
  python url_pipeline.py train              # features -> split -> models -> metrics -> model.json

Feature logic is mirrored in url_model.js. The lexicons (keywords, brands, ...) are
shipped INSIDE the exported model JSON, so Python and JS cannot drift apart.
The URL scheme is stripped before any feature is computed, so http/https can never leak the label.
"""
import argparse, csv, datetime as dt, glob, io, json, math, os, random, re, shutil, sys, urllib.request, zipfile
from collections import Counter

# ----------------------------------------------------------------------------
# Lexicon (exported with the model)
# ----------------------------------------------------------------------------
MULTI = ["co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
         "org.in", "net.in", "com.au", "net.au", "org.au", "co.jp", "com.br", "com.cn", "co.za", "com.mx",
         "co.nz", "com.sg", "com.pk", "com.bd", "com.tr", "com.ng"]
KEYWORDS = ["login", "signin", "secure", "verify", "account", "update", "bank", "wallet", "confirm", "password",
            "billing", "support", "auth", "recover", "suspend", "unlock", "invoice", "payment", "security", "alert"]
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.in", "googleapis.com", "googleusercontent.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com",
                  "msn.com", "bing.com", "windows.com", "azure.com", "sharepoint.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"],
    "facebook": ["facebook.com", "fb.com", "fb.me"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "adobe": ["adobe.com"],
    "yahoo": ["yahoo.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "irctc": ["irctc.co.in"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
}
N_TLD, N_NG = 32, 256

HOST_NUM = ["host_len", "n_dots_host", "n_subdomains", "n_hyphens_host", "n_digits_host", "digit_ratio_host",
            "host_entropy", "longest_label", "tld_len", "is_ip", "has_at", "has_punycode", "has_port",
            "kw_host", "brand_mismatch_host", "host_length", "deep_subdomain_count", "digit_ratio",
            "hyphen_count", "has_ip", "has_userinfo", "host_keyword_count"]
PATH_NUM = ["url_len", "path_len", "query_len", "path_depth", "n_params", "n_pct", "path_entropy",
            "double_slash", "kw_path", "brand_in_path"]
# The shipped 9-feature model includes has_https. The task's hard rule forbids
# scheme features, so the compliant baseline uses its other 8 host features.
BASELINE = ["host_length", "deep_subdomain_count", "digit_ratio", "hyphen_count",
            "has_userinfo", "has_ip", "host_keyword_count", "has_punycode"]
TLD_NAMES = [f"tld_h{i}" for i in range(N_TLD)]
NG_NAMES = [f"ng_h{i}" for i in range(N_NG)]
FEATURE_SETS = {
    "baseline": BASELINE,
    "host": HOST_NUM + TLD_NAMES,
    "full": HOST_NUM + PATH_NUM + TLD_NAMES + NG_NAMES,
}

# ----------------------------------------------------------------------------
# Feature extraction (keep identical to url_model.js)
# ----------------------------------------------------------------------------
NONASCII = re.compile(r"[^\x00-\x7f]")
SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MULTI_SET = set(MULTI)


def fnv1a(s):
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def parse(url):
    u = NONASCII.sub("?", url.strip())
    u = SCHEME.sub("", u, count=1)
    m = re.search(r"[/?#]", u)
    authority, rest = (u[:m.start()], u[m.start():]) if m else (u, "")
    has_at = "@" in authority
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    port = ""
    mp = re.search(r":(\d+)$", authority)
    if mp:
        port, authority = mp.group(1), authority[:mp.start()]
    host = authority.lower().strip(".")
    rest = rest.split("#", 1)[0]
    path, query = rest.split("?", 1) if "?" in rest else (rest, "")
    return u, host, port, path, query, has_at


def split_host(host):
    if IPV4.match(host) or host.startswith("["):
        return [host], host, [], ""
    labels = [l for l in host.split(".") if l]
    if labels and labels[0] == "www":
        labels = labels[1:]
    k = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SET else 2
    k = min(k, len(labels))
    reg = ".".join(labels[-k:]) if labels else ""
    return labels, reg, labels[:len(labels) - k], (labels[-1] if labels else "")


def group_of(url):
    return split_host(parse(url)[1])[1]


def host_of(url):
    h = parse(url)[1]
    return h[4:] if h.startswith("www.") else h


def _brand_hit(b, text, toks):
    return (b in text) if len(b) >= 6 else (b in toks)


def extract(url):
    u, host, port, path, query, has_at = parse(url)
    match = re.search(r"[/?#]", u)
    authority = u[:match.start()] if match else u
    userinfo = authority.rsplit("@", 1)[0] if "@" in authority else ""
    username, separator, password = userinfo.partition(":")
    has_userinfo = bool(username or (separator and password))
    labels, reg, sub, tld = split_host(host)
    is_ip = 1 if (IPV4.match(host) or host.startswith("[")) else 0
    pathq_raw = path + ("?" + query if query else "")
    pathq = pathq_raw.lower()
    host_toks = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    path_toks = [t for t in re.split(r"[^a-z0-9]+", pathq) if t]
    n_digits = sum(ch.isdigit() for ch in host)
    model_host = host[4:] if host.startswith("www.") else host
    model_labels = model_host.split(".") if model_host else []
    old_second_level = {"co", "com", "ac", "edu", "gov", "org", "net", "or", "ne", "go"}
    old_suffix_len = (2 if len(model_labels) >= 3 and len(model_labels[-1]) == 2
                      and model_labels[-2] in old_second_level else 1)
    old_subdomain_count = max(0, len(model_labels) - old_suffix_len - 1) if not is_ip else 0
    old_deep_subdomains = max(0, old_subdomain_count - 1)
    old_keywords = {"login", "signin", "verify", "verification", "account", "secure", "security", "update",
                    "password", "credential", "authenticate", "bank", "banking", "payment", "billing",
                    "wallet", "card", "transaction", "urgent", "suspended", "blocked", "expired"}
    old_host_tokens = [t for t in re.split(r"[^a-z0-9]+", model_host) if t]
    f = {
        "host_len": len(host), "n_dots_host": host.count("."), "n_subdomains": len(sub),
        "n_hyphens_host": host.count("-"), "n_digits_host": n_digits,
        "digit_ratio_host": n_digits / len(host) if host else 0.0,
        "host_entropy": entropy(host), "longest_label": max((len(l) for l in labels), default=0),
        "tld_len": len(tld), "is_ip": is_ip, "has_at": 1 if has_at else 0,
        "has_punycode": 1 if "xn--" in host else 0,
        "has_port": 1 if port and port not in ("80", "443") else 0,
        "kw_host": sum(1 for k in KEYWORDS if k in host),
        "brand_mismatch_host": 1 if any(_brand_hit(b, host, host_toks) and reg not in off
                                        for b, off in BRANDS.items()) else 0,
        "host_length": len(model_host),
        "deep_subdomain_count": old_deep_subdomains,
        "digit_ratio": sum(ch.isdigit() for ch in model_host) / len(model_host) if model_host else 0.0,
        "hyphen_count": model_host.count("-"),
        "has_ip": is_ip,
        "has_userinfo": 1 if has_userinfo else 0,
        "host_keyword_count": sum(1 for token in old_host_tokens if token in old_keywords),
        "url_len": len(u), "path_len": len(path), "query_len": len(query),
        "path_depth": path.count("/"), "n_params": len([p for p in query.split("&") if p]),
        "n_pct": u.count("%"), "path_entropy": entropy(pathq_raw),
        "double_slash": 1 if "//" in path else 0,
        "kw_path": sum(1 for k in KEYWORDS if k in pathq),
        "brand_in_path": 1 if any(_brand_hit(b, pathq, path_toks) and reg not in off
                                  for b, off in BRANDS.items()) else 0,
    }
    if tld:
        f[f"tld_h{fnv1a(tld) % N_TLD}"] = 1
    s = host + pathq
    n_tri = max(1, len(s) - 2)
    for i in range(len(s) - 2):
        key = f"ng_h{fnv1a(s[i:i + 3]) % N_NG}"
        f[key] = f.get(key, 0) + 1.0 / n_tri
    return f


def lexicon():
    return {"multi": MULTI, "keywords": KEYWORDS, "brands": BRANDS, "n_tld": N_TLD, "n_ng": N_NG}


def score_model(model, url):
    """Pure-Python scorer for exported LR/GB models; mirrors ml/url_model.js."""
    f = extract(url)
    x = [f.get(name, 0.0) for name in model["features"]]
    if model["type"] == "lr":
        z = model["intercept"]
        for value, mean, scale, coef in zip(x, model["mean"], model["scale"], model["coef"]):
            z += coef * ((value - mean) / scale)
    elif model["type"] == "gb":
        z = model["init"]
        for tree in model["trees"]:
            node = 0
            while tree["l"][node] != -1:
                node = tree["l"][node] if x[tree["f"][node]] <= tree["t"][node] else tree["r"][node]
            z += model["lr"] * tree["v"][node]
    else:
        raise ValueError(f"unsupported model type: {model['type']}")
    if z >= 0:
        return 1 / (1 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1 + ez)


# ----------------------------------------------------------------------------
# collect
# ----------------------------------------------------------------------------
def http_get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-academic/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


PHISH_SOURCES = {
    "openphish": "https://openphish.com/feed.txt",
    "phishingdb": "https://phish.co.za/latest/phishing-links-ACTIVE.txt",
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",
}


def cmd_collect(a):
    os.makedirs(a.raw, exist_ok=True)
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    rows = []
    failures = []
    for name, url in PHISH_SOURCES.items():
        try:
            body = http_get(url).decode("utf-8", "ignore")
            if name == "phishtank":
                feed = csv.DictReader(io.StringIO(body))
                found = [(r.get("url", "").strip(), today)
                         for r in feed if r.get("url", "").strip().lower().startswith("http")]
            else:
                found = [(line.strip(), today) for line in body.splitlines()
                         if line.strip().lower().startswith("http")]
            if a.max_per_source:
                found = found[:a.max_per_source]
            rows += [(u, name, date) for u, date in found]
            print(f"[collect] {name}: {len(found)} urls")
        except Exception as e:
            print(f"[collect] {name} FAILED: {e}")
            if name != "phishtank":
                failures.append(name)
    if rows:
        path = os.path.join(a.raw, f"phish_{today}.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["url", "source", "date"])
            w.writerows(rows)
        print(f"[collect] wrote {path}")
    tr = os.path.join(a.raw, "tranco_top.csv")
    if not a.phish_only and not os.path.exists(tr):
        try:
            z = zipfile.ZipFile(io.BytesIO(http_get("https://tranco-list.eu/top-1m.csv.zip", 300)))
            lines = z.read("top-1m.csv").decode().splitlines()[:a.tranco_n]
            with open(tr, "w", newline="", encoding="utf-8") as fh:
                fh.write("rank,domain\n" + "\n".join(lines) + "\n")
            print(f"[collect] wrote {tr} ({len(lines)} domains)")
        except Exception as e:
            print(f"[collect] Tranco FAILED: {e}  (download top-1m.csv manually and save as {tr})")
            failures.append("tranco")
    if failures:
        sys.exit(f"collection incomplete; required sources failed: {', '.join(failures)}")


# ----------------------------------------------------------------------------
# build
# ----------------------------------------------------------------------------
BENIGN_PATHS = ["", "", "", "/login", "/signin", "/account/login", "/wp-login.php", "/search?q=news",
                "/products/12345", "/blog/2024/post-title", "/about", "/help/contact", "/users/sign_in",
                "/en/index.html", "/category/electronics?page=2"]


def cmd_build(a):
    rng = random.Random(a.seed)
    seen, dates = {}, set()
    for fpath in sorted(glob.glob(os.path.join(a.raw, "phish_*.csv"))):
        with open(fpath, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                h = host_of(r["url"])
                if h and h not in seen:                  # dedupe by full host, keep earliest sighting
                    seen[h] = r
                dates.add(r["date"])
    tr_path = os.path.join(a.raw, "tranco_top.csv")
    if not os.path.isfile(tr_path):
        sys.exit(f"Tranco list missing: {tr_path}; run collect or place rank,domain rows there")
    tranco = [l.split(",", 1)[1].strip().lower() for l in open(tr_path, encoding="utf-8").read().splitlines()[1:]]
    tr_set = set(tranco)
    phish = [r for h, r in seen.items() if h not in tr_set]
    if not phish:
        sys.exit("no phishing rows - run `collect` first")
    n_benign = min(len(tranco), int(a.benign_ratio * len(phish)))
    picks = rng.sample(tranco, n_benign)
    dl = sorted(dates)
    out = [(r["url"], 1, r["source"], r["date"]) for r in phish]
    for d in picks:                                       # NOTE: synthetic benign paths, see README caveat
        host = ("www." + d) if rng.random() < 0.3 else d
        out.append((f"https://{host}{rng.choice(BENIGN_PATHS)}", 0, "tranco", rng.choice(dl)))
    rng.shuffle(out)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "source", "date"])
        w.writerows(out)
    per_source = Counter(r["source"] for r in phish)
    print(f"[build] phishing by source: {dict(sorted(per_source.items()))}")
    print(f"[build] {len(phish)} phishing + {n_benign} benign -> {a.out}")
    print(f"[build] benign:phishing ratio={n_benign / len(phish):.3f}; {len(dl)} distinct phishing collection days")


# ----------------------------------------------------------------------------
# train / evaluate / export
# ----------------------------------------------------------------------------
def metrics(y, p, prev=0.005):
    from sklearn.metrics import roc_curve, roc_auc_score, average_precision_score
    import numpy as np
    fpr, tpr, _ = roc_curve(y, p)
    out = {"roc_auc": roc_auc_score(y, p), "pr_auc": average_precision_score(y, p)}
    for t in (0.001, 0.01, 0.05):
        idx = int(np.where(fpr <= t)[0][-1])
        r, f = float(tpr[idx]), float(fpr[idx])
        out[f"recall@fpr{t}"] = r
        den = r * prev + f * (1 - prev)
        out[f"precision@fpr{t}_prev0.5%"] = (r * prev / den) if den > 0 else float("nan")
    return out


def write_results(out_dir, rows, info, primary, oof_pr, coefs, data_frame):
    """Write the reproducible evaluation summary; never substitutes smoke data."""
    n_benign = int(info["test_benign"])
    min_fpr = 1 / n_benign if n_benign else float("nan")
    phish_sources = Counter(data_frame.loc[data_frame.label == 1, "source"].fillna("unknown"))
    lines = [
        "# URL Model Results",
        "",
        f"Split: **{info['method']}**.",
        f"Training rows: {info['n_train']}; test rows: {info['n_test']}; test phishing: {info['test_phish']}; test benign: {n_benign}.",
        f"Phishing rows by source in the full dataset: `{dict(sorted(phish_sources.items()))}`.",
        f"Smallest resolvable FPR: {min_fpr:.8f} (1 / n_test_benign)." if n_benign else "Smallest resolvable FPR: unavailable because the test set has no benign rows.",
        "",
        "## Model comparison",
        "",
        "| Feature set | Model | ROC-AUC | PR-AUC | Recall @ 0.1% FPR | Recall @ 1% FPR | Recall @ 5% FPR | Precision @ 0.5% prevalence, 0.1% FPR | Precision @ 0.5% prevalence, 1% FPR | Precision @ 0.5% prevalence, 5% FPR |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['feature_set']} | {r['model']} | {r['roc_auc']:.6f} | {r['pr_auc']:.6f} | "
            f"{r['recall@fpr0.001']:.6f} | {r['recall@fpr0.01']:.6f} | {r['recall@fpr0.05']:.6f} | "
            f"{r['precision@fpr0.001_prev0.5%']:.6f} | {r['precision@fpr0.01_prev0.5%']:.6f} | {r['precision@fpr0.05_prev0.5%']:.6f} |"
        )
    lines += [
        "| Old shipped model | Not scored: uses prohibited `has_https` | — | — | — | — | — | — | — | — |",
        "",
        "## Split and model selection",
        "",
        f"OOF PR-AUC: `{json.dumps(oof_pr, sort_keys=True)}`. The primary model `{primary}` was selected on OOF PR-AUC only, never on the test set.",
        "",
        "## Top 15 LR coefficients",
        "",
        "Coefficients are standardized LR coefficients, ranked by absolute magnitude:",
        "",
        "| Feature | Coefficient |",
        "|---|---:|",
    ]
    for name, coef in coefs:
        lines.append(f"| `{name}` | {coef:.8f} |")
    hashed = [name for name, _ in coefs if name.startswith(("ng_h", "tld_h"))]
    lines += [
        "",
        "Artifact check: " + (f"top coefficients include hashed buckets {hashed}; inspect for synthetic-path or source artifacts." if hashed else "no hashed n-gram or TLD bucket appears in the top 15."),
        "",
        "## Data caveats",
        "",
        "Phishing dates are first-seen collection dates. Tranco domains receive synthetic paths, so path features can learn the construction process. No dated benign source or licensed real-path benign source was added in this run.",
        "",
        "## Handoff notes",
        "",
        "Join key: `url`. `ml_prob` contains the primary URL-model probability selected on OOF PR-AUC. `url_oof_train.csv` is for fusion training; rows in `url_test_pred.csv` are reserved for the single final evaluation and must not be used to fit or choose anything.",
        "The DOM teammate can take phishing URL strings from `data/urls.csv`. The DOM set is expected to be smaller than the URL set.",
    ]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "RESULTS.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def export_lr(pipe, names):
    sc, lr = pipe.named_steps["sc"], pipe.named_steps["lr"]
    return {"type": "lr", "version": 1, "features": names, "lexicon": lexicon(),
            "mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(),
            "coef": lr.coef_[0].tolist(), "intercept": float(lr.intercept_[0])}


def export_gb(model, names, X0):
    ests = model.estimators_[:, 0]
    trees = []
    for e in ests:
        t = e.tree_
        trees.append({"f": t.feature.tolist(), "t": t.threshold.tolist(), "l": t.children_left.tolist(),
                      "r": t.children_right.tolist(), "v": t.value[:, 0, 0].tolist()})
    lr_ = float(model.learning_rate)
    init = float(model.decision_function(X0)[0] - lr_ * sum(e.predict(X0)[0] for e in ests))
    return {"type": "gb", "version": 1, "features": names, "lexicon": lexicon(),
            "init": init, "lr": lr_, "trees": trees}


def cmd_train(a):
    import numpy as np, pandas as pd
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold, GroupShuffleSplit
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    os.makedirs(a.out, exist_ok=True)
    df = pd.read_csv(a.data)
    df["group"] = [group_of(u) for u in df.url]
    allnames = FEATURE_SETS["full"]
    idx = {n: i for i, n in enumerate(allnames)}
    X = np.zeros((len(df), len(allnames)))
    for r, u in enumerate(df.url):
        for k, v in extract(u).items():
            X[r, idx[k]] = v
    y = df.label.values
    groups = df.group.values

    # ---- split -------------------------------------------------------------
    pd_dates = pd.to_datetime(df.date)
    phish_days = pd_dates[df.label == 1].dt.date.nunique()
    span = (pd_dates.max() - pd_dates.min()).days
    method = a.split if a.split != "auto" else ("time" if phish_days >= 5 and span >= 7 else "domain")
    if method == "time":
        latest_phish_day = pd_dates[df.label == 1].max().normalize()
        cutoff = latest_phish_day - pd.Timedelta(days=6)
        te_mask = (pd_dates >= cutoff).values
        te_groups = set(groups[te_mask])
        tr_mask = (~te_mask) & np.array([g not in te_groups for g in groups])
        tr, te = np.where(tr_mask)[0], np.where(te_mask)[0]
        info = {"method": "time split (newest 7 days)", "cutoff": str(cutoff.date()),
                "latest_phishing_day": str(latest_phish_day.date())}
    else:
        tr, te = next(GroupShuffleSplit(test_size=0.2, random_state=42).split(X, y, groups))
        info = {"method": "domain-grouped random",
                "warning": f"only {phish_days} distinct phishing days over {span} days: NOT a time split; say so in the report"}
        print(f"[split] WARNING: NOT A TIME SPLIT. Domain-grouped random split used because only {phish_days} distinct phishing days span {span} days.")
    info.update(n_train=len(tr), n_test=len(te), train_phish=int(y[tr].sum()), test_phish=int(y[te].sum()),
                test_benign=int((1 - y[te]).sum()), phishing_days=int(phish_days), date_span_days=int(span))
    print("[split]", info)
    json.dump(info, open(os.path.join(a.out, "split_info.json"), "w"), indent=2)

    def make_lr():
        return Pipeline([("sc", StandardScaler()), ("lr", LogisticRegression(max_iter=3000))])

    def make_gb():
        return GradientBoostingClassifier(n_estimators=200, max_depth=3, learning_rate=0.1,
                                          subsample=0.8, random_state=42)
    makers = {"lr": make_lr, "gb": make_gb}

    # ---- comparison table (fit on train, score on test; test never used to choose) ----
    rows = []
    for fs, names in FEATURE_SETS.items():
        cols = [idx[n] for n in names]
        for mname, mk in makers.items():
            m = mk().fit(X[tr][:, cols], y[tr])
            met = metrics(y[te], m.predict_proba(X[te][:, cols])[:, 1])
            rows.append({"feature_set": fs, "model": mname, "n_features": len(cols), **met})
            print(f"[eval] {fs:8s} {mname}: pr_auc={met['pr_auc']:.4f} recall@fpr0.1%={met['recall@fpr0.001']:.3f}")
    pd.DataFrame(rows).to_csv(os.path.join(a.out, "metrics.csv"), index=False)

    # ---- out-of-fold predictions on TRAIN (what the fusion step must learn from) ----
    cols = [idx[n] for n in FEATURE_SETS["full"]]
    Xtr, Xte = X[tr][:, cols], X[te][:, cols]
    if len(set(groups[tr])) < 5:
        sys.exit(f"Cannot create five domain-grouped OOF folds: only {len(set(groups[tr]))} training domains.")
    oof = {k: np.zeros(len(tr)) for k in makers}
    fold = np.zeros(len(tr), dtype=int)
    for k, (a_i, b_i) in enumerate(GroupKFold(n_splits=5).split(Xtr, y[tr], groups[tr])):
        fold[b_i] = k
        for mname, mk in makers.items():
            oof[mname][b_i] = mk().fit(Xtr[a_i], y[tr][a_i]).predict_proba(Xtr[b_i])[:, 1]
    oof_pr = {k: metrics(y[tr], v)["pr_auc"] for k, v in oof.items()}
    primary = max(oof_pr, key=oof_pr.get)                 # chosen on OOF only, never on test
    print(f"[select] OOF PR-AUC {oof_pr} -> primary = {primary}")

    final = {k: mk().fit(Xtr, y[tr]) for k, mk in makers.items()}
    base = df.iloc[tr][["url", "label", "group", "date"]].copy()
    base["fold"] = fold
    for k in makers:
        base[f"prob_{k}"] = oof[k]
    base["ml_prob"] = oof[primary]
    base.to_csv(os.path.join(a.out, "url_oof_train.csv"), index=False)
    t = df.iloc[te][["url", "label", "group", "date"]].copy()
    for k in makers:
        t[f"prob_{k}"] = final[k].predict_proba(Xte)[:, 1]
    t["ml_prob"] = t[f"prob_{primary}"]
    t.to_csv(os.path.join(a.out, "url_test_pred.csv"), index=False)  # TEST: do not fit anything on this

    # ---- export for the extension ------------------------------------------
    mj_lr = export_lr(final["lr"], FEATURE_SETS["full"])
    mj_gb = export_gb(final["gb"], FEATURE_SETS["full"], Xtr[:1])
    json.dump(mj_lr, open(os.path.join(a.out, "model_lr.json"), "w"))
    json.dump(mj_gb, open(os.path.join(a.out, "model_gb.json"), "w"))
    json.dump(mj_lr if primary == "lr" else mj_gb, open(os.path.join(a.out, "model.json"), "w"))
    coefs = sorted(zip(FEATURE_SETS["full"], mj_lr["coef"]), key=lambda kv: -abs(kv[1]))[:15]
    print("[lr] top standardized coefficients:", [(n, round(c, 2)) for n, c in coefs])
    write_results(a.out, rows, info, primary, oof_pr, coefs, df)
    candidate_path = os.path.join("ml", "model_candidate.json")
    shutil.copyfile(os.path.join(a.out, "model.json"), candidate_path)
    print(f"[export] {candidate_path}: {os.path.getsize(candidate_path)} bytes (old ml/model.json left untouched)")
    print(f"[done] outputs in {a.out}/  (model.json = {primary})")


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("collect")
    c.add_argument("--raw", default="data/raw")
    c.add_argument("--tranco-n", type=int, default=100000)
    c.add_argument("--max-per-source", type=int, default=0)
    c.add_argument("--phish-only", action="store_true")
    c.set_defaults(fn=cmd_collect)
    b = sp.add_parser("build")
    b.add_argument("--raw", default="data/raw")
    b.add_argument("--out", default="data/urls.csv")
    b.add_argument("--benign-ratio", type=float, default=5.0)
    b.add_argument("--seed", type=int, default=42)
    b.set_defaults(fn=cmd_build)
    t = sp.add_parser("train")
    t.add_argument("--data", default="data/urls.csv")
    t.add_argument("--out", default="out")
    t.add_argument("--split", choices=["auto", "time", "domain"], default="auto")
    t.set_defaults(fn=cmd_train)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
