# PhishGuard Hybrid Browser Extension (Role 4)

Manifest V3 Chrome/Edge extension implementing Role 4's product layer, Tranco Top-50k Bloom filter, PHISHING blocking page, "Why Flagged" attribution panel (`coefficient × value`), per-hostname verdict cache with latency telemetry, local allowlist with false-positive JSON export, and unit tests for `rules.js`, `inference.js`, and `hybrid.js`.

## Folder Layout

```
extension/
├── manifest.json                 # Chrome Manifest V3 config
├── background.js                 # Navigation listener, cache, Bloom filter, blocking redirect
├── blocked.html / blocked.js     # Full-page PHISHING warning + Mark as Safe + JSON export
├── popup.html / popup.js         # Live tab verdict, latency, why-flagged, allowlist actions
├── data/
│   ├── tranco-top50k-bloom.json  # Prebuilt 50,000-domain Bloom filter (60 KB bitset)
│   └── demo-scenarios.json       # Controlled Safe, Benign Login, Suspicious, Phishing demos
├── scripts/
│   └── build-bloom.mjs           # Regenerates tranco-top50k-bloom.json
└── src/
    ├── rules.js                  # 0/1 heuristic flags + rule weights
    ├── ml/inference.js           # URL lexical/entropy ML model inference (no has_https bias)
    ├── ml/model.json             # Calibrated URL Logistic Regression weights
    ├── hybrid.js                 # Stacked fusion combiner + Bloom + allowlist + whyFlagged
    ├── bloom-filter.js           # Multi-hash FNV-1a/DJB2 Bloom filter
    ├── verdict-cache.js          # Per-hostname LRU/TTL cache with ms latency measurement
    ├── allowlist.js              # Local allowlist & false-positive JSON exporter
    └── content.js                # Safe read-only DOM signal bridge (compatible with Role 3)
tests/
├── rules.test.js
├── inference.test.js
└── hybrid.test.js
```

## Install in Chrome / Edge (Load Unpacked)

1. Rebuild the Tranco Top-50k Bloom filter if needed:
   ```bash
   node extension/scripts/build-bloom.mjs
   ```
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the `extension/` folder.
5. Visit any URL or open the extension popup to inspect the verdict, latency (`ms`), Tranco Bloom status, and `coefficient × value` attribution.

## Run Unit Tests

```bash
node --test tests/*.test.js
```

## Controlled Live Demos

Test the four benchmark scenarios inside `extension/data/demo-scenarios.json`:
1. **Safe**: `https://github.com/trending/javascript` → Tranco Bloom match → `SAFE`
2. **Benign Login Page**: `https://accounts.google.com/v3/signin/...` → Protected from false-positive login keyword flags → `SAFE`
3. **Suspicious**: `https://portal-verify-9821.billing-desk.xyz/...` → High digit/hyphen/TLD risk → `SUSPICIOUS`
4. **Phishing**: `https://secure-paypal-login.verify-account-8841.top/...` + DOM mismatch → Redirects to `blocked.html` with "Why Flagged" breakdown and "Mark as Safe / Report False Positive" button.

## Push Role 4 Branch to GitHub

```bash
git checkout -b feat/role4-extension
git add extension/ tests/
git commit -m "[Role 4] add Bloom filter, blocking warning page, allowlist export, cache, and unit tests"
git push -u origin feat/role4-extension
```
