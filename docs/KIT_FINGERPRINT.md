# Phishing-kit fingerprints

## The problem

Many phishing pages reuse the same page template or kit. A fingerprint can help recognize a repeated structure even when the page is hosted on a different domain. It is only one clue: a copied login template can also be legitimate, and a kit can change its structure.

## What the fingerprint measures

PhishGuard creates a 64-bit SimHash from page structure. It uses the first 400 element tag names in document order and hashes each consecutive three-tag sequence. It also adds tokens describing the number of forms, each form's method and ordered input types, whether a password field exists, and bucketed counts of links, images, scripts, and iframes.

Each token votes for or against each of the 64 bits. The combined votes become a 64-bit value written as 16 hexadecimal characters. Hamming distance counts how many bits differ: 0 means identical fingerprints, and a larger number means more structural difference.

Text, class names, domains, form destinations, and URLs are ignored. That keeps the fingerprint focused on reusable structure and prevents a copied page's words or host name from deciding a match. Input types and form methods are retained because they describe the form layout. The shared implementation lives in `content.js`; both the extension and crawler call that function.

## Dataset and signature database

The offline report reads `data/dom/dom_features_kitfp.csv`. It drops rows without a fingerprint and rejects malformed fingerprints or repeated registrable domains. The supplied file has 136 rows; 2 phishing rows with empty fingerprints were dropped, leaving 74 phishing and 60 benign pages.

Run the reproducible summary with:

```powershell
node tools/eval_kit.js
```

It writes `out/kit/RESULTS.md`, including cluster sizes, mixed-label groups, both nearest-neighbour tests, the hand-built DOM baseline, and confidence intervals. The signature database is generated with:

```powershell
node tools/build_kit_db.js
```

The generated `ml/kit_db.json` has 102 deduplicated entries. Every entry contains only `fp` and `label`; it contains no URLs, domains, or snapshot names.

## Evaluation and threshold

The script evaluates two different questions:

1. **Leave one domain out:** for each page, compare its nearest fingerprint among the other phishing pages with its nearest fingerprint among the other benign pages. The score is `nearest benign distance - nearest phishing distance`; larger scores look more phishing-like.
2. **Leave one radius-4 cluster out:** remove every page in the query's radius-4 cluster before finding its nearest references. This tests whether the method recognizes a kit when a close sibling is unavailable. Pages with no radius-4 sibling are treated as novel kits.

On the supplied sample, Test 1 ROC-AUC is **0.747** (95% stratified bootstrap interval **0.659–0.827**). At the zero-observed-false-positive threshold, it detects **27/74 phishing pages** (**36.5%**, 95% Wilson interval **26.4–47.9%**) and flags **0/60 benign pages**. Zero observed false positives does not prove the true false-positive rate is zero: the benign sample's smallest measurable step is **1/60 = 1.67%**, and the zero-count Wilson interval extends to **6.0%**.

The selected rule threshold is **T = 0**. Of the tested distances `{0, 2, 4, 6, 8, 12}`, it is the largest distance that produced zero benign false positives in Test 1. It detects 27/74 phishing pages on that same sample. This choice is descriptive and optimistic because the threshold is selected on the evaluation data; it is not a production threshold.

Test 2 is weaker, as expected for unseen kits: ROC-AUC is **0.599** (95% bootstrap interval **0.505–0.695**), and recall at zero observed false positives is **11/74 = 14.9%** (95% Wilson interval **8.5–24.7%**). It detects **11/31** phishing pages with a radius-4 sibling, but **0/43** singleton/novel kits (95% Wilson interval **0.0–8.2%**). The matcher relies on reuse; it does not solve detection of new kits.

For comparison, the hand-built DOM score alone has ROC-AUC **0.539** (95% bootstrap interval **0.503–0.578**) and detects **0/74 phishing pages** at zero observed false positives. Full tables and intervals are in `out/kit/RESULTS.md`.

### Existing brand-title signals

The same report also counts the existing `dom_brand_in_title` and `dom_brand_domain_mismatch` flags on the scored rows, with 95% Wilson intervals for phishing and benign pages. These are already-collected features; this work added no brand, image, or logo matching behavior. See the **Existing brand-title DOM features** table in `out/kit/RESULTS.md` for the computed counts.

## Extension behavior

The matcher is disabled by default in `content.js`:

```js
const ENABLE_KIT_MATCH = false;
```

To try it, change that constant to `true` and refresh the unpacked extension. A finding is shown when the closest phishing fingerprint is within T and strictly closer than the closest benign fingerprint. The finding is kept separate from scored DOM findings, so it does not change `domScore`, fusion weights, or decision thresholds. Keep the small-sample warning in mind when demonstrating it.

## Limits

- The dataset represents one crawl day; clustering pages collected on one day overstates how much kit reuse may persist over time.
- There are only 74 phishing and 60 benign pages after exclusions, so the confidence intervals are wide.
- Benign WordPress and login-framework templates can look like phishing templates and create mixed-label clusters.
- Attackers can randomize their DOM, and phishing pages can cloak content from headless browsers.
- Fingerprints here were computed from saved pages re-rendered offline. Live-versus-saved parity on the safe fixtures was not run because Playwright is unavailable in this environment.
- A similarity is not proof that a page is phishing. T=0's measured zero benign false positives is based on only 60 benign examples and is not a safety guarantee.

## Viva questions

1. **What is a phishing kit?** A reusable page template or set of files used to build phishing pages.
2. **What does SimHash do?** It turns many structural tokens into a compact bit signature whose Hamming distance reflects similarity.
3. **Why use 64 bits?** It is compact, fast to compare, and gives a simple distance from 0 to 64.
4. **Why use three-tag sequences?** They capture local document order and nesting patterns better than a count of tags alone.
5. **Why ignore text and domains?** Reused kits change their words and hosting domains; those fields can also expose unrelated page details.
6. **What does Hamming distance 0 mean?** The two fingerprints have all 64 bits in common; it does not prove the pages are malicious.
7. **What is leave-one-domain-out testing?** Each page is compared with other domains, never with itself, to avoid self-matching.
8. **Why leave out an entire radius-4 cluster?** It tests generalization when a nearby copy of the same kit is not available.
9. **Why is singleton recall low?** A singleton has no close sibling to match, so a reuse-based method has little evidence for it.
10. **Why is T=0 not a guarantee of zero false positives?** It produced no false positives in only 60 benign samples; more data could reveal errors.
