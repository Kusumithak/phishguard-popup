# DOM layer false-positive report

Rows crawled: 136. Fetched OK: 136 (100.0%; the rest were dead, blocked or timed out).
Benign pages: 60. Phishing pages: 76.

> The DOM set is much smaller than the URL set, because phishing pages die within hours and each one needs a live crawl. Treat DOM-layer rates as indicative, with wide confidence intervals.

## Would the DOM layer alone raise a red PHISHING banner?

A page is counted if any of `hidden_password_field`, `password_form_cross_origin`, `password_form_http` fired (hybrid.js floors the score at 60) or the DOM score is 70+.

| Class | Pages | Red banner | Rate |
|---|---|---|---|
| Benign (false positives) | 60 | 1 | 1.7% |
| Phishing (detections) | 76 | 3 | 3.9% |

## Per-rule firing rate

| Rule flag | Benign | Phishing |
|---|---|---|
| password_form_cross_origin | 1 (1.7%) | 0 (0.0%) |
| password_form_http | 0 (0.0%) | 3 (3.9%) |
| external_form_http | 0 (0.0%) | 0 (0.0%) |
| hidden_password_field | 0 (0.0%) | 0 (0.0%) |
| hidden_iframe_with_form | 0 (0.0%) | 0 (0.0%) |
| password_field_without_form | 0 (0.0%) | 2 (2.6%) |
| invalid_form_action | 0 (0.0%) | 0 (0.0%) |

## Benign pages that would show a red banner

- https://www.wellsfargo.com/ - password_form_cross_origin  (stealth-hidden pw: 0, cross-site pw forms: 0, null-action forms: 0)

## New Role 3 signals: mean value by class

| Feature | Benign | Phishing |
|---|---|---|
| dom_ext_resource_ratio | 0.448 | 0.414 |
| dom_null_link_ratio | 0.046 | 0.188 |
| dom_favicon_foreign | 0.300 | 0.211 |
| dom_meta_refresh | 0.150 | 0.000 |
| dom_script_eval | 0.017 | 0.026 |
| dom_script_atob | 0.067 | 0.039 |
| dom_script_obfuscation | 0.067 | 0.079 |
| dom_brand_domain_mismatch | 0.000 | 0.132 |

A feature is only useful if the two columns differ. Features that look the same for both classes get a weight near zero in the learned fusion.

## DOM scan latency (ms)

median 2.6, p95 11.3, max 112.3 (n=136)
