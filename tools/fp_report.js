#!/usr/bin/env node
/* DOM false-positive report: node tools/fp_report.js [data/dom/dom_features.csv] > data/dom/dom_fp_report.md */
"use strict";
const fs = require("node:fs");
const { parseCsv, FLAG_NAMES, STRONG_FLAGS } = require("./dom_csv");

function buildReport(rows, crawl) {
  const ok = rows.filter((r) => r.fetch_ok === "1");
  const benign = ok.filter((r) => r.label === "0");
  const phish = ok.filter((r) => r.label === "1");
  const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "n/a");
  const fired = (r, f) => r[`flag_${f}`] === "1";
  const strong = (r) => STRONG_FLAGS.some((f) => fired(r, f)) || Number(r.dom_hand_score) >= 70;

  const out = [];
  out.push("# DOM layer false-positive report", "");
  if (crawl) out.push(`Rows crawled: ${crawl.total}. Fetched OK: ${crawl.total - crawl.deadOrBlocked} (${pct(crawl.total - crawl.deadOrBlocked, crawl.total)}; the rest were dead, blocked or timed out). Below: one row per domain, ${ok.length} pages.`);
  else out.push(`Rows crawled: ${rows.length}. Fetched OK: ${ok.length} (${pct(ok.length, rows.length)}; the rest were dead, blocked or timed out).`);
  out.push(`Benign pages: ${benign.length}. Phishing pages: ${phish.length}.`);
  out.push("", "> The DOM set is much smaller than the URL set, because phishing pages die within hours and each one needs a live crawl. Treat DOM-layer rates as indicative, with wide confidence intervals.", "");

  out.push("## Would the DOM layer alone raise a red PHISHING banner?", "");
  out.push("A page is counted if any of `hidden_password_field`, `password_form_cross_origin`, `password_form_http` fired (hybrid.js floors the score at 60) or the DOM score is 70+.", "");
  out.push("| Class | Pages | Red banner | Rate |", "|---|---|---|---|");
  out.push(`| Benign (false positives) | ${benign.length} | ${benign.filter(strong).length} | ${pct(benign.filter(strong).length, benign.length)} |`);
  out.push(`| Phishing (detections) | ${phish.length} | ${phish.filter(strong).length} | ${pct(phish.filter(strong).length, phish.length)} |`, "");

  out.push("## Per-rule firing rate", "", "| Rule flag | Benign | Phishing |", "|---|---|---|");
  for (const f of FLAG_NAMES) out.push(`| ${f} | ${benign.filter((r) => fired(r, f)).length} (${pct(benign.filter((r) => fired(r, f)).length, benign.length)}) | ${phish.filter((r) => fired(r, f)).length} (${pct(phish.filter((r) => fired(r, f)).length, phish.length)}) |`);

  out.push("", "## Benign pages that would show a red banner", "");
  const offenders = benign.filter(strong);
  if (!offenders.length) out.push("None.");
  for (const r of offenders) {
    const why = [...STRONG_FLAGS.filter((f) => fired(r, f)), ...(Number(r.dom_hand_score) >= 70 ? ["dom_score>=70"] : [])].join(", ");
    out.push(`- ${r.url} - ${why}  (stealth-hidden pw: ${r.dom_n_password_stealth_hidden}, cross-site pw forms: ${r.dom_n_password_forms_cross_site}, null-action forms: ${r.dom_n_forms_null_action})`);
  }

  const numericMeans = ["dom_ext_resource_ratio", "dom_null_link_ratio", "dom_favicon_foreign", "dom_meta_refresh", "dom_script_eval", "dom_script_atob", "dom_script_obfuscation", "dom_brand_domain_mismatch"];
  const mean = (set, k) => (set.length ? (set.reduce((s, r) => s + Number(r[k] || 0), 0) / set.length).toFixed(3) : "n/a");
  out.push("", "## New Role 3 signals: mean value by class", "", "| Feature | Benign | Phishing |", "|---|---|---|");
  for (const k of numericMeans) out.push(`| ${k} | ${mean(benign, k)} | ${mean(phish, k)} |`);
  out.push("", "A feature is only useful if the two columns differ. Features that look the same for both classes get a weight near zero in the learned fusion.");

  const scan = ok.map((r) => Number(r.scan_ms)).filter(Number.isFinite).sort((a, b) => a - b);
  if (scan.length) out.push("", "## DOM scan latency (ms)", "", `median ${scan[Math.floor(scan.length / 2)].toFixed(1)}, p95 ${scan[Math.floor(scan.length * 0.95)].toFixed(1)}, max ${scan[scan.length - 1].toFixed(1)} (n=${scan.length})`);
  return out.join("\n") + "\n";
}

// Shared numbers (also used by fill_report.js) so every document uses one definition.
function computeStats(rows) {
  const ok = rows.filter((r) => r.fetch_ok === "1");
  const benign = ok.filter((r) => r.label === "0");
  const phish = ok.filter((r) => r.label === "1");
  const fired = (r, f) => r[`flag_${f}`] === "1";
  const strong = (r) => STRONG_FLAGS.some((f) => fired(r, f)) || Number(r.dom_hand_score) >= 70;
  const mean = (set, k) => (set.length ? set.reduce((s, r) => s + Number(r[k] || 0), 0) / set.length : null);
  const scan = ok.map((r) => Number(r.scan_ms)).filter(Number.isFinite).sort((a, b) => a - b);
  return {
    ok: ok.length, benign: benign.length, phish: phish.length,
    benignRed: benign.filter(strong).length, phishRed: phish.filter(strong).length,
    mean, benignRows: benign, phishRows: phish,
    latency: scan.length ? { median: scan[Math.floor(scan.length / 2)], p95: scan[Math.floor(scan.length * 0.95)], n: scan.length } : null
  };
}

if (require.main === module) {
  const file = process.argv[2] || "data/dom/dom_features.csv";
  process.stdout.write(buildReport(parseCsv(fs.readFileSync(file, "utf8"))));
}
module.exports = { buildReport, computeStats };
