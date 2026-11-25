#!/usr/bin/env node
/* Fill docs/ROLE3_REPORT_TEMPLATE.md from the crawl data. Unknown values stay as [FILL: name], never guessed. */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv } = require("./dom_csv");
const { computeStats } = require("./fp_report");
const { mergeRows } = require("./merge_dom_csv");

const pct = (k, n) => (n ? `${((100 * k) / n).toFixed(1)}%` : "n/a");
const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, "utf8") : null);

function buildValues({ raw, labeled, beforeText, seedRows }) {
  const v = {};
  const all = raw.flat();
  const phishAll = all.filter((r) => r.label === "1"), benignAll = all.filter((r) => r.label === "0");
  const okOf = (rows) => rows.filter((r) => r.fetch_ok === "1");
  const dates = [...new Set(all.map((r) => r.date).filter(Boolean))].sort();
  if (all.length) {
    v.crawled_phish = phishAll.length; v.crawled_benign = benignAll.length;
    v.ok_phish = okOf(phishAll).length; v.ok_benign = okOf(benignAll).length;
    v.dead_rate = pct(all.length - okOf(all).length, all.length);
    v.n_days = dates.length; v.date_range = dates.length > 1 ? `${dates[0]} to ${dates[dates.length - 1]}` : dates[0] || undefined;
    const feeds = [...new Set(phishAll.map((r) => r.source).filter(Boolean))];
    if (feeds.length) v.feeds = feeds.join(" and ");
    v.harness_n = new Set(benignAll.map((r) => r.domain).filter(Boolean)).size;
    v.conflicts = mergeRows([raw.flat()]).stats.conflicts.length;
  }
  if (seedRows) v.college_n = seedRows.filter((r) => /college|university|campus/i.test(r.source || "")).length;

  if (labeled) {
    const kept = labeled;
    v.kept_phish = kept.filter((r) => r.label === "1").length; v.kept_benign = kept.filter((r) => r.label === "0").length;
    const days = [...new Set(kept.map((r) => r.date))].sort(), test = new Set(days.slice(-7));
    const trainRows = kept.filter((r) => !test.has(r.date)), testRows = kept.filter((r) => test.has(r.date));
    v.split_note = days.length < 8
      ? `Only ${days.length} crawl day(s) so far, so a 7-day held-out window is not yet possible; the split will be fixed once at least 8 days exist.`
      : `Train: ${trainRows.length} rows (${trainRows.filter((r) => r.label === "1").length} phishing). Test (newest 7 days): ${testRows.length} rows (${testRows.filter((r) => r.label === "1").length} phishing).`;
    const s = computeStats(labeled.map((r) => ({ ...r, fetch_ok: "1" })));
    v.fp_after_n = s.benign; v.fp_after_k = s.benignRed; v.fp_after_rate = pct(s.benignRed, s.benign);
    v.det_n = s.phish; v.det_k = s.phishRed; v.det_rate = pct(s.phishRed, s.phish);
    if (s.latency) { v.lat_median = s.latency.median.toFixed(1); v.lat_p95 = s.latency.p95.toFixed(1); v.lat_n = s.latency.n; }
    const features = ["dom_ext_resource_ratio", "dom_null_link_ratio", "dom_favicon_foreign", "dom_meta_refresh", "dom_script_eval", "dom_script_atob", "dom_script_obfuscation", "dom_brand_domain_mismatch"];
    const m = (set, k) => (set.length ? s.mean(set, k).toFixed(3) : "n/a");
    v.means_table = ["| Feature | Benign | Phishing |", "|---|---|---|", ...features.map((k) => `| ${k} | ${m(s.benignRows, k)} | ${m(s.phishRows, k)} |`)].join("\n");
  }
  const before = beforeText && /Benign \(false positives\) \| (\d+) \| (\d+) \| ([\d.]+%|n\/a)/.exec(beforeText);
  if (before) { v.fp_before_n = before[1]; v.fp_before_k = before[2]; v.fp_before_rate = before[3]; }
  return v;
}

function fillTemplate(template, values) {
  const missing = new Set();
  const text = template.replace(/\{\{(\w+)\}\}/g, (_, name) => {
    if (values[name] === undefined || values[name] === null || values[name] === "") { missing.add(name); return `[FILL: ${name}]`; }
    return String(values[name]);
  });
  return { text, missing: [...missing] };
}

function main() {
  const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, all) => { if (x.startsWith("--")) a.push([x.slice(2), all[i + 1]]); return a; }, []));
  const dir = args.dir || "data/dom", prefix = args.prefix || "dom_features_";
  const rawFiles = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.startsWith(prefix) && f.endsWith(".csv")) : [];
  const raw = rawFiles.map((f) => parseCsv(read(path.join(dir, f))));
  const labeledText = read(args.labeled || path.join(dir, "dom_labeled.csv"));
  const seedText = read(path.join(dir, "benign_login_seed.csv"));
  const values = buildValues({
    raw, labeled: labeledText ? parseCsv(labeledText) : null,
    beforeText: read(args.before || path.join(dir, "dom_fp_report_before.md")),
    seedRows: seedText ? parseCsv(seedText) : null
  });
  const { text, missing } = fillTemplate(read(args.template || "docs/ROLE3_REPORT_TEMPLATE.md"), values);
  const out = args.out || "docs/ROLE3_REPORT_SECTION.md";
  fs.writeFileSync(out, text);
  console.log(`Wrote ${out} from ${rawFiles.length} daily CSV(s).`);
  console.log(missing.length ? `Still to fill by hand (not computable from your files): ${missing.join(", ")}` : "Every number was filled from your data.");
}
if (require.main === module) main();
module.exports = { buildValues, fillTemplate };
