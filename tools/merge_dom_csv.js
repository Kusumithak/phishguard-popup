#!/usr/bin/env node
/*
 * Merge the daily crawl CSVs into the final labeled DOM dataset and write a summary.
 *   node tools/merge_dom_csv.js --dir data/dom --prefix dom_features_ --out data/dom/dom_labeled.csv --summary data/dom/dom_dataset_summary.md
 * Keeps fetch_ok==1 rows, ONE ROW PER registrable domain (earliest date wins), optional --drop-conflicts
 * removes domains that appear with both labels. Never mixes rows from different schemas.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, toCsvLine } = require("./dom_csv");

function mergeRows(rowSets, { dropConflicts = false } = {}) {
  const all = rowSets.flat();
  const total = all.length;
  const ok = all.filter((r) => r.fetch_ok === "1" && r.domain);
  const deadOrBlocked = total - ok.length;
  const labelsByDomain = new Map();
  for (const r of ok) { if (!labelsByDomain.has(r.domain)) labelsByDomain.set(r.domain, new Set()); labelsByDomain.get(r.domain).add(r.label); }
  const conflicts = [...labelsByDomain].filter(([, s]) => s.size > 1).map(([d]) => d);
  const conflictSet = new Set(dropConflicts ? conflicts : []);

  const seen = new Set(); const kept = []; let duplicates = 0;
  // Earliest date wins; on the same day the page with a password form wins (the login page is
  // what the harness is about), instead of whichever row the crawler happened to finish first.
  const pw = (r) => Number(r.dom_n_password_fields || 0);
  for (const r of [...ok].sort((a, b) => (a.date || "").localeCompare(b.date || "") || pw(b) - pw(a))) {
    if (conflictSet.has(r.domain)) continue;
    const key = `${r.domain}|${r.label}`;
    if (seen.has(key)) { duplicates += 1; continue; }
    seen.add(key); kept.push(r);
  }
  return { rows: kept, stats: { total, deadOrBlocked, duplicates, conflicts, droppedConflicts: dropConflicts ? conflicts.length : 0 } };
}

function summarize({ rows, stats }) {
  const phish = rows.filter((r) => r.label === "1"), benign = rows.filter((r) => r.label === "0");
  const dates = [...new Set(rows.map((r) => r.date))].sort();
  const lines = ["# DOM dataset summary", ""];
  lines.push(`Crawled rows: ${stats.total}. Dead, blocked or timed out: ${stats.deadOrBlocked} (${stats.total ? ((100 * stats.deadOrBlocked) / stats.total).toFixed(1) : 0}%).`);
  lines.push(`After one-row-per-domain: **${phish.length} phishing, ${benign.length} benign** (${stats.duplicates} duplicate domains removed).`);
  lines.push(`Domains seen with both labels: ${stats.conflicts.length}${stats.conflicts.length ? ` (${stats.conflicts.slice(0, 5).join(", ")}${stats.conflicts.length > 5 ? ", ..." : ""})` : ""}${stats.droppedConflicts ? "; dropped" : "; kept, review them"}.`);
  lines.push("", "| Date | Phishing | Benign |", "|---|---|---|");
  for (const d of dates) lines.push(`| ${d} | ${phish.filter((r) => r.date === d).length} | ${benign.filter((r) => r.date === d).length} |`);
  // time split: newest 7 distinct days = test candidates, everything older = train
  const testDays = new Set(dates.slice(-7));
  const train = rows.filter((r) => !testDays.has(r.date)), test = rows.filter((r) => testDays.has(r.date));
  lines.push("", "## Suggested time split (newest 7 days = untouched test set)", "");
  lines.push(`Train: ${train.length} rows (${train.filter((r) => r.label === "1").length} phishing). Test: ${test.length} rows (${test.filter((r) => r.label === "1").length} phishing).`);
  if (dates.length < 8) lines.push("", "> Fewer than 8 crawl days: a 7-day test window would leave almost nothing to train on. Crawl for more days, or agree a smaller window with Role 1.");
  if (phish.length < 150) lines.push("", `> **The DOM set is small (${phish.length} phishing pages)** compared with the URL set. State this in the report and give wide confidence intervals; with this few pages Role 1 should keep a hand-set or strongly regularised DOM weight.`);
  return lines.join("\n") + "\n";
}

function main() {
  const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => { if (a.startsWith("--")) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]); return acc; }, []));
  const dir = args.dir || "data/dom", prefix = args.prefix || "dom_features_";
  const files = fs.readdirSync(dir).filter((f) => f.startsWith(prefix) && f.endsWith(".csv")).sort();
  if (!files.length) { console.error(`No ${prefix}*.csv files in ${dir}`); process.exit(1); }
  const header = fs.readFileSync(path.join(dir, files[0]), "utf8").split(/\r?\n/)[0];
  const sets = files.map((f) => {
    if (fs.readFileSync(path.join(dir, f), "utf8").split(/\r?\n/)[0] !== header) throw new Error(`${f} has a different column layout (re-run it with --reextract using the current content.js)`);
    return parseCsv(fs.readFileSync(path.join(dir, f), "utf8"));
  });
  const merged = mergeRows(sets, { dropConflicts: Boolean(args["drop-conflicts"]) });
  const columns = header.split(",");
  const out = args.out || path.join(dir, "dom_labeled.csv");
  fs.writeFileSync(out, [header, ...merged.rows.map((r) => toCsvLine(columns.map((c) => r[c])))].join("\n") + "\n");
  fs.writeFileSync(args.summary || path.join(dir, "dom_dataset_summary.md"), summarize(merged));
  console.log(`Merged ${files.length} files -> ${merged.rows.length} rows in ${out}`);
}
if (require.main === module) main();
module.exports = { mergeRows, summarize };