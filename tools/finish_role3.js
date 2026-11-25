#!/usr/bin/env node
/*
 * One command for the final Role 3 outputs, after your crawls are done:
 *   node tools/finish_role3.js
 * 1. merges data/dom/dom_features_*.csv -> dom_labeled.csv (+ dom_dataset_summary.md)
 * 2. writes dom_fp_report.md from the merged data
 * 3. fills the report section from your numbers -> docs/ROLE3_REPORT_SECTION.md
 * Optional: --dir <folder>  --out <report.md>  --template <template.md>  --drop-conflicts
 */
"use strict";
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, all) => { if (x.startsWith("--")) a.push([x.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]); return a; }, []));
const dir = args.dir || "data/dom";
const run = (script, scriptArgs, outFile) => {
  const r = spawnSync(process.execPath, [path.join(__dirname, script), ...scriptArgs], { encoding: "utf8" });
  if (r.status !== 0) { console.error(`${script} failed:\n${r.stderr || r.stdout}`); process.exit(1); }
  if (outFile) fs.writeFileSync(outFile, r.stdout); else process.stdout.write(r.stdout);
};

const dailyFiles = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.startsWith("dom_features_") && f.endsWith(".csv")) : [];
if (!dailyFiles.length) { console.error(`No ${dir}/dom_features_*.csv files yet. Crawl first (docs/ROLE3_DOM.md), naming outputs dom_features_<date>.csv.`); process.exit(1); }

run("merge_dom_csv.js", ["--dir", dir, "--prefix", "dom_features_", "--out", path.join(dir, "dom_labeled.csv"), "--summary", path.join(dir, "dom_dataset_summary.md"), ...(args["drop-conflicts"] ? ["--drop-conflicts"] : [])]);
run("fp_report.js", [path.join(dir, "dom_labeled.csv")], path.join(dir, "dom_fp_report.md"));
console.log(`Wrote ${path.join(dir, "dom_fp_report.md")}`);
run("fill_report.js", ["--dir", dir, "--template", args.template || "docs/ROLE3_REPORT_TEMPLATE.md", "--out", args.out || "docs/ROLE3_REPORT_SECTION.md"]);

const summary = fs.readFileSync(path.join(dir, "dom_dataset_summary.md"), "utf8");
if (/DOM set is small/.test(summary)) console.log("\nNote: the dataset is small. That is expected for a first crawl; the report already says so.");
if (!fs.existsSync(path.join(dir, "dom_fp_report_before.md"))) console.log("Tip: no dom_fp_report_before.md found, so the before/after false-positive row stays [FILL].");
