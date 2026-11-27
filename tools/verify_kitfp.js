#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { parseCsv } = require("./dom_csv.js");

const HEX_64 = /^[0-9a-f]{16}$/i;

function main() {
  const input = process.argv[2];
  if (!input || process.argv.length !== 3) {
    console.error("Usage: node tools/verify_kitfp.js <csv-path>");
    process.exitCode = 2;
    return;
  }

  const csvPath = path.resolve(process.cwd(), input);
  const rows = parseCsv(fs.readFileSync(csvPath, "utf8"));
  let empty = 0;
  let invalid = 0;
  const distinct = new Set();
  const labels = new Map();

  for (const row of rows) {
    const value = String(row.kit_fp ?? "").trim();
    if (!value) empty += 1;
    if (!HEX_64.test(value)) invalid += 1;
    else distinct.add(value.toLowerCase());

    const label = String(row.label ?? "").trim() || "(empty)";
    labels.set(label, (labels.get(label) || 0) + 1);
  }

  console.log(`CSV: ${csvPath}`);
  console.log(`Total rows: ${rows.length}`);
  console.log(`Rows with empty kit_fp: ${empty}`);
  console.log(`Rows whose kit_fp is not 16 hex characters (includes empty): ${invalid}`);
  console.log(`Distinct valid kit_fp values: ${distinct.size}`);
  console.log("Rows per label:");
  for (const [label, count] of [...labels.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    console.log(`  ${label}: ${count}`);
  }

  if (empty > 0 || invalid > 0) process.exitCode = 1;
}

try { main(); }
catch (error) {
  console.error(`Verification failed: ${error.message}`);
  process.exitCode = 2;
}
