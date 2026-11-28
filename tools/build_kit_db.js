#!/usr/bin/env node
"use strict";

// Build the extension's minimal local signature list. Deliberately copy only fingerprints
// and labels; URLs, domains, snapshots, and other CSV metadata never enter the JSON file.
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, normalizeLabel } = require("./dom_csv.js");

const ROOT = path.resolve(__dirname, "..");
const INPUT = path.join(ROOT, "data", "dom", "dom_features_kitfp.csv");
const OUTPUT = path.join(ROOT, "ml", "kit_db.json");

function buildEntries(rows) {
  const unique = new Map();
  for (const [index, row] of rows.entries()) {
    const fp = String(row.kit_fp || "").trim().toLowerCase();
    if (!fp) continue;
    if (!/^[0-9a-f]{16}$/.test(fp)) throw new Error(`Invalid fingerprint at CSV data row ${index + 2}.`);
    const label = normalizeLabel(row.label);
    const key = `${fp}:${label}`;
    if (!unique.has(key)) unique.set(key, { fp, label });
  }
  return [...unique.values()].sort((a, b) => a.label - b.label || a.fp.localeCompare(b.fp));
}

function main() {
  const rows = parseCsv(fs.readFileSync(INPUT, "utf8"));
  if (!rows.length || !("kit_fp" in rows[0])) throw new Error("Input CSV must contain kit_fp rows.");
  const entries = buildEntries(rows);
  fs.writeFileSync(OUTPUT, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
  console.log(`Wrote ${entries.length} deduplicated fingerprint/label entries to ${OUTPUT}.`);
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(`Kit database build failed: ${error.message}`); process.exitCode = 1; }
}

module.exports = { buildEntries };
