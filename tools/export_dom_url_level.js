
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, toCsvLine } = require("./dom_csv");

const inputDir = "data/dom";

const files = [
  "dom_features_benign.csv",
  "dom_features_benign_retry.csv",
  "dom_features_phishing.csv"
];

const outputFile = "out/dom_features.csv";

let allRows = [];
let expectedHeader = null;

for (const file of files) {
  const filePath = path.join(inputDir, file);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing input file: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf8");
  const header = content.split(/\r?\n/)[0];

  if (expectedHeader === null) {
    expectedHeader = header;
  } else if (header !== expectedHeader) {
    throw new Error(`Column mismatch in ${file}`);
  }

  allRows.push(...parseCsv(content));
}

const successfulRows = allRows.filter(
  row => row.fetch_ok === "1" && row.url
);

const seen = new Map();
const finalRows = [];

for (const row of successfulRows) {
  if (!["0", "1"].includes(row.label)) {
    throw new Error(`Invalid label for URL: ${row.url}`);
  }

  if (seen.has(row.url)) {
    const previousLabel = seen.get(row.url);

    if (previousLabel !== row.label) {
      throw new Error(`Conflicting labels for URL: ${row.url}`);
    }

    continue;
  }

  seen.set(row.url, row.label);
  finalRows.push(row);
}

const columns = expectedHeader.split(",").map(c => c.trim());

if (!columns.includes("url") || !columns.includes("label")) {
  throw new Error("Required url or label column is missing");
}

fs.mkdirSync(path.dirname(outputFile), { recursive: true });

const output = [
  expectedHeader,
  ...finalRows.map(row =>
    toCsvLine(columns.map(column => row[column] ?? ""))
  )
];

fs.writeFileSync(outputFile, output.join("\n") + "\n");

const phishing = finalRows.filter(row => row.label === "1").length;
const benign = finalRows.filter(row => row.label === "0").length;

console.log(`URL-level dataset created: ${outputFile}`);
console.log(`Total successful unique URLs: ${finalRows.length}`);
console.log(`Phishing: ${phishing}`);
console.log(`Benign: ${benign}`);
console.log("Original url column preserved.");

