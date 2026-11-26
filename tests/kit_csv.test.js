"use strict";
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { parseCsv, buildHeader, buildRow } = require("../tools/dom_csv.js");

const features = ["dom_sample"];
const header = buildHeader(features).split(",");
assert.ok(header.includes("kit_fp"), "new CSV headers must include kit_fp");

const scan = {
  kitFp: "0123456789abcdef",
  findings: [],
  domScore: 0,
  features: { dom_sample: 7 }
};
const built = parseCsv(`${buildHeader(features)}\n${buildRow({ url: "https://safe.example.test", label: 0 }, scan, features)}`)[0];
assert.equal(built.kit_fp, scan.kitFp, "CSV builder must keep the supplied fingerprint");
assert.equal(built.dom_sample, "7");

const oldCsv = parseCsv("url,label\nhttps://safe.example.test,0\n");
assert.equal(oldCsv[0].kit_fp, "", "old CSVs without kit_fp remain readable as empty");

const verifier = path.join(__dirname, "../tools/verify_kitfp.js");
function verifyFixture(filename) {
  return spawnSync(process.execPath, [verifier, path.join(__dirname, "fixtures", filename)], { encoding: "utf8" });
}
const valid = verifyFixture("kitfp_valid.csv");
assert.equal(valid.status, 0, valid.stderr);
assert.match(valid.stdout, /Total rows: 2/);
assert.match(valid.stdout, /Distinct valid kit_fp values: 2/);
const empty = verifyFixture("kitfp_empty.csv");
assert.equal(empty.status, 1);
assert.match(empty.stdout, /Rows with empty kit_fp: 1/);
assert.match(empty.stdout, /not 16 hex characters \(includes empty\): 1/);
const invalid = verifyFixture("kitfp_invalid.csv");
assert.equal(invalid.status, 1);
assert.match(invalid.stdout, /not 16 hex characters \(includes empty\): 1/);

console.log("Kit CSV builder and verifier tests passed.");
