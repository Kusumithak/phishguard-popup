// No browser or dependencies needed:  node tests/dom_csv.test.js
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const csv = require("../tools/dom_csv");
const { buildReport } = require("../tools/fp_report");

const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "../data/dom/dom_feature_schema.json"), "utf8"));
const names = schema.features.map((f) => f.name);

// parse / escape round trip, including commas, quotes and CRLF
const tricky = 'a,"b ""quoted"", with comma",c\r\n1,2,3\r\n';
assert.deepEqual(csv.parseCsv("x,y,z\r\n" + tricky.split("\r\n")[0] + "\r\n"), [{ x: "a", y: 'b "quoted", with comma', z: "c" }]);
assert.equal(csv.csvEscape('he said "hi", ok'), '"he said ""hi"", ok"');

// labels: 1 = phishing, 0 = benign
assert.equal(csv.normalizeLabel("phish"), 1);
assert.equal(csv.normalizeLabel("0"), 0);
assert.throws(() => csv.normalizeLabel("maybe"));

// seed + example inputs are well formed and every label parses
for (const file of ["benign_login_seed.csv", "crawl_input.example.csv"]) {
  const rows = csv.parseCsv(fs.readFileSync(path.join(__dirname, "../data/dom", file), "utf8"));
  assert.ok(rows.length >= 3, file);
  for (const r of rows) { new URL(r.url); csv.normalizeLabel(r.label); }
}
const seed = csv.parseCsv(fs.readFileSync(path.join(__dirname, "../data/dom/benign_login_seed.csv"), "utf8"));
assert.ok(seed.length >= 50, "benign harness should hold about 50 login pages");
assert.equal(new Set(seed.map((r) => r.url)).size, seed.length, "duplicate seed URLs");

// header and row always have the same number of columns, failed fetches included
const header = csv.parseCsv(csv.buildHeader(names) + "\n" + csv.buildRow({ url: "https://a.test/", label: 0 }, null, names));
assert.equal(Object.keys(header[0]).length, csv.META_COLUMNS.length + csv.FLAG_NAMES.length + 1 + names.length);

// FP report on a small synthetic dataset
const feature = (over) => Object.fromEntries(names.map((n) => [n, over[n] ?? 0]));
const scan = (findings, domScore, f = {}) => ({ findings, domScore, features: feature(f) });
const make = (url, label, s) => csv.parseCsv(csv.buildHeader(names) + "\n" + csv.buildRow({ url, label, fetch_ok: 1, scan_ms: "3.0" }, s, names))[0];
const rows = [
  make("https://good.test/", 0, scan([], 0)),
  make("https://modal.test/", 0, scan(["hidden_password_field"], 20)),            // benign false positive
  make("https://bad.test/", 1, scan(["password_form_cross_origin"], 35)),
  { ...make("https://dead.test/", 1, null), fetch_ok: "0" }
];
const report = buildReport(rows);
assert.match(report, /Benign \(false positives\) \| 2 \| 1 \| 50\.0%/);
assert.match(report, /Phishing \(detections\) \| 1 \| 1 \| 100\.0%/);
assert.match(report, /https:\/\/modal\.test\/ - hidden_password_field/);
assert.match(report, /DOM set is much smaller than the URL set/);
console.log("dom_csv + fp_report tests passed.");
