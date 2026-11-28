"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { kitFingerprint, kitMatchFinding } = require("../content.js");
const { documentFromHtml } = require("./kit_fixture_document.js");

const html = fs.readFileSync(path.join(__dirname, "fixtures/kit_structure_a.html"), "utf8");
const doc = documentFromHtml(html, "safe-fixture.test");
const fp = kitFingerprint(doc);
const matchDb = [{ fp, label: 1 }, { fp: "ffffffffffffffff", label: 0 }];
const match = kitMatchFinding(doc, matchDb, 0, true);
assert.equal(match, "page structure matches a known phishing kit (distance 0)");
assert.equal(kitMatchFinding(doc, [{ fp: "ffffffffffffffff", label: 1 }, { fp, label: 0 }], 0, true), null, "benign entry closer means no match");
assert.equal(kitMatchFinding(doc, matchDb, 0, false), null, "flag off must suppress the finding");

const db = JSON.parse(fs.readFileSync(path.join(__dirname, "../ml/kit_db.json"), "utf8"));
assert.ok(db.length > 0);
for (const entry of db) {
  assert.deepEqual(Object.keys(entry).sort(), ["fp", "label"]);
  assert.match(entry.fp, /^[0-9a-f]{16}$/);
  assert.ok(entry.label === 0 || entry.label === 1);
}
assert.equal(new Set(db.map((entry) => `${entry.fp}:${entry.label}`)).size, db.length, "kit database must be deduplicated");

console.log("Kit matcher tests passed: match, no-match, disabled flag, and minimal database schema.");
