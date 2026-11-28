"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { kitFingerprint, hamming } = require("../content.js");
const { documentFromHtml } = require("./kit_fixture_document.js");
const FIXTURES = path.join(__dirname, "fixtures");

function fixtureDocument(filename, domain) {
  return documentFromHtml(fs.readFileSync(path.join(FIXTURES, filename), "utf8"), domain);
}

const first = fixtureDocument("kit_structure_a.html", "alpha.test");
const second = fixtureDocument("kit_structure_b.html", "beta.test");
const different = fixtureDocument("kit_structure_different.html", "catalog.test");
const firstFp = kitFingerprint(first);
const secondFp = kitFingerprint(second);
const differentFp = kitFingerprint(different);
const sameStructureDistance = hamming(firstFp, secondFp);
const differentStructureDistance = hamming(firstFp, differentFp);

assert.match(firstFp, /^[0-9a-f]{16}$/);
assert.equal(hamming(firstFp, firstFp), 0);
assert.equal(hamming(firstFp, secondFp), hamming(secondFp, firstFp));
assert.ok(sameStructureDistance <= 4, `same structure distance ${sameStructureDistance} must be <= 4`);
assert.ok(differentStructureDistance >= 16, `different structure distance ${differentStructureDistance} must be >= 16`);
assert.throws(() => hamming("xyz", firstFp), TypeError);

const largeHtml = `<html><body>${"<section><div><a href='#'>Safe item</a><img src='safe.png'></div></section>".repeat(80)}</body></html>`;
const largePage = documentFromHtml(largeHtml, "large-safe.test");
const start = performance.now();
for (let i = 0; i < 20; i += 1) kitFingerprint(largePage);
const averageMs = (performance.now() - start) / 20;
assert.ok(averageMs < 10, `400-element fixture average ${averageMs.toFixed(3)} ms must be < 10 ms`);
console.log(`Kit fingerprint tests passed: same=${sameStructureDistance}, different=${differentStructureDistance}, 400-element avg=${averageMs.toFixed(3)} ms`);
