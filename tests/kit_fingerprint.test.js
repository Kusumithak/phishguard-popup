"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { kitFingerprint, hamming } = require("../content.js");

const FIXTURES = path.join(__dirname, "fixtures");
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);

// Small parser for the controlled, safe fixtures below. It builds only the DOM properties
// the fingerprint is allowed to inspect; text and attribute values are intentionally omitted.
function documentFromHtml(html, domain) {
  const elements = [];
  const forms = [];
  const stack = [];
  const tokens = /<!--[\s\S]*?-->|<![^>]*>|<\/?([a-z][\w:-]*)\b([^>]*)>/gi;
  for (const match of html.matchAll(tokens)) {
    const raw = match[0];
    const tag = match[1]?.toLowerCase();
    if (!tag) continue;
    if (raw.startsWith("</")) {
      const index = stack.map((item) => item.tagName).lastIndexOf(tag);
      if (index >= 0) stack.length = index;
      continue;
    }

    const attrs = Object.fromEntries([...raw.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)]
      .map((item) => [item[1].toLowerCase(), item[2] ?? item[3] ?? item[4] ?? ""]));
    const node = { tagName: tag, type: (attrs.type || "text").toLowerCase() };
    elements.push(node);
    if (tag === "form") {
      node.method = (attrs.method || "get").toLowerCase();
      node.inputs = [];
      node.querySelectorAll = (selector) => selector === "input" ? node.inputs : [];
      forms.push(node);
    } else if (tag === "input") {
      const parentForm = [...stack].reverse().find((item) => item.tagName === "form");
      parentForm?.inputs.push(node);
    }
    if (!VOID.has(tag) && !raw.endsWith("/>")) stack.push(node);
  }

  return {
    URL: `https://${domain}/`,
    forms,
    querySelectorAll(selector) {
      if (selector === "*") return elements;
      if (selector === 'input[type="password"]') return elements.filter((item) => item.tagName === "input" && item.type === "password");
      const tags = selector.split(",").map((value) => value.trim());
      return elements.filter((item) => tags.includes(item.tagName));
    }
  };
}

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
