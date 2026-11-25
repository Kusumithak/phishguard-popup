// Runs every fixture through the real content.js in jsdom and checks the manifest.
// Needs jsdom:  npm i -D jsdom   then   node tests/fixtures.test.js
let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch { console.log("jsdom not installed - skipping fixture tests (npm i -D jsdom)."); process.exit(0); }
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const dir = path.join(__dirname, "fixtures");
const src = fs.readFileSync(path.join(__dirname, "../content.js"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));

function scan(url, html) {
  const w = new JSDOM(html, { url, runScripts: "outside-only", pretendToBeVisual: true }).window;
  w.Element.prototype.getClientRects = function () {
    for (let el = this; el && el.nodeType === 1; el = el.parentElement) {
      const cs = w.getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden") return [];
    }
    return [{}];
  };
  w.chrome = { runtime: { id: "t", sendMessage: () => Promise.resolve(), onMessage: { addListener() {} } } };
  w.eval(src);
  const result = w.__phishGuardScanDom();
  const out = { flags: [...result.findings].sort(), features: { ...result.features }, domScore: result.domScore };
  w.close();
  return out;
}

const STRONG = ["hidden_password_field", "password_form_cross_origin", "password_form_http"];
let caught = 0, phish = 0, falseAlarms = 0, benign = 0;
for (const fx of manifest.fixtures) {
  const got = scan(manifest.baseUrl + fx.file, fs.readFileSync(path.join(dir, fx.file), "utf8"));
  assert.deepEqual(got.flags, [...fx.flags].sort(), `${fx.file}: flags ${JSON.stringify(got.flags)}`);
  for (const [name, value] of Object.entries(fx.features || {})) assert.equal(got.features[name], value, `${fx.file}: ${name}`);
  const red = got.flags.some((f) => STRONG.includes(f));
  if (fx.label === 1) { phish += 1; if (red) caught += 1; } else { benign += 1; if (red) falseAlarms += 1; }
}
console.log(`Fixture tests passed (${manifest.fixtures.length} pages). Hand-set rules alone: caught ${caught}/${phish} phishing-style pages, ${falseAlarms}/${benign} benign pages would show a red banner (the known sibling-subdomain false positive).`);
