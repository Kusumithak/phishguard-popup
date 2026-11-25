#!/usr/bin/env node
/*
 * Real-Chrome self-test with NO real phishing site involved.
 *   node tools/selftest.js
 * Serves tests/fixtures/* from memory under https://fixtures.example.com/ (every other request is
 * blocked), injects the real content.js, and compares flags/features with tests/fixtures/manifest.json.
 * Run this once before crawling real phishing URLs: it proves your Chrome + crawler + content.js agree.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const ROOT = path.join(__dirname, "..");
const dir = path.join(ROOT, "tests/fixtures");
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
const STRONG = ["hidden_password_field", "password_form_cross_origin", "password_form_http"];
const CHROME_STUB = `
  window.chrome = window.chrome || {};
  window.chrome.runtime = { id: "phishguard-selftest", sendMessage: () => Promise.resolve(), onMessage: { addListener() {} } };
  addEventListener("submit", (e) => e.preventDefault(), true);
`;

(async () => {
  let chromium;
  try { ({ chromium } = require("playwright")); }
  catch { console.error("Run: npm i -D playwright && npx playwright install chromium"); process.exit(1); }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1280, height: 800 } });
  await context.addInitScript(CHROME_STUB);
  await context.addInitScript({ path: path.join(ROOT, "content.js") });
  const byUrl = new Map(manifest.fixtures.map((fx) => [manifest.baseUrl + fx.file, fx.file]));
  await context.route("**/*", (route) => {
    const file = byUrl.get(route.request().url());
    if (file && route.request().isNavigationRequest()) {
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fs.readFileSync(path.join(dir, file), "utf8") });
    }
    return route.abort(); // nothing else may leave the machine
  });

  let failures = 0, caught = 0, phish = 0, redBenign = 0, benign = 0;
  console.log("fixture".padEnd(34), "label  result  detail");
  for (const fx of manifest.fixtures) {
    const page = await context.newPage();
    const problems = [];
    try {
      await page.goto(manifest.baseUrl + fx.file, { waitUntil: "domcontentloaded", timeout: 10000 });
      await page.waitForTimeout(300); // short on purpose: some fixtures contain a delayed meta refresh
      const result = await page.evaluate(() => window.__phishGuardScanDom());
      const flags = [...result.findings].sort();
      if (JSON.stringify(flags) !== JSON.stringify([...fx.flags].sort())) problems.push(`flags ${JSON.stringify(flags)} != ${JSON.stringify(fx.flags)}`);
      for (const [name, value] of Object.entries(fx.features || {})) {
        if (result.features[name] !== value) problems.push(`${name}=${result.features[name]} (expected ${value})`);
      }
      const red = flags.some((f) => STRONG.includes(f));
      if (fx.label === 1) { phish += 1; if (red) caught += 1; } else { benign += 1; if (red) redBenign += 1; }
    } catch (error) {
      problems.push(String(error.message).split("\n")[0]);
    }
    if (problems.length) failures += 1;
    console.log(fx.file.padEnd(34), String(fx.label).padEnd(6), problems.length ? "FAIL  " : "ok    ", problems.join("; "));
    await page.close();
  }
  await browser.close();
  console.log(`\nHand-set rules alone: ${caught}/${phish} phishing-style fixtures raise a red banner; ${redBenign}/${benign} benign fixtures do (known sibling-subdomain case).`);
  console.log(failures ? `${failures} fixture(s) FAILED - send me this output.` : "Self-test passed: Chrome + crawler + content.js agree with the jsdom tests.");
  process.exit(failures ? 1 : 0);
})();
