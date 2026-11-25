#!/usr/bin/env node
/*
 * PhishGuard DOM crawler (Role 3).
 *
 *   node tools/crawl_dom.js --input data/dom/crawl_input.csv --out data/dom/dom_features.csv
 *   node tools/crawl_dom.js --input ... --out ... --reextract     # rebuild features from saved snapshots, no network
 *   node tools/crawl_dom.js --retry-failed old.csv --out new.csv --timeout 45000 --concurrency 1   # retry only failures
 *
 * Input CSV columns: url,label[,source][,date]   (label: 1/0 or phish/benign; date: YYYY-MM-DD)
 *
 * SAFETY - run phishing crawls ONLY inside a disposable sandbox (VM / Docker, no logged-in
 * browser profile, no credentials, no shared folders). This script never fills, clicks or
 * submits anything, blocks every non-GET request, downloads, popups and dialogs.
 *
 * The SAME content.js that ships in the extension is injected, so training features and
 * live features cannot drift apart.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, normalizeLabel, domainOf, snapshotName, buildHeader, buildRow } = require("./dom_csv");

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => {
  if (a.startsWith("--")) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]);
  return acc;
}, []));

const ROOT = path.join(__dirname, "..");
const INPUT = args.input || path.join(ROOT, "data/dom/crawl_input.csv");
const OUT = args.out || path.join(ROOT, "data/dom/dom_features.csv");
const SNAP_DIR = args.snapshots || path.join(ROOT, "data/dom/snapshots");
const CONCURRENCY = Number(args.concurrency || 3);
const TIMEOUT = Number(args.timeout || 20000);
const SETTLE = Number(args.settle || 2000);
const REEXTRACT = Boolean(args.reextract);
const FEATURE_NAMES = JSON.parse(fs.readFileSync(path.join(ROOT, "data/dom/dom_feature_schema.json"), "utf8")).features.map((f) => f.name);

const CHROME_STUB = `
  window.chrome = window.chrome || {};
  window.chrome.runtime = { id: "phishguard-crawler", sendMessage: () => Promise.resolve(), onMessage: { addListener() {} } };
  // Defence in depth: nothing on the page may submit a form.
  addEventListener("submit", (e) => e.preventDefault(), true);
  HTMLFormElement.prototype.submit = function () {};
  HTMLFormElement.prototype.requestSubmit = function () {};
`;

async function crawlOne(context, row) {
  const url = row.url;
  const meta = {
    url, label: normalizeLabel(row.label), domain: domainOf(url),
    date: row.date || new Date().toISOString().slice(0, 10), source: row.source || "",
    fetch_ok: 0, snapshot_file: snapshotName(url)
  };
  const snapshotPath = path.join(SNAP_DIR, meta.snapshot_file);
  const page = await context.newPage();
  try {
    page.on("dialog", (d) => d.dismiss().catch(() => {}));
    page.on("popup", (p) => p.close().catch(() => {}));

    let response = null;
    if (REEXTRACT) {
      const html = fs.readFileSync(snapshotPath, "utf8");
      await page.route("**/*", (route) => {
        const req = route.request();
        if (req.url() === url && req.isNavigationRequest()) return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: html });
        return route.abort();
      });
    }
    response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT });
    await page.waitForLoadState("load", { timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(SETTLE); // let SPA / delayed login forms render

    // Pages (especially phishing kits) often redirect while loading. If the page navigates during
    // the scan, wait for the new document to settle and scan again (up to 3 attempts).
    let scan;
    for (let attempt = 1; ; attempt += 1) {
      try {
        scan = await page.evaluate(() => {
          const t0 = performance.now();
          const result = window.__phishGuardScanDom();
          return { ...result, scanMs: performance.now() - t0 };
        });
        break;
      } catch (error) {
        if (attempt >= 3 || !/context was destroyed|navigation|Target closed/i.test(String(error.message))) throw error;
        await page.waitForLoadState("domcontentloaded", { timeout: 10000 }).catch(() => {});
        await page.waitForTimeout(SETTLE);
      }
    }

    if (!REEXTRACT) {
      fs.mkdirSync(SNAP_DIR, { recursive: true });
      fs.writeFileSync(snapshotPath, await page.content());
    }
    const finalUrl = page.url();
    Object.assign(meta, {
      fetch_ok: 1, http_status: response?.status() ?? "", final_url: finalUrl,
      redirected_cross_site: domainOf(finalUrl) !== meta.domain ? 1 : 0, scan_ms: scan.scanMs.toFixed(1)
    });
    return { line: buildRow(meta, scan, FEATURE_NAMES), ok: true };
  } catch (error) {
    meta.error = String(error.message || error).split("\n")[0].slice(0, 160);
    return { line: buildRow(meta, null, FEATURE_NAMES), ok: false };
  } finally {
    await page.close().catch(() => {});
  }
}

async function main() {
  let chromium;
  try { ({ chromium } = require("playwright")); }
  catch { console.error("Playwright is not installed. Run:  npm i -D playwright tldts && npx playwright install chromium"); process.exit(1); }

  // --retry-failed <previous output csv>: re-crawl only the rows that failed last time
  // (use with a longer --timeout and --concurrency 1 for slow or bot-shy sites).
  const rows = args["retry-failed"]
    ? parseCsv(fs.readFileSync(args["retry-failed"], "utf8")).filter((r) => r.fetch_ok === "0" && r.url).map((r) => ({ url: r.url, label: r.label, source: r.source, date: r.date }))
    : parseCsv(fs.readFileSync(INPUT, "utf8")).filter((r) => r.url);
  console.log(`${rows.length} URLs${REEXTRACT ? " (re-extracting from snapshots, offline)" : ""}, concurrency ${CONCURRENCY}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    acceptDownloads: false, ignoreHTTPSErrors: true, serviceWorkers: "block", locale: "en-US",
    viewport: { width: 1280, height: 800 }
  });
  await context.addInitScript(CHROME_STUB);
  await context.addInitScript({ path: path.join(ROOT, "content.js") });
  // Read-only crawl: any request that could carry data out is dropped.
  await context.route("**/*", (route) => (["GET", "HEAD", "OPTIONS"].includes(route.request().method()) ? route.fallback() : route.abort()));

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  const lines = [buildHeader(FEATURE_NAMES)];
  let next = 0; let ok = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (next < rows.length) {
      const index = next++;
      const result = await crawlOne(context, rows[index]);
      lines.push(result.line);
      if (result.ok) ok += 1;
      if ((index + 1) % 10 === 0) console.log(`  ${index + 1}/${rows.length}`);
    }
  }));
  await browser.close();

  fs.writeFileSync(OUT, lines.join("\n") + "\n");
  console.log(`Wrote ${lines.length - 1} rows (${ok} fetched OK) to ${OUT}. Filter fetch_ok==1 for training; the dead-page rate is itself a result worth reporting.`);
}
main();