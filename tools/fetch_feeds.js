#!/usr/bin/env node
/*
 * Build today's crawl_input CSV from public phishing URL lists + the benign seed list.
 *   node tools/fetch_feeds.js --max 100 --benign 30
 * This only DOWNLOADS TEXT LISTS. It never opens a phishing URL; crawl_dom.js does that, in your sandbox.
 * Role 2 may already collect these feeds: use theirs if so, so both roles train on the same URLs.
 * Feed URLs change: override with --openphish <url> --phishingdb <url> if a download fails.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, domainOf, toCsvLine } = require("./dom_csv");

const DEFAULTS = {
  openphish: "https://openphish.com/feed.txt",
  phishingdb: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-today.txt"
};

function parseFeed(text) {
  return [...new Set(text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\//i.test(l)))].filter((u) => { try { new URL(u); return true; } catch { return false; } });
}

// small deterministic shuffle so the same day gives the same sample
function seededShuffle(items, seed) {
  let h = 2166136261; for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  const rand = () => { h ^= h << 13; h ^= h >>> 17; h ^= h << 5; return ((h >>> 0) % 1e6) / 1e6; };
  const a = [...items]; for (let i = a.length - 1; i > 0; i -= 1) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

// One URL per registrable domain, capped per source.
function pickPhishing(urls, cap, date, seenDomains) {
  const out = [];
  for (const url of seededShuffle(urls, date)) {
    const d = domainOf(url);
    if (!d || seenDomains.has(d)) continue;
    seenDomains.add(d); out.push(url);
    if (out.length >= cap) break;
  }
  return out;
}

function buildInputRows({ openphish = [], phishingdb = [], benign = [], max, benignMax, date }) {
  const seen = new Set();
  const each = Math.ceil(max / 2);
  const rows = [];
  for (const url of pickPhishing(openphish, each, date, seen)) rows.push({ url, label: 1, source: "openphish", date });
  for (const url of pickPhishing(phishingdb, max - rows.length, date, seen)) rows.push({ url, label: 1, source: "phishing_database", date });
  for (const b of benign.slice(0, benignMax)) rows.push({ url: b.url, label: 0, source: b.source || "benign_seed", date });
  return rows;
}

async function download(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30000), headers: { "user-agent": "phishguard-research-crawler" } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return parseFeed(await res.text());
}

async function main() {
  const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => { if (a.startsWith("--")) acc.push([a.slice(2), all[i + 1]]); return acc; }, []));
  const date = new Date().toISOString().slice(0, 10);
  const out = args.out || path.join(__dirname, `../data/dom/crawl_input_${date}.csv`);
  const lists = {};
  for (const name of ["openphish", "phishingdb"]) {
    try { lists[name] = await download(args[name] || DEFAULTS[name]); console.log(`${name}: ${lists[name].length} URLs`); }
    catch (error) { console.warn(`${name} failed (${error.message}); continuing without it`); lists[name] = []; }
  }
  const seed = parseCsv(fs.readFileSync(path.join(__dirname, "../data/dom/benign_login_seed.csv"), "utf8"));
  const rows = buildInputRows({ ...lists, benign: seed, max: Number(args.max || 100), benignMax: Number(args.benign || 30), date });
  fs.writeFileSync(out, ["url,label,source,date", ...rows.map((r) => toCsvLine([r.url, r.label, r.source, r.date]))].join("\n") + "\n");
  const n = rows.filter((r) => r.label === 1).length;
  console.log(`Wrote ${rows.length} rows (${n} phishing, ${rows.length - n} benign) to ${out}`);
  console.log("Next, INSIDE YOUR SANDBOX:  node tools/crawl_dom.js --input " + out + " --out data/dom/dom_features_" + date + ".csv");
}
if (require.main === module) main();
module.exports = { parseFeed, buildInputRows, seededShuffle };
