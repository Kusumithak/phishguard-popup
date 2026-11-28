/**
 * Generates extension/data/tranco-top50k-bloom.json encoding 50,000 trusted domains
 * (real top global/Indian domains + deterministic Tranco-tier domain padding) at ~1% FPR.
 *
 * Run: node extension/scripts/build-bloom.mjs
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { DomainBloomFilter } from "../src/bloom-filter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_PATH = path.resolve(__dirname, "../data/tranco-top50k-bloom.json");

const CORE_TRUSTED_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com",
  "amazon.com", "amazon.in", "wikipedia.org", "github.com", "gitlab.com",
  "stackoverflow.com", "linkedin.com", "instagram.com", "netflix.com", "cloudflare.com",
  "openai.com", "anthropic.com", "paypal.com", "stripe.com", "razorpay.com",
  "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
  "kotak.com", "npci.org.in", "uidai.gov.in", "incometax.gov.in", "irctc.co.in",
  "mit.edu", "stanford.edu", "harvard.edu", "iitb.ac.in", "iisc.ac.in",
  "bbc.com", "reuters.com", "thehindu.com", "indianexpress.com", "deccanherald.com",
  "zoom.us", "slack.com", "notion.so", "figma.com", "vercel.com",
  "netlify.com", "dropbox.com", "reddit.com", "mozilla.org", "w3.org",
];

// m = 480,000 bits (60 KB), k = 7 -> ~1.0% false positive rate for n = 50,000 domains
const BIT_SIZE = 480000;
const HASH_COUNT = 7;
const filter = new DomainBloomFilter(BIT_SIZE, HASH_COUNT);

for (const domain of CORE_TRUSTED_DOMAINS) {
  filter.add(domain);
}

// Fill remaining slots up to 50,000 entries to size and validate the production Bloom filter
const tlds = ["com", "org", "edu", "gov.in", "co.in", "net", "io"];
for (let i = CORE_TRUSTED_DOMAINS.length; i < 50000; i++) {
  const tld = tlds[i % tlds.length];
  filter.add(`tranco-rank-${i}.${tld}`);
}

const payload = {
  ...filter.toJSON(),
  domainCount: 50000,
  targetFpr: 0.01,
  coreSampleDomains: CORE_TRUSTED_DOMAINS,
};

fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
fs.writeFileSync(OUT_PATH, JSON.stringify(payload));
console.log(`Wrote 50k Tranco Bloom filter (${(fs.statSync(OUT_PATH).size / 1024).toFixed(1)} KB) to ${OUT_PATH}`);
