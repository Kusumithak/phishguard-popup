import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DomainBloomFilter } from "../extension/src/bloom-filter.js";
import { evaluateHybrid } from "../extension/src/hybrid.js";
import { VerdictCache } from "../extension/src/verdict-cache.js";
import { AllowlistStore } from "../extension/src/allowlist.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bloomJson = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../extension/data/tranco-top50k-bloom.json"), "utf-8")
);
const model = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../extension/src/ml/model.json"), "utf-8")
);
const bloom = DomainBloomFilter.fromJSON(bloomJson);

test("hybrid.js marks Tranco Bloom domains including Google login as SAFE", () => {
  const safeRes = evaluateHybrid("https://github.com/trending", { bloomFilter: bloom, model });
  assert.equal(safeRes.verdict, "SAFE");
  assert.equal(safeRes.trustedBloomHit, true);

  const benignLogin = evaluateHybrid(
    "https://accounts.google.com/v3/signin/identifier?continue=https://mail.google.com",
    {
      bloomFilter: bloom,
      model,
      domFeatures: { dom_external_resource_ratio: 0.08, dom_foreign_favicon: 0 },
    }
  );
  assert.equal(benignLogin.verdict, "SAFE");
  assert.equal(benignLogin.trustedBloomHit, true);
});

test("hybrid.js flags multi-signal phishing URL + DOM mismatch as PHISHING with explanations", () => {
  const phishRes = evaluateHybrid(
    "https://secure-paypal-login.verify-account-8841.top/signin/kyc-update.php?token=99182736",
    {
      bloomFilter: bloom,
      model,
      domFeatures: {
        dom_external_resource_ratio: 0.85,
        dom_foreign_favicon: 1,
        dom_eval_atob_hits: 1,
        dom_brand_domain_mismatch: 1,
        dom_password_external_form: 1,
      },
    }
  );
  assert.equal(phishRes.verdict, "PHISHING");
  assert.ok(phishRes.riskScore >= 0.72);
  assert.ok(phishRes.whyFlagged.length >= 3);
});

test("allowlist bypasses PHISHING verdict and exports valid false-positive JSON", () => {
  const allowlist = new AllowlistStore();
  const url = "https://portal-verify-9821.billing-desk.xyz/account";
  allowlist.markSafe(url, { verdict: "SUSPICIOUS", riskScore: 0.55 });

  const res = evaluateHybrid(url, { bloomFilter: bloom, allowlistSet: allowlist.hosts, model });
  assert.equal(res.verdict, "SAFE");
  assert.equal(res.allowlisted, true);

  const exported = JSON.parse(allowlist.exportJSON());
  assert.equal(exported.false_positive_reports.length, 1);
  assert.equal(exported.allowlisted_hosts[0], "portal-verify-9821.billing-desk.xyz");
});

test("VerdictCache returns per-hostname cache hits with low latency", () => {
  const cache = new VerdictCache(60_000, 100);
  const url = "https://example.org/login";
  assert.equal(cache.get(url), null);

  cache.set(url, { verdict: "SAFE", riskScore: 0.1 });
  const hit = cache.get("https://example.org/dashboard");
  assert.ok(hit !== null);
  assert.equal(hit.cacheHit, true);
  assert.equal(hit.verdict, "SAFE");
});
