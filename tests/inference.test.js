import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractUrlFeatures, predictUrlMl } from "../extension/src/ml/inference.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const model = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../extension/src/ml/model.json"), "utf-8")
);

test("inference.js does not exhibit has_https bias between http and https of same URL", () => {
  const httpsRes = predictUrlMl("https://example-campus-portal.edu/login", model);
  const httpRes = predictUrlMl("http://example-campus-portal.edu/login", model);
  assert.equal(httpsRes.mlProb, httpRes.mlProb);
});

test("inference.js scores obfuscated phishing URL higher than clean domain", () => {
  const clean = predictUrlMl("https://github.com/nodejs/node", model);
  const phish = predictUrlMl(
    "https://secure-paypal-login.verify-998123.a1b2c3d4.top/auth/update?token=9182736455",
    model
  );
  assert.ok(phish.mlProb > clean.mlProb + 0.35);
  assert.ok(phish.contributions.length > 0);
});

test("extractUrlFeatures returns normalized bounded features", () => {
  const feats = extractUrlFeatures("https://sub.domain.org/path?q=123");
  for (const val of Object.values(feats)) {
    assert.ok(val >= 0 && val <= 1);
  }
});
