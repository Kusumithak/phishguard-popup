import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRules } from "../extension/src/rules.js";

test("rules.js flags IP host, @ symbol, punycode, and suspicious TLD", () => {
  const res = evaluateRules("http://192.168.1.50/login@verify");
  assert.equal(res.flags.flag_ip_host, 1);
  assert.equal(res.flags.flag_at_symbol, 1);
  assert.equal(res.flags.flag_sensitive_keywords, 1);
  assert.ok(res.ruleScore > 2.5);

  const puny = evaluateRules("https://xn--pypal-4ve.xyz/signin");
  assert.equal(puny.flags.flag_punycode, 1);
  assert.equal(puny.flags.flag_suspicious_tld, 1);
});

test("rules.js suppresses brand/keyword false positives on trusted Bloom domains", () => {
  const res = evaluateRules(
    "https://accounts.google.com/v3/signin/identifier?continue=https://mail.google.com",
    true
  );
  assert.equal(res.flags.flag_brand_impersonation, 0);
  assert.equal(res.flags.flag_sensitive_keywords, 0);
  assert.equal(res.activeFlags.length, 0);
});

test("rules.js detects brand impersonation on untrusted domain", () => {
  const res = evaluateRules("https://paypal-secure-login.verify-desk.top/update", false);
  assert.equal(res.flags.flag_brand_impersonation, 1);
  assert.equal(res.flags.flag_suspicious_tld, 1);
  assert.equal(res.flags.flag_sensitive_keywords, 1);
});
