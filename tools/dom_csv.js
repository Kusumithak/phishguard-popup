/* Pure helpers shared by the crawler, the FP report and the tests (no browser needed). */
"use strict";
const crypto = require("node:crypto");

// The seven hand-set DOM rule flags in content.js (0/1 columns "flag_*" in the shared CSV).
const FLAG_NAMES = [
  "password_form_cross_origin", "password_form_http", "external_form_http",
  "hidden_password_field", "hidden_iframe_with_form", "password_field_without_form", "invalid_form_action"
];
// Findings that make hybrid.js raise the fused score to at least 60 (= red PHISHING banner).
const STRONG_FLAGS = ["hidden_password_field", "password_form_cross_origin", "password_form_http"];

const META_COLUMNS = ["url", "label", "domain", "date", "source", "fetch_ok", "http_status", "final_url", "redirected_cross_site", "scan_ms", "snapshot_file", "error"];

function csvEscape(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
const toCsvLine = (values) => values.map(csvEscape).join(",");

// Small RFC-4180 style parser (quotes, escaped quotes, CRLF).
function parseCsv(text) {
  const rows = []; let row = []; let field = ""; let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { row.push(field); field = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field); field = "";
      if (row.some((cell) => cell !== "")) rows.push(row);
      row = [];
    } else field += ch;
  }
  row.push(field);
  if (row.some((cell) => cell !== "")) rows.push(row);
  if (!rows.length) return [];
  const header = rows[0].map((h) => h.trim());
  return rows.slice(1).map((cells) => Object.fromEntries(header.map((h, i) => [h, (cells[i] ?? "").trim()])));
}

// 1 = phishing, 0 = benign (the shared-format convention). Accepts a few spellings.
function normalizeLabel(value) {
  const v = String(value).trim().toLowerCase();
  if (["1", "phish", "phishing", "malicious"].includes(v)) return 1;
  if (["0", "benign", "legit", "legitimate", "safe"].includes(v)) return 0;
  throw new Error(`Unrecognised label "${value}" (use 1/0 or phish/benign)`);
}

// eTLD+1 using the full Public Suffix List when tldts is installed (matches Python tldextract),
// otherwise a small fallback. Install with: npm i -D tldts
function domainOf(url) {
  try {
    const { getDomain } = require("tldts");
    const d = getDomain(url);
    if (d) return d;
  } catch { /* tldts not installed */ }
  try {
    const host = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    const labels = host.split(".");
    const multi = new Set(["co.uk", "org.uk", "ac.uk", "com.au", "co.in", "org.in", "gov.in", "ac.in", "nic.in", "bank.in", "co.jp", "com.br"]);
    return labels.length > 2 && multi.has(labels.slice(-2).join(".")) ? labels.slice(-3).join(".") : labels.slice(-2).join(".");
  } catch { return ""; }
}

const snapshotName = (url) => `${crypto.createHash("sha1").update(url).digest("hex")}.html`;
const flagColumns = () => FLAG_NAMES.map((name) => `flag_${name}`);

// One CSV row: meta columns, flag_* (0/1), dom_hand_score, then the dom_* features in schema order.
function buildRow(meta, scan, featureNames) {
  const metaValues = META_COLUMNS.map((c) => meta[c] ?? "");
  if (!scan) return toCsvLine([...metaValues, ...FLAG_NAMES.map(() => ""), "", ...featureNames.map(() => "")]);
  const flags = FLAG_NAMES.map((name) => (scan.findings.includes(name) ? 1 : 0));
  return toCsvLine([...metaValues, ...flags, scan.domScore, ...featureNames.map((n) => scan.features[n])]);
}
const buildHeader = (featureNames) => toCsvLine([...META_COLUMNS, ...flagColumns(), "dom_hand_score", ...featureNames]);

module.exports = { FLAG_NAMES, STRONG_FLAGS, META_COLUMNS, csvEscape, toCsvLine, parseCsv, normalizeLabel, domainOf, snapshotName, flagColumns, buildRow, buildHeader };
