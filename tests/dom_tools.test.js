// No browser, no network, no dependencies:  node tests/dom_tools.test.js
const assert = require("node:assert/strict");
const { parseFeed, buildInputRows, seededShuffle } = require("../tools/fetch_feeds");
const { mergeRows, summarize } = require("../tools/merge_dom_csv");

// --- feed parsing: only valid http(s) URLs, deduplicated
assert.deepEqual(parseFeed("https://a.test/x\r\nnot a url\nhttps://a.test/x\nftp://b.test\n  https://c.test/y  \n"), ["https://a.test/x", "https://c.test/y"]);

// --- daily input: one URL per domain, capped, deterministic, benign appended
const op = ["https://one.test/a", "https://one.test/b", "https://two.test/a", "https://three.test/a"];
const pdb = ["https://two.test/zzz", "https://four.test/a", "https://five.test/a"];
const benign = [{ url: "https://github.com/login", source: "benign_seed:dev" }, { url: "https://gitlab.com/users/sign_in", source: "benign_seed:dev" }];
const rows = buildInputRows({ openphish: op, phishingdb: pdb, benign, max: 4, benignMax: 1, date: "2026-11-24" });
assert.equal(rows.filter((r) => r.label === 1).length, 4);
assert.equal(rows.filter((r) => r.label === 0).length, 1);
const hosts = rows.filter((r) => r.label === 1).map((r) => new URL(r.url).hostname);
assert.equal(new Set(hosts).size, hosts.length, "one URL per domain across both feeds");
assert.deepEqual(rows, buildInputRows({ openphish: op, phishingdb: pdb, benign, max: 4, benignMax: 1, date: "2026-11-24" }), "same day -> same sample");
assert.notDeepEqual(seededShuffle([1, 2, 3, 4, 5, 6, 7, 8], "a"), seededShuffle([1, 2, 3, 4, 5, 6, 7, 8], "b"));

// --- merge: dead rows dropped, one row per domain (earliest wins), conflicts reported
const r = (domain, label, date, ok = "1") => ({ domain, label: String(label), date, fetch_ok: ok, url: `https://${domain}/` });
const merged = mergeRows([
  [r("a.test", 1, "2026-11-20"), r("a.test", 1, "2026-11-22"), r("dead.test", 1, "2026-11-20", "0")],
  [r("b.test", 0, "2026-11-21"), r("both.test", 1, "2026-11-21"), r("both.test", 0, "2026-11-23")]
]);
assert.equal(merged.stats.deadOrBlocked, 1);
assert.equal(merged.stats.duplicates, 1);
assert.deepEqual(merged.stats.conflicts, ["both.test"]);
assert.equal(merged.rows.find((x) => x.domain === "a.test").date, "2026-11-20");
assert.equal(mergeRows([[r("both.test", 1, "d1"), r("both.test", 0, "d2"), r("c.test", 1, "d1")]], { dropConflicts: true }).rows.length, 1);

// --- same domain, same day: the login page (password field) is kept, not the completion-order winner
const tie = mergeRows([[{ ...r("college.test", 0, "2026-11-24"), url: "https://college.test/", dom_n_password_fields: "0" },
                        { ...r("college.test", 0, "2026-11-24"), url: "https://college.test/login", dom_n_password_fields: "1" }]]);
assert.equal(tie.rows.length, 1);
assert.equal(tie.rows[0].url, "https://college.test/login");

// --- summary states the small-set caveat and the time-split suggestion
const text = summarize(merged);
assert.match(text, /\*\*2 phishing, 3 benign\*\*|\*\*\d+ phishing, \d+ benign\*\*/);
assert.match(text, /DOM set is small/);
assert.match(text, /Fewer than 8 crawl days/);
console.log("dom_tools tests passed.");

// --- end-to-end: finish_role3 on synthetic crawl data (temp folder, nothing real touched)
{
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
  const csv = require("../tools/dom_csv");
  const names = JSON.parse(fs.readFileSync(path.join(__dirname, "../data/dom/dom_feature_schema.json"), "utf8")).features.map((f) => f.name);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "role3-"));
  const feat = (o = {}) => Object.fromEntries(names.map((n) => [n, o[n] ?? 0]));
  const row = (domain, label, date, findings, features, ok = 1) => csv.buildRow(
    { url: `https://${domain}/login`, label, domain, date, source: label ? "openphish" : "benign_seed:edu", fetch_ok: ok, scan_ms: "5.0" },
    ok ? { findings, domScore: findings.length ? 35 : 0, features: feat(features) } : null, names);
  const header = csv.buildHeader(names);
  fs.writeFileSync(path.join(tmp, "dom_features_2026-11-24.csv"), [header,
    row("bank.test", 1, "2026-11-24", ["password_form_cross_origin"], { dom_ext_resource_ratio: 0.8 }),
    row("kit2.test", 1, "2026-11-24", [], { dom_script_atob: 1 }),
    row("dead.test", 1, "2026-11-24", [], {}, 0),
    row("good.test", 0, "2026-11-24", [], { dom_ext_resource_ratio: 0.1 }),
    row("modal.test", 0, "2026-11-24", ["hidden_password_field"], {})].join("\n") + "\n");
  fs.writeFileSync(path.join(tmp, "benign_login_seed.csv"), "url,label,source,date\nhttps://college.test/login,0,benign_seed:college,\n");
  fs.writeFileSync(path.join(tmp, "dom_fp_report_before.md"), "| Benign (false positives) | 40 | 6 | 15.0% |\n");
  const out = path.join(tmp, "report.md");
  const run = spawnSync(process.execPath, [path.join(__dirname, "../tools/finish_role3.js"), "--dir", tmp, "--out", out, "--template", path.join(__dirname, "../docs/ROLE3_REPORT_TEMPLATE.md")], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const report = fs.readFileSync(out, "utf8");
  assert.ok(!report.includes("{{"), "unreplaced token");
  assert.match(report, /\| Crawled \| 3 \| 2 \|/);            // 3 phishing incl. dead, 2 benign
  assert.match(report, /\| Fetched successfully \| 2 \| 2 \|/);
  assert.match(report, /\| Original \| 40 \| 6 \(15\.0%\) \|/);  // from the "before" report
  assert.match(report, /\| After fixes \| 2 \| 1 \(50\.0%\) \|/); // modal.test false positive
  assert.match(report, /red banner on 1 of 2 phishing pages \(50\.0%\)/);
  assert.match(report, /openphish/);
  assert.match(report, /1 college portals/);
  assert.match(report, /Only 1 crawl day/);
  assert.ok(fs.existsSync(path.join(tmp, "dom_labeled.csv")) && fs.existsSync(path.join(tmp, "dom_fp_report.md")));
  // numbers that cannot be computed stay visible instead of being invented
  const noBefore = fs.rmSync(path.join(tmp, "dom_fp_report_before.md")) || spawnSync(process.execPath, [path.join(__dirname, "../tools/fill_report.js"), "--dir", tmp, "--out", out, "--template", path.join(__dirname, "../docs/ROLE3_REPORT_TEMPLATE.md")], { encoding: "utf8" });
  assert.match(fs.readFileSync(out, "utf8"), /\[FILL: fp_before_n\]/);
  console.log("finish_role3 end-to-end test passed.");
}