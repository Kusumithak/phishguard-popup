// One command for every test:  node tests/run_all.js
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const files = ["rules.test.js", "dom_csv.test.js", "dom_tools.test.js", "dom_features.test.js", "fixtures.test.js"];
let failed = 0;
for (const file of files) {
  const run = spawnSync(process.execPath, [path.join(__dirname, file)], { encoding: "utf8" });
  const out = (run.stdout + run.stderr).trim().split("\n").filter(Boolean);
  console.log(`${run.status === 0 ? "PASS" : "FAIL"}  ${file.padEnd(22)} ${run.status === 0 ? out[out.length - 1] : out.slice(0, 8).join("\n")}`);
  if (run.status !== 0) failed += 1;
}
console.log(failed ? `\n${failed} test file(s) failed.` : "\nAll test files passed.");
process.exit(failed ? 1 : 0);
