/* Compare the Colab-saved test probabilities with the exported pure-JS models. */
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const PhishUrlModel = require('../ml/url_model.js');

const root = path.resolve(__dirname, '..');
const python = process.env.PYTHON || path.join(root, '.venv', 'Scripts', 'python.exe');
const readCsv = (file) => parseCsv(fs.readFileSync(path.join(root, file), 'utf8'));
function parseCsv(text) {
  const records = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field.length === 0) quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((cell) => cell !== '')) records.push(row);
      row = [];
    } else field += ch;
  }
  if (field || row.length) { row.push(field); records.push(row); }
  const [header, ...body] = records;
  return body.map((cells) => Object.fromEntries(header.map((name, i) => [name, cells[i] || ''])));
}
const csvCell = (value) => `"${String(value).replace(/"/g, '""')}"`;
const runScorer = (rows, lookupFiles) => {
  const input = `url\n${rows.map((row) => csvCell(row.url)).join('\n')}\n`;
  const args = [path.join(root, 'scripts', 'score_urls.py'), '-', '-',
    '--model', path.join(root, 'out', 'model.json'),
    '--oof', lookupFiles ? path.join(root, 'out', 'url_oof_train.csv') : path.join(root, 'out', 'missing-oof.csv'),
    '--test', lookupFiles ? path.join(root, 'out', 'url_test_pred.csv') : path.join(root, 'out', 'missing-test.csv')];
  const result = spawnSync(python, args, { cwd: root, input, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`score_urls.py failed (${result.status}): ${result.stderr}`);
  return parseCsv(result.stdout);
};

const readModel = (file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const lr = readModel('out/model_lr.json');
const gb = readModel('out/model_gb.json');
const candidate = readModel('ml/model_candidate.json');
const savedTest = readCsv('out/url_test_pred.csv');
if (savedTest.length !== 303) throw new Error(`Expected 303 saved test rows; got ${savedTest.length}.`);
let maxLrDelta = 0, maxGbDelta = 0, maxCandidateDelta = 0;

for (const row of savedTest) {
  const lrDelta = Math.abs(Number(row.prob_lr) - PhishUrlModel.score(lr, row.url));
  const gbDelta = Math.abs(Number(row.prob_gb) - PhishUrlModel.score(gb, row.url));
  const candidateDelta = Math.abs(Number(row.ml_prob) - PhishUrlModel.score(candidate, row.url));
  maxLrDelta = Math.max(maxLrDelta, lrDelta);
  maxGbDelta = Math.max(maxGbDelta, gbDelta);
  maxCandidateDelta = Math.max(maxCandidateDelta, candidateDelta);
  if (lrDelta > 1e-6 || gbDelta > 1e-6 || candidateDelta > 1e-6) {
    throw new Error(`Saved probability mismatch for ${row.url}: LR=${lrDelta}, GB=${gbDelta}, candidate=${candidateDelta}`);
  }
}

const sample = savedTest.slice(0, 200);
const joined = runScorer(sample, true);
const fallback = runScorer(sample, false);
const oofSample = readCsv('out/url_oof_train.csv').slice(0, 200);
const oofJoined = runScorer(oofSample, true);
let maxJoinDelta = 0, maxFallbackDelta = 0;
for (let i = 0; i < sample.length; i++) {
  const jsScore = PhishUrlModel.score(candidate, sample[i].url);
  const joinDelta = Math.abs(Number(joined[i].ml_prob) - jsScore);
  const fallbackDelta = Math.abs(Number(fallback[i].ml_prob) - jsScore);
  maxJoinDelta = Math.max(maxJoinDelta, joinDelta);
  maxFallbackDelta = Math.max(maxFallbackDelta, fallbackDelta);
  if (joined[i].prob_source !== 'test' || fallback[i].prob_source !== 'model' || joinDelta > 1e-6 || fallbackDelta > 1e-6) {
    throw new Error(`score_urls.py mismatch for ${sample[i].url}: join=${joinDelta}, fallback=${fallbackDelta}, sources=${joined[i].prob_source}/${fallback[i].prob_source}`);
  }
}
let maxOofLookupDelta = 0;
for (let i = 0; i < oofSample.length; i++) {
  const delta = Math.abs(Number(oofJoined[i].ml_prob) - Number(oofSample[i].ml_prob));
  maxOofLookupDelta = Math.max(maxOofLookupDelta, delta);
  if (oofJoined[i].prob_source !== 'oof' || delta > 1e-12) {
    throw new Error(`score_urls.py OOF lookup mismatch for ${oofSample[i].url}: delta=${delta}, source=${oofJoined[i].prob_source}`);
  }
}
console.log(`Saved test parity passed: ${savedTest.length} URLs; max deltas LR=${maxLrDelta}, GB=${maxGbDelta}, candidate=${maxCandidateDelta}.`);
console.log(`score_urls.py passed: ${sample.length} test joins and model fallbacks matched JS; ${oofSample.length} OOF lookups matched saved ml_prob. Max deltas=${maxJoinDelta}, ${maxOofLookupDelta}, ${maxFallbackDelta}.`);
