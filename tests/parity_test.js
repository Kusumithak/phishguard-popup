/* Synthetic smoke-test fixture only; it is not training/evaluation data. */
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const PhishUrlModel = require('../ml/url_model.js');

const root = path.resolve(__dirname, '..');
const python = process.env.PYTHON || path.join(root, '.venv', 'Scripts', 'python.exe');
const fixtureArgs = [path.join(__dirname, 'parity_fixture.py')];
if (process.argv[2]) fixtureArgs.push(path.resolve(process.argv[2]));
const fixture = spawnSync(python, fixtureArgs, {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 32 * 1024 * 1024,
});
if (fixture.status !== 0) {
  throw new Error(`Python parity fixture failed (${fixture.status}): ${fixture.stderr}`);
}
const { model, rows } = JSON.parse(fixture.stdout);
let maxFeatureDelta = 0;
let maxScoreDelta = 0;

for (const row of rows) {
  const jsFeatures = PhishUrlModel.extract(row.url, model.lexicon);
  const keys = new Set([...Object.keys(row.features), ...Object.keys(jsFeatures)]);
  for (const key of keys) {
    const delta = Math.abs((row.features[key] || 0) - (jsFeatures[key] || 0));
    maxFeatureDelta = Math.max(maxFeatureDelta, delta);
    if (delta > 1e-9) {
      throw new Error(`Feature mismatch ${key} for ${row.url}: ${row.features[key]} vs ${jsFeatures[key]}`);
    }
  }
  const jsScore = PhishUrlModel.score(model, row.url);
  const delta = Math.abs(row.score - jsScore);
  maxScoreDelta = Math.max(maxScoreDelta, delta);
  if (delta > 1e-6) {
    throw new Error(`Score mismatch for ${row.url}: ${row.score} vs ${jsScore}`);
  }
}

console.log('Synthetic smoke-test parity passed for URL features and the Python scoring helper. No dataset metrics computed.');
