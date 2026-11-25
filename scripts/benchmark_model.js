/* Measure URL scoring only. URLs are read as strings and never opened. */
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const PhishUrlModel = require('../ml/url_model.js');

const modelPath = path.resolve(process.argv[2] || 'out/model.json');
const csvPath = path.resolve(process.argv[3] || 'out/url_test_pred.csv');
const model = JSON.parse(fs.readFileSync(modelPath, 'utf8'));
const lines = fs.readFileSync(csvPath, 'utf8').trim().split(/\r?\n/).slice(1);
const urls = lines.map((line) => {
  if (line.startsWith('"')) {
    let value = '';
    for (let i = 1; i < line.length; i++) {
      if (line[i] === '"' && line[i + 1] === '"') { value += '"'; i++; }
      else if (line[i] === '"') break;
      else value += line[i];
    }
    return value;
  }
  return line.slice(0, line.indexOf(','));
}).slice(0, 1000);
if (urls.length !== 1000) throw new Error(`Need 1000 test URLs; found ${urls.length}.`);

for (let i = 0; i < 100; i++) PhishUrlModel.score(model, urls[i]);
const durations = urls.map((url) => {
  const start = performance.now();
  PhishUrlModel.score(model, url);
  return performance.now() - start;
}).sort((a, b) => a - b);
const mean = durations.reduce((sum, ms) => sum + ms, 0) / durations.length;
const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
console.log(`Scored ${urls.length} test URL strings: mean ${mean.toFixed(6)} ms, p95 ${p95.toFixed(6)} ms.`);
