#!/usr/bin/env node
"use strict";

// Offline evaluation of the exact URL model shipped with the extension.
// This reads labeled URLs as strings; it does not visit or fetch any site.
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, normalizeLabel } = require("./dom_csv.js");
require("../ml/inference.js");
const { scoreWithModel } = globalThis.PhishGuardML;
const rules = require("../rules.js");

const ROOT = path.resolve(__dirname, "..");
const DEFAULT_INPUT = path.join(ROOT, "data", "dom", "dom_labeled.csv");
const DEFAULT_OUTPUT = path.join(ROOT, "out", "url_model_evaluation.md");

function argumentsFrom(argv) {
  const options = { input: DEFAULT_INPUT, output: DEFAULT_OUTPUT };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help" || argv[i] === "-h") {
      options.help = true;
      continue;
    }
    if (!["--input", "--output"].includes(argv[i]) || !argv[i + 1]) {
      throw new Error(`Unknown or incomplete argument: ${argv[i]}`);
    }
    options[argv[i].slice(2)] = path.resolve(process.cwd(), argv[i + 1]);
    i += 1;
  }
  return options;
}

function usage() {
  return [
    "Usage: node tools/evaluate_url_model.js [--input labeled.csv] [--output report.md]",
    "Defaults: data/dom/dom_labeled.csv -> out/url_model_evaluation.md",
    "The input must have url, label, domain, and fetch_ok columns."
  ].join("\n");
}

function auc(scores, labels) {
  let positives = 0;
  let negatives = 0;
  for (const label of labels) label === 1 ? positives += 1 : negatives += 1;
  if (!positives || !negatives) return null;

  const ordered = scores.map((score, i) => ({ score, label: labels[i] }))
    .sort((a, b) => a.score - b.score);
  let rankSum = 0;
  for (let start = 0; start < ordered.length;) {
    let end = start + 1;
    while (end < ordered.length && ordered[end].score === ordered[start].score) end += 1;
    const averageRank = ((start + 1) + end) / 2;
    for (let i = start; i < end; i += 1) {
      if (ordered[i].label === 1) rankSum += averageRank;
    }
    start = end;
  }
  return (rankSum - positives * (positives + 1) / 2) / (positives * negatives);
}

function confusion(scores, labels, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  scores.forEach((score, i) => {
    const predicted = score >= threshold;
    if (predicted && labels[i] === 1) tp += 1;
    else if (predicted) fp += 1;
    else if (labels[i] === 0) tn += 1;
    else fn += 1;
  });
  return {
    tp, fp, tn, fn,
    tpr: tp + fn ? tp / (tp + fn) : 0,
    fpr: fp + tn ? fp / (fp + tn) : 0,
    precision: tp + fp ? tp / (tp + fp) : 0
  };
}

function averagePrecision(scores, labels) {
  const positives = labels.reduce((total, label) => total + (label === 1), 0);
  if (!positives) return null;
  const ordered = scores.map((score, i) => ({ score, label: labels[i] }))
    .sort((a, b) => b.score - a.score);
  let seen = 0, truePositives = 0, sumPrecision = 0;
  for (let start = 0; start < ordered.length;) {
    let end = start + 1;
    while (end < ordered.length && ordered[end].score === ordered[start].score) end += 1;
    let positivesInGroup = 0;
    for (let i = start; i < end; i += 1) positivesInGroup += ordered[i].label === 1 ? 1 : 0;
    seen += end - start;
    truePositives += positivesInGroup;
    if (positivesInGroup) sumPrecision += (truePositives / seen) * positivesInGroup;
    start = end;
  }
  return sumPrecision / positives;
}

function createRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function bootstrapIntervals(scores, labels, iterations = 2000, seed = 20261126) {
  const classIndices = [[], []];
  labels.forEach((label, index) => classIndices[label].push(index));
  const random = createRandom(seed);
  const rocValues = [];
  const apValues = [];

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const sampleScores = [];
    const sampleLabels = [];
    for (const label of [0, 1]) {
      const source = classIndices[label];
      for (let draw = 0; draw < source.length; draw += 1) {
        const index = source[Math.floor(random() * source.length)];
        sampleScores.push(scores[index]);
        sampleLabels.push(label);
      }
    }
    rocValues.push(auc(sampleScores, sampleLabels));
    apValues.push(averagePrecision(sampleScores, sampleLabels));
  }

  const interval = (values) => {
    values.sort((a, b) => a - b);
    return { low: values[Math.floor(iterations * 0.025)], high: values[Math.ceil(iterations * 0.975) - 1] };
  };
  return { roc: interval(rocValues), averagePrecision: interval(apValues), iterations, seed };
}

function bestAtFpr(scores, labels, cap) {
  const candidates = [...new Set([...scores, 1.000000000001])].sort((a, b) => a - b);
  let selected = null;
  for (const threshold of candidates) {
    const metrics = confusion(scores, labels, threshold);
    if (metrics.fpr <= cap && (!selected || metrics.tpr > selected.tpr ||
      (metrics.tpr === selected.tpr && threshold < selected.threshold))) {
      selected = { threshold, ...metrics };
    }
  }
  return selected;
}

const pct = (value) => `${(value * 100).toFixed(1)}%`;
const n4 = (value) => value === null ? "n/a" : value.toFixed(4);

function evaluate(inputPath, modelPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const rows = parseCsv(raw);
  if (!rows.length) throw new Error("The input CSV has no data rows.");
  const required = ["url", "label", "domain", "fetch_ok"];
  const missing = required.filter((key) => !(key in rows[0]));
  if (missing.length) throw new Error(`Missing required CSV columns: ${missing.join(", ")}`);

  const skipped = { unfetched: 0, malformed: 0 };
  const seenDomains = new Set();
  const examples = [];
  for (const [index, row] of rows.entries()) {
    if (row.fetch_ok !== "1") { skipped.unfetched += 1; continue; }
    let label;
    try { label = normalizeLabel(row.label); }
    catch { skipped.malformed += 1; continue; }
    if (!row.url || !row.domain) { skipped.malformed += 1; continue; }
    const domain = row.domain.trim().toLowerCase();
    if (seenDomains.has(domain)) {
      throw new Error(`Duplicate domain "${domain}" at CSV data row ${index + 2}. Use one row per registrable domain to avoid leakage.`);
    }
    seenDomains.add(domain);
    examples.push({ url: row.url, domain, label, date: row.date || "" });
  }

  const labels = examples.map((row) => row.label);
  const positives = labels.filter((label) => label === 1).length;
  const negatives = labels.length - positives;
  if (positives === 0 || negatives === 0) {
    throw new Error(`Need both classes after filtering; got ${positives} phishing and ${negatives} benign rows.`);
  }

  const model = JSON.parse(fs.readFileSync(modelPath, "utf8"));
  const mlScores = [];
  const ruleScores = [];
  for (const row of examples) {
    const predicted = scoreWithModel(row.url, model).probability;
    const heuristic = rules.scoreUrl(row.url);
    if (!Number.isFinite(predicted) || !heuristic.valid) {
      throw new Error(`Could not score URL for domain ${row.domain}.`);
    }
    mlScores.push(predicted);
    ruleScores.push(heuristic.score / 100);
  }

  const modelAtHalf = confusion(mlScores, labels, 0.5);
  const rulesAtHalf = confusion(ruleScores, labels, 0.5);
  return {
    examples, labels, positives, negatives, skipped, model, mlScores, ruleScores,
    modelAtHalf, rulesAtHalf,
    modelRoc: auc(mlScores, labels),
    rulesRoc: auc(ruleScores, labels),
    modelAp: averagePrecision(mlScores, labels),
    rulesAp: averagePrecision(ruleScores, labels),
    modelBootstrap: bootstrapIntervals(mlScores, labels),
    rulesBootstrap: bootstrapIntervals(ruleScores, labels),
    modelOperating: [0.001, 0.01, 0.05].map((cap) => ({ cap, ...bestAtFpr(mlScores, labels, cap) })),
    ruleOperating: [0.001, 0.01, 0.05].map((cap) => ({ cap, ...bestAtFpr(ruleScores, labels, cap) }))
  };
}

function report(result, inputPath, modelPath) {
  const dates = [...new Set(result.examples.map((row) => row.date).filter(Boolean))];
  const modelRows = result.modelOperating.map((row) =>
    `| ${pct(row.cap)} | ${row.threshold.toFixed(4)} | ${pct(row.fpr)} | ${pct(row.tpr)} | ${pct(row.precision)} |`
  ).join("\n");
  const ruleRows = result.ruleOperating.map((row) =>
    `| ${pct(row.cap)} | ${row.threshold.toFixed(4)} | ${pct(row.fpr)} | ${pct(row.tpr)} | ${pct(row.precision)} |`
  ).join("\n");
  const model = result.modelAtHalf;
  const baseline = result.rulesAtHalf;
  const modelCi = result.modelBootstrap;
  const rulesCi = result.rulesBootstrap;
  return `# Shipped URL detector: offline evaluation\n\n` +
    `> **Exploratory only.** This report scores the checked-in model against the supplied labeled URLs. It is not an untouched test result, does not establish real-world accuracy, and must not be used to claim a production false-positive rate. The current DOM dataset covers only ${dates.length} crawl day(s).\n\n` +
    `Generated from \`${path.relative(ROOT, inputPath).replaceAll("\\", "/")}\` with \`${path.relative(ROOT, modelPath).replaceAll("\\", "/")}\`. No URL was fetched or opened.\n\n` +
    `## Data used\n\n` +
    `- Rows scored: **${result.examples.length}** (${result.positives} phishing, ${result.negatives} benign)\n` +
    `- Crawl dates represented: ${dates.length ? dates.join(", ") : "not recorded"}\n` +
    `- Unfetched rows skipped: ${result.skipped.unfetched}; malformed rows skipped: ${result.skipped.malformed}\n` +
    `- Domain policy: input must contain no duplicate registrable domains; duplicate rows stop the run to prevent domain leakage.\n` +
    `- Model features: ${result.model.feature_names.join(", ")}\n` +
    `- Observed benign sample resolution: one false positive changes FPR by ${(100 / result.negatives).toFixed(3)} percentage points.\n\n` +
    `## Ranking metrics\n\n` +
    `| Scorer | ROC-AUC (95% bootstrap CI) | Average precision (95% bootstrap CI) |\n|---|---:|---:|\n` +
    `| Shipped logistic model | ${n4(result.modelRoc)} (${n4(modelCi.roc.low)}–${n4(modelCi.roc.high)}) | ${n4(result.modelAp)} (${n4(modelCi.averagePrecision.low)}–${n4(modelCi.averagePrecision.high)}) |\n` +
    `| URL heuristics | ${n4(result.rulesRoc)} (${n4(rulesCi.roc.low)}–${n4(rulesCi.roc.high)}) | ${n4(result.rulesAp)} (${n4(rulesCi.averagePrecision.low)}–${n4(rulesCi.averagePrecision.high)}) |\n\n` +
    `Average precision uses the observed sample prevalence (${pct(result.positives / result.examples.length)}); it will change with class balance.\n\n` +
    `Intervals are reproducible, stratified percentile bootstrap intervals (${modelCi.iterations} resamples; seed ${modelCi.seed}). They quantify sampling variation within this collected set only and do not account for temporal or source bias.\n\n` +
    `## Fixed threshold (0.50)\n\n` +
    `| Scorer | TP | FP | TN | FN | Recall | FPR | Precision |\n|---|---:|---:|---:|---:|---:|---:|---:|\n` +
    `| Shipped logistic model | ${model.tp} | ${model.fp} | ${model.tn} | ${model.fn} | ${pct(model.tpr)} | ${pct(model.fpr)} | ${pct(model.precision)} |\n` +
    `| URL heuristics | ${baseline.tp} | ${baseline.fp} | ${baseline.tn} | ${baseline.fn} | ${pct(baseline.tpr)} | ${pct(baseline.fpr)} | ${pct(baseline.precision)} |\n\n` +
    `## Empirical model operating points\n\n` +
    `Each row uses the lowest observed score threshold that meets the requested FPR cap, maximizing recall on this same dataset. These are descriptive points, not validated deployment thresholds.\n\n` +
    `| Requested FPR cap | Threshold | Observed FPR | Recall | Precision |\n|---:|---:|---:|---:|---:|\n${modelRows}\n\n` +
    `### Heuristic comparison\n\n| Requested FPR cap | Threshold | Observed FPR | Recall | Precision |\n|---:|---:|---:|---:|---:|\n${ruleRows}\n\n` +
    `## Interpretation and limits\n\n` +
    `- This dataset is small, collected on very few days, and was not reserved as an untouched final test set. Same-dataset threshold selection is optimistic.\n` +
    `- The one-day crawl cannot measure temporal generalization; the benign/phishing mix is not a natural browsing prevalence. Precision here is therefore not a user-facing precision estimate.\n` +
    `- The URL model's original training data and training pipeline are not present in this checkout, so this evaluates the shipped artifact but cannot reproduce its training.\n` +
    `- Collect multiple days, keep domains disjoint between development and final test sets, freeze the threshold before the final run, and report confidence intervals before making accuracy claims.\n`;
}

function main() {
  const options = argumentsFrom(process.argv.slice(2));
  if (options.help) { console.log(usage()); return; }
  const modelPath = path.join(ROOT, "ml", "model.json");
  const result = evaluate(options.input, modelPath);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, report(result, options.input, modelPath), "utf8");
  console.log(`Wrote exploratory evaluation for ${result.examples.length} domains to ${options.output}`);
  console.log("This is not an untouched test result; see the limitations in the report.");
}

try { main(); }
catch (error) {
  console.error(`Evaluation failed: ${error.message}`);
  process.exitCode = 1;
}
