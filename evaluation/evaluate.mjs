
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { DomainBloomFilter } from "../extension/src/bloom-filter.js";
import {
  evaluateHybrid,
  FUSION_WEIGHTS,
} from "../extension/src/hybrid.js";
import { predictUrlMl } from "../extension/src/ml/inference.js";
import { evaluateRules } from "../extension/src/rules.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

const csvPath = path.join(root, "data/dom/dom_labeled.csv");
const modelPath = path.join(root, "extension/src/ml/model.json");
const bloomPath = path.join(
  root,
  "extension/data/tranco-top50k-bloom.json"
);

// Read CSV safely, including quoted fields.
function parseCSV(content) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    if (char === '"') {
      if (quoted && content[i + 1] === '"') {
        value += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (char === "," && !quoted) {
      row.push(value);
      value = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && content[i + 1] === "\n") i++;
      row.push(value);
      if (row.some((cell) => cell !== "")) rows.push(row);
      row = [];
      value = "";
    } else {
      value += char;
    }
  }

  row.push(value);
  if (row.some((cell) => cell !== "")) rows.push(row);

  const headers = rows.shift().map((header) => header.replace(/^\uFEFF/, ""));

  return rows.map((cells) =>
    Object.fromEntries(
      headers.map((header, i) => [header, cells[i] ?? ""])
    )
  );
}

function number(value) {
  const result = Number(value);
  return Number.isFinite(result) ? result : 0;
}

function getDomFeatures(row) {
  return {
    dom_external_resource_ratio: number(row.dom_ext_resource_ratio),
    dom_foreign_favicon: number(row.dom_favicon_foreign),
    dom_void_links_ratio: number(row.dom_null_link_ratio),
    dom_meta_refresh: number(row.dom_meta_refresh),

    dom_eval_atob_hits: Number(
      number(row.dom_script_eval) > 0 ||
      number(row.dom_script_atob) > 0
    ),

    dom_brand_domain_mismatch: number(row.dom_brand_domain_mismatch),

    // Closest available CSV equivalent to the live extension check.
    dom_password_external_form: Number(
      number(row.dom_n_password_forms_cross_origin) > 0
    ),
  };
}

function getHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

function getTrustedBloomHit(rawUrl) {
  const hostname = getHostname(rawUrl);
  return Boolean(hostname && bloom.has(hostname));
}

// Calculate confusion matrix for scenarios with a defined verdict.
function confusion(rows, positiveCheck) {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const item of rows) {
    const actual = item.label === 1;
    const predicted = positiveCheck(item);

    if (actual && predicted) tp++;
    else if (!actual && !predicted) tn++;
    else if (!actual && predicted) fp++;
    else fn++;
  }

  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall
    ? (2 * precision * recall) / (precision + recall)
    : 0;

  return {
    TP: tp,
    TN: tn,
    FP: fp,
    FN: fn,
    accuracy: rows.length ? (tp + tn) / rows.length : 0,
    precision,
    recall,
    f1,
    falsePositiveRate: fp + tn ? fp / (fp + tn) : 0,
  };
}

// Calculate ROC-AUC from continuous scores.
// Higher scores must indicate greater phishing risk.
function calculateAUC(rows) {
  const sorted = [...rows].sort(
    (a, b) => a.riskScore - b.riskScore
  );

  const positives = rows.filter((r) => r.label === 1).length;
  const negatives = rows.length - positives;

  if (!positives || !negatives) return null;

  let rankSum = 0;
  let i = 0;

  while (i < sorted.length) {
    let j = i;

    while (
      j + 1 < sorted.length &&
      sorted[j + 1].riskScore === sorted[i].riskScore
    ) {
      j++;
    }

    const averageRank = ((i + 1) + (j + 1)) / 2;

    for (let k = i; k <= j; k++) {
      if (sorted[k].label === 1) rankSum += averageRank;
    }

    i = j + 1;
  }

  return (
    rankSum - (positives * (positives + 1)) / 2
  ) / (positives * negatives);
}

const model = JSON.parse(fs.readFileSync(modelPath, "utf8"));
const bloomJson = JSON.parse(fs.readFileSync(bloomPath, "utf8"));
const bloom = DomainBloomFilter.fromJSON(bloomJson);

const allRows = parseCSV(fs.readFileSync(csvPath, "utf8"));

const rows = allRows.filter(
  (row) =>
    row.fetch_ok === "1" &&
    ["0", "1"].includes(row.label) &&
    row.url
);

if (!rows.length) {
  throw new Error("No valid dataset rows were found.");
}

// Create a consistent result format for every experiment.
function makeResult(row, scenario, riskScore, verdict = null) {
  return {
    url: row.url,
    label: Number(row.label),
    scenario,
    verdict,
    riskScore: number(riskScore),
  };
}

// 1. ML-only evaluation.
function evaluateMlOnly() {
  return rows.map((row) => {
    const result = predictUrlMl(row.url, model);

    return makeResult(row, "ML_ONLY", result.mlProb);
  });
}

// 2. URL heuristic rules-only evaluation.
function evaluateRulesOnly() {
  return rows.map((row) => {
    const trustedBloomHit = getTrustedBloomHit(row.url);
    const result = evaluateRules(row.url, trustedBloomHit);

    return makeResult(row, "URL_RULES_ONLY", result.ruleScore);
  });
}

// 3. DOM-only evaluation.
function evaluateDomOnly() {
  return rows.map((row) => {
    const domFeatures = getDomFeatures(row);

    const domScore = Object.entries(domFeatures).reduce(
      (total, [key, value]) =>
        total + (FUSION_WEIGHTS[key] ?? 0) * value,
      0
    );

    return makeResult(row, "DOM_ONLY", domScore);
  });
}

// Evaluate the actual hybrid engine with optional DOM signals
// and optional removal of one or more DOM features.
function evaluateHybridRows(
  scenarioName,
  featureToRemove = null,
  includeDom = true
) {
  return rows.map((row) => {
    const domFeatures = includeDom ? getDomFeatures(row) : {};

    if (featureToRemove) {
      const featuresToRemove = Array.isArray(featureToRemove)
        ? featureToRemove
        : [featureToRemove];

      for (const feature of featuresToRemove) {
        domFeatures[feature] = 0;
      }
    }

    const result = evaluateHybrid(row.url, {
      bloomFilter: bloom,
      model,
      domFeatures,
    });

    return {
      ...makeResult(
        row,
        scenarioName,
        result.riskScore,
        result.verdict
      ),
      mlProb: result.mlProb,
      trustedBloomHit: result.trustedBloomHit,
    };
  });
}

function summarize(name, results) {
  const hasVerdicts = results.every(
    (result) => result.verdict !== null
  );

  return {
    scenario: name,
    rows: results.length,
    auc: calculateAUC(results),

    phishingVerdict: hasVerdicts
      ? confusion(results, (r) => r.verdict === "PHISHING")
      : null,

    anyAlert: hasVerdicts
      ? confusion(results, (r) => r.verdict !== "SAFE")
      : null,
  };
}

// Run all experiments.
const scenarios = [
  {
    name: "ML_ONLY",
    results: evaluateMlOnly(),
  },
  {
    name: "URL_RULES_ONLY",
    results: evaluateRulesOnly(),
  },
  {
    name: "DOM_ONLY",
    results: evaluateDomOnly(),
  },
  {
    // Actual hybrid engine without DOM signals.
    name: "URL_ONLY",
    results: evaluateHybridRows("URL_ONLY", null, false),
  },
  {
    name: "FULL_FUSION",
    results: evaluateHybridRows("FULL_FUSION"),
  },
  {
    // Hybrid engine with two DOM features removed.
    name: "REDUCED_DOM_FUSION",
    results: evaluateHybridRows("REDUCED_DOM_FUSION", [
      "dom_external_resource_ratio",
      "dom_foreign_favicon",
    ]),
  },
];

// Remove one DOM feature at a time.
const domKeys = [
  "dom_external_resource_ratio",
  "dom_foreign_favicon",
  "dom_void_links_ratio",
  "dom_meta_refresh",
  "dom_eval_atob_hits",
  "dom_brand_domain_mismatch",
  "dom_password_external_form",
];

for (const key of domKeys) {
  scenarios.push({
    name: `WITHOUT_${key}`,
    results: evaluateHybridRows(`WITHOUT_${key}`, key),
  });
}

const summaries = scenarios.map((scenario) =>
  summarize(scenario.name, scenario.results)
);

// Save detailed row-level results.
const detailRows = scenarios.flatMap(
  (scenario) => scenario.results
);

const csvHeaders = [
  "url",
  "label",
  "scenario",
  "verdict",
  "riskScore",
  "mlProb",
  "trustedBloomHit",
];

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

const detailCSV = [
  csvHeaders.join(","),
  ...detailRows.map((row) =>
    csvHeaders.map((key) => csvCell(row[key])).join(",")
  ),
].join("\n");

fs.writeFileSync(
  path.join(__dirname, "results.csv"),
  detailCSV,
  "utf8"
);

fs.writeFileSync(
  path.join(__dirname, "summary.json"),
  JSON.stringify(
    {
      dataset: {
        totalRows: allRows.length,
        evaluatedRows: rows.length,
        phishing: rows.filter((r) => r.label === "1").length,
        benign: rows.filter((r) => r.label === "0").length,
      },

      notes: [
        "Preliminary offline evaluation.",
        "Standalone ML, URL rules and DOM layers are compared using ROC-AUC.",
        "Standalone layers do not have independently defined verdict thresholds.",
        "URL_ONLY is the actual hybrid engine without DOM signals.",
        "REDUCED_DOM_FUSION removes external resource ratio and foreign favicon.",
        "CSV DOM features may differ from live extension DOM extraction.",
        "DOM-only score uses the existing fusion DOM coefficients without the fusion bias.",
        "URL rules-only uses the existing ruleScore and Bloom trust check.",
      ],

      summaries,
    },
    null,
    2
  ),
  "utf8"
);

// Print results.
console.log("\n===== PHISHGUARD EVALUATION =====");
console.log(`Evaluated rows: ${rows.length}`);
console.log(`Phishing: ${rows.filter((r) => r.label === "1").length}`);
console.log(`Benign: ${rows.filter((r) => r.label === "0").length}`);

for (const item of summaries) {
  console.log(`\n--- ${item.scenario} ---`);
  console.log(`AUC: ${item.auc?.toFixed(4) ?? "N/A"}`);

  if (item.phishingVerdict) {
    console.log("Phishing verdict:", item.phishingVerdict);
    console.log("Any alert:", item.anyAlert);
  } else {
    console.log("Standalone layer: AUC comparison only.");
  }
}

console.log("\nFiles created:");
console.log("evaluation/results.csv");
console.log("evaluation/summary.json");
