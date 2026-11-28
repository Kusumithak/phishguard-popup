#!/usr/bin/env node
"use strict";

// Offline, deterministic evaluation of structural fingerprints. This tool only reads CSV
// strings and never opens, fetches, or prints phishing URLs/domains.
const fs = require("node:fs");
const path = require("node:path");
const { parseCsv, normalizeLabel } = require("./dom_csv.js");
const { hamming } = require("../content.js");

const ROOT = path.resolve(__dirname, "..");
const DEFAULT_INPUT = path.join(ROOT, "data", "dom", "dom_features_kitfp.csv");
const DEFAULT_OUTPUT = path.join(ROOT, "out", "kit", "RESULTS.md");
const RADII = [0, 4, 8, 12];
const KIT_THRESHOLDS = [0, 2, 4, 6, 8, 12];
const BOOTSTRAPS = 2000;
const SEED = 20261128;

function optionsFrom(argv) {
  const options = { input: DEFAULT_INPUT, output: DEFAULT_OUTPUT };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--help" || argv[i] === "-h") { options.help = true; continue; }
    if (!["--input", "--output"].includes(argv[i]) || !argv[i + 1]) throw new Error(`Unknown or incomplete argument: ${argv[i]}`);
    options[argv[i].slice(2)] = path.resolve(process.cwd(), argv[i + 1]);
    i += 1;
  }
  return options;
}

function usage() {
  return "Usage: node tools/eval_kit.js [--input data/dom/dom_features_kitfp.csv] [--output out/kit/RESULTS.md]";
}

function loadDataset(filename) {
  const rows = parseCsv(fs.readFileSync(filename, "utf8"));
  if (!rows.length) throw new Error("The input CSV has no data rows.");
  const required = ["label", "domain", "kit_fp", "dom_hand_score", "dom_brand_in_title", "dom_brand_domain_mismatch"];
  const missing = required.filter((key) => !(key in rows[0]));
  if (missing.length) throw new Error(`Input CSV missing required columns: ${missing.join(", ")}`);

  const dropped = { phishing: 0, benign: 0 };
  const seen = new Set();
  const pages = [];
  for (const [rowIndex, row] of rows.entries()) {
    let label;
    try { label = normalizeLabel(row.label); }
    catch { throw new Error(`Invalid label at data row ${rowIndex + 2}.`); }
    if (label !== 0 && label !== 1) throw new Error(`Invalid label at data row ${rowIndex + 2}.`);
    const fp = String(row.kit_fp || "").trim().toLowerCase();
    if (!fp) {
      dropped[label ? "phishing" : "benign"] += 1;
      continue;
    }
    if (!/^[0-9a-f]{16}$/.test(fp)) throw new Error(`Invalid nonempty kit_fp at data row ${rowIndex + 2}.`);
    const domain = String(row.domain || "").trim().toLowerCase();
    if (!domain) throw new Error(`Missing registrable domain at data row ${rowIndex + 2}.`);
    if (seen.has(domain)) throw new Error(`Input must be one row per registrable domain; duplicate at data row ${rowIndex + 2}.`);
    seen.add(domain);
    const domScore = Number(row.dom_hand_score);
    if (!Number.isFinite(domScore)) throw new Error(`Invalid dom_hand_score at data row ${rowIndex + 2}.`);
    const brandInTitle = Number(row.dom_brand_in_title);
    const brandDomainMismatch = Number(row.dom_brand_domain_mismatch);
    if (![0, 1].includes(brandInTitle) || ![0, 1].includes(brandDomainMismatch)) {
      throw new Error(`Invalid brand-title feature value at data row ${rowIndex + 2}.`);
    }
    pages.push({ fp, label, domain, domScore, brandInTitle, brandDomainMismatch });
  }
  const nPhish = pages.filter((page) => page.label === 1).length;
  const nBenign = pages.length - nPhish;
  if (!nPhish || !nBenign) throw new Error(`Need both classes after dropping empty fingerprints; got ${nPhish} phishing and ${nBenign} benign.`);
  return { pages, dropped, nPhish, nBenign, totalRows: rows.length };
}

function distanceMatrix(pages) {
  const distances = Array.from({ length: pages.length }, () => new Uint8Array(pages.length));
  for (let i = 0; i < pages.length; i += 1) {
    for (let j = i + 1; j < pages.length; j += 1) {
      const distance = hamming(pages[i].fp, pages[j].fp);
      distances[i][j] = distance;
      distances[j][i] = distance;
    }
  }
  return distances;
}

function clustersFor(pages, distances, radius, filterLabel = null) {
  const selected = pages.map((page, index) => ({ page, index }))
    .filter(({ page }) => filterLabel === null || page.label === filterLabel);
  const parent = selected.map((_, index) => index);
  const find = (value) => {
    let current = value;
    while (parent[current] !== current) { parent[current] = parent[parent[current]]; current = parent[current]; }
    return current;
  };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent[rb] = ra; };
  for (let i = 0; i < selected.length; i += 1) {
    for (let j = i + 1; j < selected.length; j += 1) {
      if (distances[selected[i].index][selected[j].index] <= radius) union(i, j);
    }
  }
  const grouped = new Map();
  for (let i = 0; i < selected.length; i += 1) {
    const root = find(i);
    if (!grouped.has(root)) grouped.set(root, []);
    grouped.get(root).push(selected[i].index);
  }
  return [...grouped.values()].map((indices) => indices.sort((a, b) => pages[a].fp.localeCompare(pages[b].fp)));
}

function clustersAll(pages, distances, radius) {
  return clustersFor(pages, distances, radius, null);
}

function wilson(successes, total) {
  if (!total) return { low: 0, high: 0 };
  const z = 1.959963984540054;
  const p = successes / total;
  const z2 = z * z;
  const denominator = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denominator;
  const half = z * Math.sqrt((p * (1 - p) / total) + (z2 / (4 * total * total))) / denominator;
  return { low: Math.max(0, center - half), high: Math.min(1, center + half) };
}

function fmtRate(successes, total) {
  const rate = total ? successes / total : 0;
  const ci = wilson(successes, total);
  return `${(100 * rate).toFixed(1)}% (${successes}/${total}; 95% Wilson ${(100 * ci.low).toFixed(1)}–${(100 * ci.high).toFixed(1)}%)`;
}

function rocAuc(scores, labels) {
  let positives = 0, negatives = 0;
  labels.forEach((label) => label === 1 ? positives += 1 : negatives += 1);
  if (!positives || !negatives) return null;
  const sorted = scores.map((score, i) => ({ score, label: labels[i] })).sort((a, b) => a.score - b.score);
  let rankSum = 0;
  for (let start = 0; start < sorted.length;) {
    let end = start + 1;
    while (end < sorted.length && sorted[end].score === sorted[start].score) end += 1;
    const averageRank = (start + 1 + end) / 2;
    for (let i = start; i < end; i += 1) if (sorted[i].label === 1) rankSum += averageRank;
    start = end;
  }
  return (rankSum - positives * (positives + 1) / 2) / (positives * negatives);
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function aucInterval(scores, labels, seed) {
  const classIndices = [[], []];
  labels.forEach((label, index) => classIndices[label].push(index));
  const random = seededRandom(seed);
  const values = [];
  for (let iteration = 0; iteration < BOOTSTRAPS; iteration += 1) {
    const sampleScores = [], sampleLabels = [];
    for (const label of [0, 1]) {
      const source = classIndices[label];
      for (let draw = 0; draw < source.length; draw += 1) {
        const index = source[Math.floor(random() * source.length)];
        sampleScores.push(scores[index]);
        sampleLabels.push(label);
      }
    }
    values.push(rocAuc(sampleScores, sampleLabels));
  }
  values.sort((a, b) => a - b);
  return { low: values[Math.floor(BOOTSTRAPS * 0.025)], high: values[Math.ceil(BOOTSTRAPS * 0.975) - 1] };
}

function confusion(scores, labels, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  scores.forEach((score, index) => {
    if (score >= threshold && labels[index] === 1) tp += 1;
    else if (score >= threshold) fp += 1;
    else if (labels[index] === 0) tn += 1;
    else fn += 1;
  });
  return { tp, fp, tn, fn, recall: tp + fn ? tp / (tp + fn) : 0, fpr: fp + tn ? fp / (fp + tn) : 0 };
}

function pointsAtResolvableFpr(scores, labels) {
  const nBenign = labels.filter((label) => label === 0).length;
  const maxScore = Math.max(...scores);
  const maxBenign = Math.max(...scores.filter((_, index) => labels[index] === 0));
  const candidates = [...new Set([...scores, maxScore + 1, maxBenign + 1e-6])].sort((a, b) => a - b);
  const caps = [...new Set([0, 1 / nBenign, 0.05, 0.10])].sort((a, b) => a - b);
  return caps.map((cap) => {
    let best = null;
    for (const threshold of candidates) {
      const result = confusion(scores, labels, threshold);
      if (result.fpr <= cap && (!best || result.tp > best.tp || (result.tp === best.tp && result.fp < best.fp))) {
        best = { threshold, ...result };
      }
    }
    return { cap, ...best };
  });
}

function zeroFpPoint(scores, labels) {
  const nBenign = labels.filter((label) => label === 0).length;
  const maxBenign = Math.max(...scores.filter((_, index) => labels[index] === 0));
  const threshold = maxBenign + 1e-6;
  const result = confusion(scores, labels, threshold);
  return { threshold, ...result, nBenign };
}

function makeScores(pages, distances, clusterIds = null) {
  const nearest = [];
  for (let i = 0; i < pages.length; i += 1) {
    let dPhish = 65, dBenign = 65;
    for (let j = 0; j < pages.length; j += 1) {
      if (i === j || (clusterIds && clusterIds[i] === clusterIds[j])) continue;
      if (pages[j].label === 1) dPhish = Math.min(dPhish, distances[i][j]);
      else dBenign = Math.min(dBenign, distances[i][j]);
    }
    nearest.push({ dPhish, dBenign, score: dBenign - dPhish });
  }
  return nearest;
}

function labelsOf(pages) { return pages.map((page) => page.label); }

function ruleConfusion(nearest, pages, threshold) {
  const labels = labelsOf(pages);
  return confusion(nearest.map(({ dPhish, dBenign }) => dPhish <= threshold && dPhish < dBenign ? 1 : 0), labels, 0.5);
}

function clusterStats(pages, distances, radius, label) {
  const clusters = clustersFor(pages, distances, radius, label);
  const distribution = new Map();
  let pagesInRepeatClusters = 0;
  for (const cluster of clusters) {
    distribution.set(cluster.length, (distribution.get(cluster.length) || 0) + 1);
    if (cluster.length >= 2) pagesInRepeatClusters += cluster.length;
  }
  const n = pages.filter((page) => page.label === label).length;
  const distText = [...distribution].sort(([a], [b]) => a - b).map(([size, count]) => `${size} page(s): ${count} cluster(s)`).join("; ") || "none";
  return { clusters, distribution: distText, pagesInRepeatClusters, n };
}

function formatAuc(scores, labels, seed) {
  const auc = rocAuc(scores, labels);
  const ci = aucInterval(scores, labels, seed);
  return `${auc.toFixed(3)} (95% stratified bootstrap ${ci.low.toFixed(3)}–${ci.high.toFixed(3)}; ${BOOTSTRAPS} resamples)`;
}

function evaluationSection(title, scores, pages, nearest, seed) {
  const labels = labelsOf(pages);
  const zero = zeroFpPoint(scores, labels);
  const points = pointsAtResolvableFpr(scores, labels);
  const lines = [
    `## ${title}`,
    "",
    `ROC-AUC: **${formatAuc(scores, labels, seed)}**.`,
    `At zero false positives, threshold **score ≥ ${zero.threshold.toFixed(6)}** gives recall ${fmtRate(zero.tp, labels.filter((label) => label === 1).length)} and FPR ${fmtRate(zero.fp, zero.nBenign)}.`,
    ...(title.includes("cluster-out") ? ["If removing the query cluster leaves no reference of one class, that class's nearest distance is set to 65 (one greater than the maximum Hamming distance of 64), so absence of a reference is not treated as a close match."] : []),
    "",
    "| FPR cap | Chosen score threshold | TP / FP | Recall (95% Wilson) | Observed FPR (95% Wilson) |",
    "|---:|---:|---:|---:|---:|"
  ];
  for (const point of points) {
    lines.push(`| ${(100 * point.cap).toFixed(2)}% | ${point.threshold.toFixed(6)} | ${point.tp} / ${point.fp} | ${fmtRate(point.tp, labels.filter((label) => label === 1).length)} | ${fmtRate(point.fp, labels.filter((label) => label === 0).length)} |`);
  }
  lines.push("", "| Rule T | True positives | False positives | Recall (95% Wilson) | FPR (95% Wilson) |", "|---:|---:|---:|---:|---:|");
  for (const t of KIT_THRESHOLDS) {
    const result = ruleConfusion(nearest, pages, t);
    lines.push(`| ${t} | ${result.tp} | ${result.fp} | ${fmtRate(result.tp, labels.filter((label) => label === 1).length)} | ${fmtRate(result.fp, labels.filter((label) => label === 0).length)} |`);
  }
  return { lines, zero, points };
}

function report(dataset) {
  const { pages, dropped, nPhish, nBenign, totalRows } = dataset;
  const distances = distanceMatrix(pages);
  const lines = [
    "# Phishing-kit fingerprint evaluation",
    "",
    "> Descriptive offline results. Pages were scored from the supplied fingerprint CSV; no site was opened or fetched.",
    "",
    "## Data and exclusions",
    "",
    `- Input rows: ${totalRows}; scored rows: ${pages.length}.`,
    `- Empty kit_fp rows dropped: ${dropped.phishing} phishing and ${dropped.benign} benign.`,
    `- Scored labels: **${nPhish} phishing and ${nBenign} benign**. Smallest resolvable FPR is **1/${nBenign} = ${(100 / nBenign).toFixed(2)}%**.`,
    "- The evaluator requires one row per registrable domain and rejects duplicate domains to preserve the leave-one-domain-out design.",
    "",
    "## Descriptive single-linkage clustering",
    "",
    "A cluster joins pages connected by a chain of pairwise distances at or below the stated radius.",
    "",
    "| Radius | Class | Clusters | Cluster-size distribution (size: cluster count) | Pages in clusters of size ≥2 (95% Wilson) |",
    "|---:|---|---:|---|---:|"
  ];

  const stats = new Map();
  for (const radius of RADII) {
    for (const [label, name] of [[1, "Phishing"], [0, "Benign"]]) {
      const item = clusterStats(pages, distances, radius, label);
      stats.set(`${radius}:${label}`, item);
      lines.push(`| ${radius} | ${name} | ${item.clusters.length} | ${item.distribution} | ${fmtRate(item.pagesInRepeatClusters, item.n)} |`);
    }
  }

  const mixed = clustersAll(pages, distances, 4).filter((indices) => {
    const labels = new Set(indices.map((index) => pages[index].label));
    return labels.size > 1;
  });
  lines.push("", "### Mixed-label radius-4 clusters", "");
  if (!mixed.length) {
    lines.push("No radius-4 cluster contains both labels.");
  } else {
    lines.push("These groups are false-positive review candidates. Only benign registrable domains are named; phishing domains and URLs are intentionally omitted.", "", "| Representative fingerprint | Total | Phishing count | Benign count | Benign registrable domains |", "|---|---:|---:|---:|---|");
    for (const indices of mixed.sort((a, b) => pages[a[0]].fp.localeCompare(pages[b[0]].fp))) {
      const group = indices.map((index) => pages[index]);
      const benignDomains = [...new Set(group.filter((page) => page.label === 0).map((page) => page.domain))].sort();
      lines.push(`| \`${group.map((page) => page.fp).sort()[0]}\` | ${group.length} | ${group.filter((page) => page.label === 1).length} | ${benignDomains.length} | ${benignDomains.map((domain) => `\`${domain}\``).join(", ")} |`);
    }
  }

  const test1 = makeScores(pages, distances);
  const labels = labelsOf(pages);
  const test1Result = evaluationSection("Test 1 — leave-one-domain-out nearest neighbour", test1.map((entry) => entry.score), pages, test1, SEED);

  const allClusters4 = clustersAll(pages, distances, 4);
  const clusterId = Array(pages.length).fill(0);
  const clusterSize = Array(pages.length).fill(0);
  allClusters4.forEach((indices, id) => indices.forEach((index) => { clusterId[index] = id; clusterSize[index] = indices.length; }));
  const test2 = makeScores(pages, distances, clusterId);
  const test2Result = evaluationSection("Test 2 — leave-one-radius-4-cluster-out", test2.map((entry) => entry.score), pages, test2, SEED + 1);

  const chosenTs = KIT_THRESHOLDS.filter((t) => ruleConfusion(test1, pages, t).fp === 0);
  const chosenT = chosenTs.length ? Math.max(...chosenTs) : null;
  lines.push("", ...test1Result.lines, "", ...test2Result.lines, "", "### Test 2 phishing results by kit novelty", "", "Novel means the page was a singleton in the full radius-4 clustering. Recall uses Test 2's global zero-FP score threshold.", "", "| Phishing subset | Pages | Detected | Recall (95% Wilson) |", "|---|---:|---:|---:|");
  for (const [name, condition] of [["Has a radius-4 sibling", (index) => clusterSize[index] >= 2], ["Singleton / novel kit", (index) => clusterSize[index] === 1]]) {
    const indices = pages.map((page, index) => ({ page, index })).filter(({ page, index }) => page.label === 1 && condition(index));
    const detected = indices.filter(({ index }) => test2[index].score >= test2Result.zero.threshold).length;
    lines.push(`| ${name} | ${indices.length} | ${detected} | ${fmtRate(detected, indices.length)} |`);
  }

  const domScores = pages.map((page) => page.domScore);
  const domZero = zeroFpPoint(domScores, labels);
  lines.push("", "## Hand-built DOM score baseline", "", `Existing \`dom_hand_score\` only: ROC-AUC **${formatAuc(domScores, labels, SEED + 2)}**; recall at zero false positives, threshold **score ≥ ${domZero.threshold.toFixed(6)}**, is ${fmtRate(domZero.tp, nPhish)}. FPR is ${fmtRate(domZero.fp, nBenign)}.`, "");

  lines.push("## Existing brand-title DOM features", "", "These are counts of pages whose stored feature flag equals 1; no new title or logo matching was added.", "", "| Feature | Phishing pages firing (95% Wilson) | Benign pages firing (95% Wilson) |", "|---|---:|---:|");
  for (const [key, name] of [["brandInTitle", "dom_brand_in_title"], ["brandDomainMismatch", "dom_brand_domain_mismatch"]]) {
    const phishingFires = pages.filter((page) => page.label === 1 && page[key] === 1).length;
    const benignFires = pages.filter((page) => page.label === 0 && page[key] === 1).length;
    lines.push(`| ${name} | ${fmtRate(phishingFires, nPhish)} | ${fmtRate(benignFires, nBenign)} |`);
  }

  const chosenResult = chosenT === null ? null : ruleConfusion(test1, pages, chosenT);
  lines.push("## Threshold selected for the optional extension matcher", "");
  if (chosenT === null) {
    lines.push("No tested T in {0, 2, 4, 6, 8, 12} produced zero benign false positives in Test 1. Do not enable a kit matcher threshold from this evaluation.");
  } else {
    lines.push(`Chosen **T = ${chosenT}** because it is the largest tested distance in {0, 2, 4, 6, 8, 12} with zero benign false positives in Test 1. At this T, Test 1 yields ${chosenResult.tp}/${nPhish} phishing matches (${fmtRate(chosenResult.tp, nPhish)}) and ${chosenResult.fp}/${nBenign} benign false positives (${fmtRate(chosenResult.fp, nBenign)}). T was not selected using Test 2, the DOM score, or any other metric.`);
  }

  lines.push(
    "",
    "## Limitations",
    "",
    "- This dataset covers one crawl day; clustering within one day can overstate how often kits are reused over time.",
    `- The scored set is small (${nPhish} phishing and ${nBenign} benign pages); Wilson intervals and bootstrap intervals are wide and should be shown with rates.` ,
    "- Benign WordPress and login-framework templates can resemble phishing pages and appear in mixed-label clusters.",
    "- Attackers can randomise the DOM, and phishing pages can cloak content from headless browsers.",
    "- Fingerprints were computed from saved pages re-rendered offline. The live-versus-saved parity check on the safe fixtures was not run in this environment because Playwright is unavailable.",
    "- Results are descriptive, not evidence of production performance. The dataset is small, and thresholds were selected on this same sample for descriptive operating points.",
    ""
  );
  return { markdown: lines.join("\n"), pages, distances, chosenT, test1, test2, stats };
}

function main() {
  const options = optionsFrom(process.argv.slice(2));
  if (options.help) { console.log(usage()); return; }
  const dataset = loadDataset(options.input);
  const result = report(dataset);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, result.markdown, "utf8");
  console.log(`Input rows: ${dataset.totalRows}`);
  console.log(`Dropped empty kit_fp: ${dataset.dropped.phishing} phishing, ${dataset.dropped.benign} benign`);
  console.log(`Scored rows: ${result.pages.length} (${dataset.nPhish} phishing, ${dataset.nBenign} benign)`);
  console.log(`Selected T: ${result.chosenT === null ? "none (no tested T has zero benign false positives)" : result.chosenT}`);
  console.log(`Wrote ${options.output}`);
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(`Kit evaluation failed: ${error.message}`); process.exitCode = 1; }
}

module.exports = { loadDataset, distanceMatrix, clustersFor, clustersAll, wilson, rocAuc, pointsAtResolvableFpr, zeroFpPoint, makeScores, ruleConfusion, report };
