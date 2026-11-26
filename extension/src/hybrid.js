/**
 * Stacked hybrid fusion engine combining:
 *   1. Local user allowlist + Tranco Top-50k Bloom filter trusted-domain check
 *   2. URL ML probability (ml/inference.js)
 *   3. Heuristic rule flags (rules.js)
 *   4. DOM signals (from Role 3's content.js)
 *
 * Outputs verdict ("SAFE" | "SUSPICIOUS" | "PHISHING"), calibrated risk score,
 * and sorted `whyFlagged` explanations (`coefficient * value`).
 */

import { evaluateRules } from "./rules.js";
import { predictUrlMl, sigmoid } from "./ml/inference.js";

// Calibrated fusion coefficients (learned stacked logistic regression weights + bias)
export const FUSION_WEIGHTS = {
  bias: -2.85,
  ml_prob: 3.10,
  trusted_bloom_hit: -2.40,
  dom_external_resource_ratio: 1.05,
  dom_foreign_favicon: 1.15,
  dom_void_links_ratio: 0.90,
  dom_meta_refresh: 1.10,
  dom_eval_atob_hits: 1.35,
  dom_brand_domain_mismatch: 1.95,
  dom_password_external_form: 2.10,
};

export const THRESHOLDS = {
  suspicious: 0.38,
  phishing: 0.72,
};

/**
 * @param {string} rawUrl
 * @param {{
 *   bloomFilter?: { has: (hostname: string) => boolean } | null,
 *   allowlistSet?: Set<string> | null,
 *   domFeatures?: Record<string, number>,
 *   model?: any
 * }} [options]
 */
export function evaluateHybrid(
  rawUrl,
  {
    bloomFilter = null,
    allowlistSet = null,
    domFeatures = {},
    model = undefined,
  } = {}
) {
  const startMs =
    typeof performance !== "undefined" ? performance.now() : Date.now();

  let hostname = "";
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    hostname = "";
  }

  // Allowlist bypass (Role 4 "Mark as safe" feature)
  if (allowlistSet && hostname && allowlistSet.has(hostname)) {
    const endMs =
      typeof performance !== "undefined" ? performance.now() : Date.now();
    return {
      url: rawUrl,
      hostname,
      verdict: "SAFE",
      riskScore: 0.01,
      mlProb: 0,
      trustedBloomHit: Boolean(bloomFilter?.has(hostname)),
      allowlisted: true,
      whyFlagged: [
        {
          feature: "user_allowlist",
          layer: "Allowlist",
          coefficient: -10,
          value: 1,
          impact: -10,
        },
      ],
      activeFlags: [],
      latencyMs: Number(Math.max(0.1, endMs - startMs).toFixed(2)),
    };
  }

  const trustedBloomHit = Boolean(bloomFilter && hostname && bloomFilter.has(hostname));
  const mlRes = predictUrlMl(rawUrl, model);
  const ruleRes = evaluateRules(rawUrl, trustedBloomHit);

  let logit = FUSION_WEIGHTS.bias;
  const contributions = [];

  // ML contribution
  const mlImpact = FUSION_WEIGHTS.ml_prob * mlRes.mlProb;
  logit += mlImpact;
  contributions.push({
    feature: "ml_prob",
    layer: "Fusion",
    coefficient: FUSION_WEIGHTS.ml_prob,
    value: mlRes.mlProb,
    impact: Number(mlImpact.toFixed(4)),
  });

  // Trusted Bloom filter contribution
  if (trustedBloomHit) {
    const bloomImpact = FUSION_WEIGHTS.trusted_bloom_hit * 1;
    logit += bloomImpact;
    contributions.push({
      feature: "tranco_50k_bloom_trusted",
      layer: "Bloom",
      coefficient: FUSION_WEIGHTS.trusted_bloom_hit,
      value: 1,
      impact: Number(bloomImpact.toFixed(4)),
    });
  }

  // Rule flag contributions
  for (const rc of ruleRes.contributions) {
    logit += rc.impact;
    contributions.push(rc);
  }

  // DOM signal contributions (Role 3)
  const domSignalKeys = [
    "dom_external_resource_ratio",
    "dom_foreign_favicon",
    "dom_void_links_ratio",
    "dom_meta_refresh",
    "dom_eval_atob_hits",
    "dom_brand_domain_mismatch",
    "dom_password_external_form",
  ];
  for (const key of domSignalKeys) {
    const val = Number(domFeatures?.[key] ?? 0);
    if (val > 0) {
      const coef = FUSION_WEIGHTS[key] ?? 0;
      const impact = coef * val;
      logit += impact;
      contributions.push({
        feature: key,
        layer: "DOM",
        coefficient: coef,
        value: Number(val.toFixed(4)),
        impact: Number(impact.toFixed(4)),
      });
    }
  }

  // Include top underlying ML URL feature drivers for granular "why flagged" inspection
  const detailedDrivers = [
    ...contributions,
    ...mlRes.contributions.map((c) => ({
      ...c,
      feature: `ml:${c.feature}`,
    })),
  ].sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));

  const riskScore = Number(sigmoid(logit).toFixed(4));
  let verdict = "SAFE";
  if (riskScore >= THRESHOLDS.phishing) {
    verdict = "PHISHING";
  } else if (riskScore >= THRESHOLDS.suspicious) {
    verdict = "SUSPICIOUS";
  }

  const endMs =
    typeof performance !== "undefined" ? performance.now() : Date.now();

  return {
    url: rawUrl,
    hostname,
    verdict,
    riskScore,
    mlProb: mlRes.mlProb,
    trustedBloomHit,
    allowlisted: false,
    whyFlagged: detailedDrivers.slice(0, 8),
    activeFlags: ruleRes.activeFlags,
    latencyMs: Number(Math.max(0.1, endMs - startMs).toFixed(2)),
  };
}
