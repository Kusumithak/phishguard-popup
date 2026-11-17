
/*
 * PhishGuard Hybrid Analysis
 * Combines local ML, URL heuristics, and DOM analysis.
 *
 * Privacy:
 * - No external API calls.
 * - No page content is uploaded.
 * - Uses normalized scores and structural findings.
 */

(function (root) {
  "use strict";

  const SAFE_THRESHOLD = 35;
  const SUSPICIOUS_THRESHOLD = 50;
  const PHISHING_THRESHOLD = 50;

  function clampScore(value) {
    const numeric = Number(value);

    return Number.isFinite(numeric)
      ? Math.max(0, Math.min(100, numeric))
      : 0;
  }

  function decisionFor(score) {
    const value = clampScore(score);

    if (value >= PHISHING_THRESHOLD) {
      return "PHISHING";
    }

    if (value >= SAFE_THRESHOLD && value < SUSPICIOUS_THRESHOLD) {
      return "SUSPICIOUS";
    }

    return "SAFE";
  }

  function riskLevel(score) {
    return decisionFor(score);
  }

  function normalizeFindings(findings) {
    if (!Array.isArray(findings)) {
      return [];
    }

    return findings
      .map((finding) => {
        if (typeof finding === "string") {
          return finding;
        }

        return finding?.id;
      })
      .filter(
        (finding) =>
          typeof finding === "string" && finding.length > 0
      );
  }

  function normalizeStats(stats) {
    if (!stats || typeof stats !== "object") {
      return {};
    }

    const normalized = {};

    for (const [key, value] of Object.entries(stats)) {
      if (
        typeof value === "number" &&
        Number.isFinite(value) &&
        value >= 0
      ) {
        normalized[key] = value;
      }
    }

    return normalized;
  }

  /*
   * Combines the three detection layers.
   *
   * ML available:
   * 30% ML + 30% URL heuristics + 40% DOM
   *
   * ML unavailable:
   * 50% URL heuristics + 50% DOM
   */
 function fuse({
  mlScore,
  mlAvailable,
  urlHeurScore,
  domScore,
  extremeConfidence,
  hardExtreme,
  softExtreme,
  findings = []
}) {
  const normalizedML = clampScore(mlScore);
  const normalizedHeuristics = clampScore(urlHeurScore);
  const normalizedDOM = clampScore(domScore);

  const appliedRules = [];
  let fused;

  if (mlAvailable) {
    fused = (
      0.30 * normalizedML +
      0.30 * normalizedHeuristics +
      0.40 * normalizedDOM
    );

    appliedRules.push("weighted_fusion_ml_30_url_30_dom_40");
  } else {
    fused = (
      0.50 * normalizedHeuristics +
      0.50 * normalizedDOM
    );

    appliedRules.push("weighted_fusion_url_50_dom_50");
  }

  fused = clampScore(Math.round(fused));

  const hasHardExtreme = Boolean(hardExtreme);

  const hasSoftExtreme = Boolean(
    softExtreme || (extremeConfidence && !hasHardExtreme)
  );

  if (
    hasHardExtreme ||
    (hasSoftExtreme && normalizedHeuristics >= 40)
  ) {
    fused = Math.max(fused, 80);
    appliedRules.push("extreme_confidence_url_block");

    return {
      fused,
      decision: "PHISHING",
      appliedRules
    };
  }

  const findingIds = new Set(normalizeFindings(findings));

  const strongDomFinding = [
    "hidden_password_field",
    "password_form_cross_origin",
    "password_form_http"
  ].some((id) => findingIds.has(id));

  if (normalizedDOM >= 70 || strongDomFinding) {
    fused = Math.max(fused, 60);

    appliedRules.push(
      normalizedDOM >= 70
        ? "strong_dom_score_floor_60"
        : "strong_dom_finding_floor_60"
    );
  }

  // Additional risk floor for multiple independent URL indicators.
  const urlFindingCount = normalizeFindings(
    findings
  ).length;

  if (normalizedHeuristics >= 20 && urlFindingCount >= 2) {
    fused = Math.max(fused, 35);
    appliedRules.push("multiple_url_indicators_risk_floor_35");
  }

  fused = clampScore(fused);

  return {
    fused,
    decision: decisionFor(fused),
    appliedRules
  };
}

  /*
   * URL-stage analysis.
   * This stage does not perform DOM analysis.
   */
  
async function analyseUrl(rawUrl) {

  // Wait until ML prediction is completed
  const ml = await root.PhishGuardML.predict(rawUrl);

  const heuristic = root.PhishGuardRules.scoreUrl(rawUrl);

  const mlAvailable = Boolean(ml?.available);

  // ML predict() returns probability between 0 and 1.
  const probability = Number(ml?.probability);

  const mlScore = (
    mlAvailable && Number.isFinite(probability)
  )
    ? clampScore(probability * 100)
    : null;

  return {
    url: heuristic.valid ? heuristic.url : String(rawUrl),
    valid: heuristic.valid,
    hostname: heuristic.hostname || "",
    mlScore,
    mlAvailable,
    urlHeurScore: clampScore(heuristic.score),
    hardExtreme: Boolean(heuristic.hardExtreme),
    softExtreme: Boolean(heuristic.softExtreme),
    extremeConfidence: Boolean(heuristic.extremeConfidence),
    urlFindings: heuristic.findings || [],
    featureSummary: heuristic.featureSummary || null,
    error: ml?.error || heuristic.error || null
  };
}

   

  /*
   * Combine URL-stage output with the completed DOM scan.
   */
  function combineWithDom(
    urlResult,
    domResult,
    previousDecision
  ) {
    const normalizedDOM = clampScore(
      domResult?.domScore ?? domResult?.score
    );

    const domFindings = normalizeFindings(
      domResult?.findings
    );

    const urlFindings = normalizeFindings(
      urlResult?.urlFindings
    );

    const fusedResult = fuse({
      mlScore: urlResult?.mlScore,
      mlAvailable: Boolean(urlResult?.mlAvailable),
      urlHeurScore: urlResult?.urlHeurScore,
      domScore: normalizedDOM,
      hardExtreme: urlResult?.hardExtreme,
      softExtreme: urlResult?.softExtreme,
      extremeConfidence: urlResult?.extremeConfidence,
      findings: domFindings
    });

    // Never lower an earlier decision during the same navigation.
    const rank = {
      SAFE: 0,
      SUSPICIOUS: 1,
      PHISHING: 2
    };

    if (
      Object.prototype.hasOwnProperty.call(rank, previousDecision) &&
      rank[previousDecision] > rank[fusedResult.decision]
    ) {
      fusedResult.decision = previousDecision;

      fusedResult.appliedRules.push(
        "navigation_decision_no_downgrade"
      );
    }

    return {
      ...fusedResult,
      domScore: normalizedDOM,

      // Preserve the statistics added by the updated content.js.
      stats: normalizeStats(domResult?.stats),

      // Keep both URL and DOM evidence in the final report.
      findings: [...new Set([...urlFindings, ...domFindings])]
    };
  }

  /*
   * URL-stage preview before DOM analysis is complete.
   */
  function fuseUrlStage({
    mlScore,
    mlAvailable,
    urlHeurScore
  }) {
    const normalizedML = clampScore(mlScore);
    const normalizedHeuristics = clampScore(urlHeurScore);

    const fused = clampScore(
      Math.round(
        mlAvailable
          ? 0.30 * normalizedML + 0.30 * normalizedHeuristics
          : normalizedHeuristics
      )
    );

    return {
      fused,
      decision: decisionFor(fused),

      appliedRules: [
        mlAvailable
          ? "url_stage_preview_ml_30_url_30_dom_0"
          : "url_stage_preview_url_100"
      ]
    };
  }

  /*
   * Compatibility wrapper for callers that still use URL-only analysis.
   */
  async function analyse(rawUrl) {
     const result = await analyseUrl(rawUrl);

    const fused = fuse({
      ...result,
      domScore: 0,
      findings: []
    });

    return {
      ...result,
      ...fused,
      score: fused.fused,
      level: fused.decision,

      ml: {
        available: result.mlAvailable,
        score: result.mlScore
      },

      heuristic: {
        score: result.urlHeurScore,
        findings: result.urlFindings
      }
    };
  }

  root.PhishGuardHybrid = {
    SAFE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    PHISHING_THRESHOLD,
    clampScore,
    decisionFor,
    riskLevel,
    fuse,
    fuseUrlStage,
    analyseUrl,
    combineWithDom,
    analyse
  };
})(globalThis);
