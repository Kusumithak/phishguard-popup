/**
 * URL feature extraction and Logistic Regression inference (without has_https bias).
 * Returns calibrated probability `mlProb` and per-feature `coefficient * value` contributions.
 */

export const DEFAULT_URL_MODEL = {
  model_type: "logistic_regression_url_v2",
  bias: -2.15,
  features: {
    url_length_norm: 1.15,
    path_length_norm: 0.68,
    query_length_norm: 0.54,
    host_entropy_norm: 1.42,
    digit_ratio: 1.85,
    subdomain_count_norm: 1.10,
    hyphen_count_norm: 0.92,
    brand_word_hits: 1.38,
    special_char_ratio: 1.25,
  },
};

const BRAND_WORDS = [
  "paypal",
  "google",
  "microsoft",
  "apple",
  "amazon",
  "sbi",
  "hdfc",
  "icici",
  "netflix",
  "github",
  "login",
  "verify",
  "secure",
  "account",
  "update",
];

export function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let ent = 0;
  for (const c of counts.values()) {
    const p = c / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function extractUrlFeatures(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      url_length_norm: 0,
      path_length_norm: 0,
      query_length_norm: 0,
      host_entropy_norm: 0,
      digit_ratio: 0,
      subdomain_count_norm: 0,
      hyphen_count_norm: 0,
      brand_word_hits: 0,
      special_char_ratio: 0,
    };
  }

  const host = parsed.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();
  const noProto = full.replace(/^https?:\/\//, "");
  const digits = (noProto.match(/\d/g) || []).length;
  const hyphens = (host.match(/-/g) || []).length;
  const specials = (noProto.match(/[@!$&*=+?%_;]/g) || []).length;
  const subdomains = Math.max(0, host.split(".").length - 2);
  const brandHits = BRAND_WORDS.filter((w) => noProto.includes(w)).length;

  return {
    url_length_norm: Number(Math.min(1, noProto.length / 140).toFixed(4)),
    path_length_norm: Number(Math.min(1, parsed.pathname.length / 80).toFixed(4)),
    query_length_norm: Number(Math.min(1, parsed.search.length / 80).toFixed(4)),
    host_entropy_norm: Number(Math.min(1, shannonEntropy(host) / 4.5).toFixed(4)),
    digit_ratio: Number(Math.min(1, (digits / Math.max(1, noProto.length)) * 3.0).toFixed(4)),
    subdomain_count_norm: Number(Math.min(1, subdomains / 4).toFixed(4)),
    hyphen_count_norm: Number(Math.min(1, hyphens / 4).toFixed(4)),
    brand_word_hits: Number(Math.min(1, brandHits / 3).toFixed(4)),
    special_char_ratio: Number(Math.min(1, (specials / Math.max(1, noProto.length)) * 4.0).toFixed(4)),
  };
}

export function sigmoid(z) {
  return 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, z))));
}

export function predictUrlMl(rawUrl, model = DEFAULT_URL_MODEL) {
  const feats = extractUrlFeatures(rawUrl);
  let logit = model.bias;
  const contributions = [];

  for (const [name, value] of Object.entries(feats)) {
    const coef = model.features[name] ?? 0;
    const impact = coef * value;
    logit += impact;
    if (value > 0) {
      contributions.push({
        feature: name,
        layer: "ML",
        coefficient: coef,
        value,
        impact: Number(impact.toFixed(4)),
      });
    }
  }

  return {
    mlProb: Number(sigmoid(logit).toFixed(4)),
    logit: Number(logit.toFixed(4)),
    features: feats,
    contributions,
  };
}
