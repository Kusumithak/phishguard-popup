/**
 * Heuristic URL rule engine (Role 4 contract + unit-tested module).
 * Produces binary 0/1 rule flags aligned with Role 1's stacked logistic regression inputs.
 */

const SUSPICIOUS_TLDS = new Set([
  "xyz",
  "top",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "zip",
  "click",
  "work",
  "support",
  "monster",
]);

const BRAND_TOKENS = [
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
  "instagram",
  "chase",
  "bank",
];

const SENSITIVE_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "update",
  "secure",
  "account",
  "password",
  "kyc",
  "confirm",
  "unlock",
  "wallet",
  "billing",
];

export const RULE_WEIGHTS = {
  flag_ip_host: 1.45,
  flag_at_symbol: 1.35,
  flag_punycode: 1.25,
  flag_suspicious_tld: 0.95,
  flag_many_subdomains: 0.72,
  flag_long_url: 0.48,
  flag_brand_impersonation: 1.30,
  flag_sensitive_keywords: 0.65,
};

export function evaluateRules(rawUrl, isTrustedDomain = false) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      flags: {
        flag_ip_host: 0,
        flag_at_symbol: 0,
        flag_punycode: 0,
        flag_suspicious_tld: 0,
        flag_many_subdomains: 0,
        flag_long_url: 0,
        flag_brand_impersonation: 0,
        flag_sensitive_keywords: 0,
      },
      activeFlags: [],
      ruleScore: 0,
      contributions: [],
    };
  }

  const host = parsed.hostname.toLowerCase();
  const fullLower = rawUrl.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  const tld = labels[labels.length - 1] || "";
  const registrable = labels.length >= 2 ? `${labels[labels.length - 2]}.${tld}` : host;

  const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith("[");
  const hasAt = rawUrl.includes("@");
  const hasPunycode = labels.some((lbl) => lbl.startsWith("xn--"));
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const manySubdomains = labels.length >= 4;
  const longUrl = !isTrustedDomain && rawUrl.length > 75;

  // Brand token appears in host/path while registrable domain is NOT an exact trusted brand domain
  const matchedBrand = BRAND_TOKENS.find((b) => fullLower.includes(b));
  const brandMismatch = Boolean(
    matchedBrand &&
      !isTrustedDomain &&
      !registrable.startsWith(`${matchedBrand}.`)
  );

  const hasSensitive =
    !isTrustedDomain && SENSITIVE_KEYWORDS.some((kw) => fullLower.includes(kw));

  const flags = {
    flag_ip_host: isIpHost ? 1 : 0,
    flag_at_symbol: hasAt ? 1 : 0,
    flag_punycode: hasPunycode ? 1 : 0,
    flag_suspicious_tld: hasSuspiciousTld ? 1 : 0,
    flag_many_subdomains: manySubdomains ? 1 : 0,
    flag_long_url: longUrl ? 1 : 0,
    flag_brand_impersonation: brandMismatch ? 1 : 0,
    flag_sensitive_keywords: hasSensitive ? 1 : 0,
  };

  const activeFlags = Object.entries(flags)
    .filter(([, val]) => val === 1)
    .map(([name]) => name);

  let rawSum = 0;
  const contributions = [];
  for (const [name, value] of Object.entries(flags)) {
    const coef = RULE_WEIGHTS[name] ?? 0;
    const impact = coef * value;
    rawSum += impact;
    if (value !== 0) {
      contributions.push({
        feature: name,
        layer: "Rules",
        coefficient: coef,
        value,
        impact: Number(impact.toFixed(4)),
      });
    }
  }

  return {
    flags,
    activeFlags,
    ruleScore: Number(rawSum.toFixed(4)),
    contributions,
  };
}
