
/*
 * PhishGuard DOM Analysis
 *
 * Privacy contract:
 * - Inspect page structure and form destinations only.
 * - Never read input values.
 * - Never submit forms.
 * - Never send page text or content to an external server.
 * - Send structural findings to the local extension background script.
 *
 * Role 3 additions: a few signals read inline <script> text and the page
 * title/meta names LOCALLY and reduce them to 0/1 flags or counts
 * (for example "contains atob(" or "title names a known brand").
 * The text itself is discarded and is never stored or transmitted.
 */

"use strict";

(() => {
  if (globalThis.__phishGuardDomScannerInstalled) {
    globalThis.__phishGuardScheduleProbe?.(true);
    return;
  }

  globalThis.__phishGuardDomScannerInstalled = true;

  const MAX_SCORE = 100;
  const RESCAN_INTERVAL_MS = 2000;

  let scanId = null;
  let probeTimer = null;
  let fullScanTimer = null;
  let lastProbeSignature = "";
  let lastFullScanAt = 0;
  let lastFullSignature = "";
  let observer = null;

  // Safely collect forms from the current page and accessible iframes.
  function pageForms() {
    const forms = [...document.forms];

    for (const frame of document.querySelectorAll("iframe")) {
      try {
        forms.push(...(frame.contentDocument?.forms || []));
      } catch {
        // Cross-origin iframe contents are inaccessible.
      }
    }

    return [...new Set(forms)];
  }

  // Collect password fields without reading their values.
  function pagePasswordFields() {
    const fields = [
      ...document.querySelectorAll('input[type="password"]')
    ];

    for (const frame of document.querySelectorAll("iframe")) {
      try {
        fields.push(
          ...(frame.contentDocument?.querySelectorAll(
            'input[type="password"]'
          ) || [])
        );
      } catch {
        // Cross-origin iframe contents are inaccessible.
      }
    }

    return [...new Set(fields)];
  }

  // Detect hidden inputs whose names or IDs suggest credentials.
  function hiddenCredentialInputs() {
    const inputs = [
      ...document.querySelectorAll('input[type="hidden"]')
    ];

    for (const frame of document.querySelectorAll("iframe")) {
      try {
        inputs.push(
          ...(frame.contentDocument?.querySelectorAll(
            'input[type="hidden"]'
          ) || [])
        );
      } catch {
        // Cross-origin iframe contents are inaccessible.
      }
    }

    return [...new Set(inputs)].filter((input) =>
      /pass(word)?|credential|secret/i.test(
        `${input.name} ${input.id}`
      )
    );
  }

  // Determine whether an element is hidden.
  function isHidden(element) {
    const doc = element.ownerDocument;

    try {
      const style = doc.defaultView.getComputedStyle(element);

      return (
        style.display === "none" ||
        style.visibility === "hidden" ||
        element.getClientRects().length === 0
      );
    } catch {
      return false;
    }
  }

  // Resolve a form's destination safely.
  function getFormTarget(form) {
    const baseUrl =
      form.ownerDocument?.location?.href || location.href;

    let action = (form.getAttribute("action") || "").trim();

    // A javascript: action submits nowhere (it is handled by page script), so it must not
    // be read as a different origin ("null") and flagged as a cross-origin password form.
    if (!action || /^javascript:/i.test(action)) {
      action = baseUrl;
    }

    try {
      return new URL(action, baseUrl);
    } catch {
      return null;
    }
  }

  // Lightweight structural probe used by the background script.
  function probePage() {
    const pageOrigin = location.origin;
    const forms = pageForms();
    const passwordFields = pagePasswordFields();
    const hiddenCredentials = hiddenCredentialInputs();

    const formActionOrigins = [
      ...new Set(
        forms.map((form) => {
          const target = getFormTarget(form);
          return target ? target.origin : "invalid";
        })
      )
    ];

    return {
      hasPasswordField:
        passwordFields.length > 0 || hiddenCredentials.length > 0,

      hasForm: forms.length > 0,

      formActionOrigins,

      hasCrossOriginForm: formActionOrigins.some(
        (origin) => origin !== pageOrigin
      )
    };
  }


  // ---------------------------------------------------------------------
  // Role 3: DOM feature extraction (raw numeric features for the learned
  // fusion model). Every key is always present, in a fixed order, so the
  // extension and the crawler produce identical CSV columns.
  // ---------------------------------------------------------------------

  const MULTI_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "org.in",
    "net.in", "gov.in", "ac.in", "nic.in", "bank.in", "co.jp", "co.nz",
    "co.za", "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "com.tr"
  ]);

  // Lightweight eTLD+1. The crawler recomputes the CSV `domain` column
  // with the full Public Suffix List (tldts), so this only drives the
  // relative "same site / different site" features.
  function siteOf(hostname) {
    const host = String(hostname || "").toLowerCase().replace(/^www\./, "");
    if (/^[\d.]+$/.test(host) || host.includes(":")) return host;
    const labels = host.split(".");
    if (labels.length <= 2) return host;
    const last2 = labels.slice(-2).join(".");
    return MULTI_SUFFIXES.has(last2) ? labels.slice(-3).join(".") : last2;
  }

  function sameSite(hostA, hostB) {
    return siteOf(hostA) === siteOf(hostB);
  }

  // brand -> domain fragments that legitimately belong to that brand.
  const BRAND_DOMAINS = {
    paypal: ["paypal"],
    google: ["google", "gstatic", "youtube", "gmail", "goog"],
    microsoft: ["microsoft", "live", "office", "outlook", "bing", "msn", "azure", "windows", "xbox", "skype", "sharepoint"],
    apple: ["apple", "icloud"],
    amazon: ["amazon", "amzn", "aws"],
    facebook: ["facebook", "fb", "meta", "messenger"],
    instagram: ["instagram", "facebook", "meta"],
    whatsapp: ["whatsapp", "facebook", "meta"],
    linkedin: ["linkedin", "microsoft"],
    netflix: ["netflix"],
    dropbox: ["dropbox"],
    adobe: ["adobe"],
    docusign: ["docusign"],
    dhl: ["dhl"],
    fedex: ["fedex"],
    chase: ["chase", "jpmorgan"],
    wellsfargo: ["wellsfargo"],
    citibank: ["citi"],
    bankofamerica: ["bankofamerica", "bofa"],
    sbi: ["sbi", "statebank"],
    hdfc: ["hdfc"],
    icici: ["icici"],
    axis: ["axisbank", "axis"],
    paytm: ["paytm"],
    phonepe: ["phonepe"],
    irctc: ["irctc"],
    flipkart: ["flipkart"]
  };

  const round4 = (value) => Math.round(value * 1e4) / 1e4;
  const ratio = (part, whole) => (whole > 0 ? round4(part / whole) : 0);

  function safeUrl(value, base) {
    try {
      return new URL(value, base);
    } catch {
      return null;
    }
  }

  // Elements a password manager can still fill but a person cannot see.
  function isStealthHidden(element) {
    // Deliberate password-manager decoy used by some real login pages.
    if (element.getAttribute("tabindex") === "-1" && element.getAttribute("aria-hidden") === "true") {
      return false;
    }
    try {
      const view = element.ownerDocument.defaultView;
      for (let el = element; el && el.nodeType === 1; el = el.parentElement) {
        const style = view.getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden") return false;
      }
      for (let el = element; el && el.nodeType === 1; el = el.parentElement) {
        const style = view.getComputedStyle(el);
        const offscreen =
          (style.position === "absolute" || style.position === "fixed") &&
          (parseFloat(style.left) <= -1000 || parseFloat(style.top) <= -1000);
        if (Number(style.opacity) === 0 || offscreen) return true;
      }
      const own = view.getComputedStyle(element);
      return parseFloat(own.width) <= 1 && parseFloat(own.height) <= 1;
    } catch {
      return false;
    }
  }

  function resourceFeatures(pageHost) {
    const nodes = [
      ...document.querySelectorAll(
        'img[src], script[src], link[rel~="stylesheet"][href], link[rel~="icon"][href], video[src], audio[src], source[src], embed[src]'
      )
    ].slice(0, 2000);

    let total = 0;
    let external = 0;
    let externalScripts = 0;
    const externalSites = new Set();

    for (const node of nodes) {
      const raw = node.getAttribute("src") || node.getAttribute("href") || "";
      if (!raw || /^(data|blob|about|javascript):/i.test(raw)) continue;
      const url = safeUrl(raw, location.href);
      if (!url || !/^https?:$/.test(url.protocol)) continue;

      total += 1;
      if (!sameSite(url.hostname, pageHost)) {
        external += 1;
        externalSites.add(siteOf(url.hostname));
        if (node.tagName === "SCRIPT") externalScripts += 1;
      }
    }

    return {
      dom_n_resources: total,
      dom_n_ext_resources: external,
      dom_ext_resource_ratio: ratio(external, total),
      dom_n_ext_sites: externalSites.size,
      dom_n_ext_scripts: externalScripts
    };
  }

  function faviconFeatures(pageHost) {
    const icons = [
      ...document.querySelectorAll(
        'link[rel~="icon"][href], link[rel="apple-touch-icon"][href]'
      )
    ];
    let foreign = 0;
    for (const icon of icons) {
      const raw = icon.getAttribute("href") || "";
      if (/^data:/i.test(raw)) continue;
      const url = safeUrl(raw, location.href);
      if (url && /^https?:$/.test(url.protocol) && !sameSite(url.hostname, pageHost)) {
        foreign += 1;
      }
    }
    return {
      dom_favicon_present: icons.length > 0 ? 1 : 0,
      dom_favicon_foreign: foreign > 0 ? 1 : 0
    };
  }

  function linkFeatures(pageHost) {
    const anchors = [...document.querySelectorAll("a[href]")].slice(0, 3000);
    let nullLinks = 0;
    let externalLinks = 0;
    let counted = 0;

    for (const anchor of anchors) {
      const raw = (anchor.getAttribute("href") || "").trim();
      if (/^(mailto|tel|sms):/i.test(raw)) continue;
      counted += 1;
      if (raw === "" || raw === "#" || /^javascript:/i.test(raw)) {
        nullLinks += 1;
        continue;
      }
      const url = safeUrl(raw, location.href);
      if (url && /^https?:$/.test(url.protocol) && !sameSite(url.hostname, pageHost)) {
        externalLinks += 1;
      }
    }

    return {
      dom_n_links: counted,
      dom_null_link_ratio: ratio(nullLinks, counted),
      dom_ext_link_ratio: ratio(externalLinks, counted)
    };
  }

  function metaRefreshFeatures(pageHost) {
    const meta = document.querySelector('meta[http-equiv="refresh" i]');
    if (!meta) return { dom_meta_refresh: 0, dom_meta_refresh_cross_site: 0 };

    const match = /url\s*=\s*['"]?([^'";]+)/i.exec(meta.getAttribute("content") || "");
    const target = match ? safeUrl(match[1].trim(), location.href) : null;
    return {
      dom_meta_refresh: 1,
      dom_meta_refresh_cross_site:
        target && /^https?:$/.test(target.protocol) && !sameSite(target.hostname, pageHost) ? 1 : 0
    };
  }

  // Only inline scripts are readable; their text is reduced to flags and discarded.
  function scriptFeatures() {
    const scripts = [...document.querySelectorAll("script:not([src])")].slice(0, 200);
    const flags = { eval: 0, atob: 0, obfuscation: 0, docWrite: 0 };
    let bytes = 0;

    for (const script of scripts) {
      const text = (script.textContent || "").slice(0, 100000);
      bytes += text.length;
      if (/\beval\s*\(/.test(text)) flags.eval = 1;
      if (/\batob\s*\(/.test(text)) flags.atob = 1;
      if (/\bunescape\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}/i.test(text)) flags.obfuscation = 1;
      if (/document\.write\s*\(/.test(text)) flags.docWrite = 1;
    }

    return {
      dom_n_inline_scripts: scripts.length,
      dom_inline_script_bytes: bytes,
      dom_script_eval: flags.eval,
      dom_script_atob: flags.atob,
      dom_script_obfuscation: flags.obfuscation,
      dom_script_document_write: flags.docWrite
    };
  }

  // Does the page name a known brand (title / og:site_name / application-name)
  // while the registrable domain has nothing to do with that brand?
  function brandFeatures(pageHost) {
    const names = [
      document.title,
      document.querySelector('meta[property="og:site_name"]')?.content,
      document.querySelector('meta[name="application-name"]')?.content
    ].filter(Boolean).join(" ").toLowerCase();

    const label = siteOf(pageHost).split(".")[0].replace(/[^a-z0-9]/g, "");
    const hits = Object.keys(BRAND_DOMAINS).filter((brand) =>
      new RegExp(`\\b${brand}\\b`).test(names)
    );
    const mismatched = hits.filter(
      (brand) => !BRAND_DOMAINS[brand].some((fragment) => label.includes(fragment))
    );

    return {
      dom_brand_in_title: hits.length > 0 ? 1 : 0,
      dom_brand_domain_mismatch: mismatched.length > 0 ? 1 : 0
    };
  }

  function extractFeatures(context) {
    const pageHost = location.hostname;
    const { forms, passwordFields, hiddenCredentials, iframes, counters } = context;
    const hiddenPw = passwordFields.filter(isHidden);
    const stealthPw = passwordFields.filter(isStealthHidden);

    return {
      // --- structure (these also feed the existing hand-set rule flags) ---
      dom_n_forms: forms.length,
      dom_n_password_fields: passwordFields.length,
      dom_n_password_visible: passwordFields.length - hiddenPw.length,
      dom_n_password_hidden: hiddenPw.length,
      dom_n_password_stealth_hidden: stealthPw.length,
      dom_n_hidden_credential_inputs: hiddenCredentials.length,
      dom_n_forms_cross_origin: counters.crossOrigin,
      dom_n_forms_cross_site: counters.crossSite,
      dom_n_forms_http: counters.http,
      dom_n_password_forms_cross_origin: counters.pwCrossOrigin,
      dom_n_password_forms_cross_site: counters.pwCrossSite,
      dom_n_password_forms_http: counters.pwHttp,
      dom_n_forms_null_action: counters.nullAction,
      dom_n_iframes: iframes.length,
      dom_n_hidden_iframes: counters.hiddenIframes,
      dom_n_hidden_iframes_with_form: counters.hiddenIframesWithForms,
      dom_password_without_form: passwordFields.length > 0 && forms.length === 0 ? 1 : 0,
      // --- Role 3 signals ---
      ...resourceFeatures(pageHost),
      ...faviconFeatures(pageHost),
      ...linkFeatures(pageHost),
      ...metaRefreshFeatures(pageHost),
      ...scriptFeatures(),
      ...brandFeatures(pageHost)
    };
  }

  // Full DOM risk analysis.
  function scanDom() {
    const findings = [];
    const pageUrl = new URL(location.href);

    const forms = pageForms();
    const passwordFields = pagePasswordFields();
    const hiddenCredentials = hiddenCredentialInputs();
    const iframes = [...document.querySelectorAll("iframe")];

    let crossOriginForms = 0;
    let httpForms = 0;
    let hiddenIframeCount = 0;
    let hiddenIframesWithForms = 0;

    // Raw counters for the learned-fusion feature vector (no effect on scoring).
    const counters = {
      crossOrigin: 0, crossSite: 0, http: 0,
      pwCrossOrigin: 0, pwCrossSite: 0, pwHttp: 0,
      nullAction: 0, hiddenIframes: 0, hiddenIframesWithForms: 0
    };

    // Check form destinations and password-form relationships.
    for (const form of forms) {
      const target = getFormTarget(form);

      if (!target) {
        findings.push("invalid_form_action");
        continue;
      }

      const baseUrl =
        form.ownerDocument?.location?.href || location.href;

      const formOrigin = (() => {
        try {
          return new URL(baseUrl).origin;
        } catch {
          return pageUrl.origin;
        }
      })();

      const containsPassword = Boolean(
        form.querySelector('input[type="password"]')
      );

      const isCrossOrigin = target.origin !== formOrigin;
      const usesHttp = target.protocol === "http:";

      const rawAction = (form.getAttribute("action") || "").trim();
      const isCrossSite =
        /^https?:$/.test(target.protocol) &&
        !sameSite(target.hostname, pageUrl.hostname);

      if (!rawAction || rawAction === "#" || /^javascript:/i.test(rawAction)) counters.nullAction += 1;
      if (isCrossOrigin) counters.crossOrigin += 1;
      if (isCrossSite) counters.crossSite += 1;
      if (usesHttp) counters.http += 1;
      if (containsPassword && isCrossOrigin) counters.pwCrossOrigin += 1;
      if (containsPassword && isCrossSite) counters.pwCrossSite += 1;
      if (containsPassword && usesHttp) counters.pwHttp += 1;

      if (isCrossOrigin) {
        crossOriginForms += 1;
      }

      if (usesHttp) {
        httpForms += 1;
      }

      // A password form posting to another origin is worth investigating.
      if (containsPassword && isCrossOrigin) {
        findings.push("password_form_cross_origin");
      }

      // Password data sent over unencrypted HTTP is a stronger warning.
      if (containsPassword && usesHttp) {
        findings.push("password_form_http");
      }

      // External HTTP forms without password fields are also suspicious.
      if (!containsPassword && isCrossOrigin && usesHttp) {
        findings.push("external_form_http");
      }
    }

    // Detect hidden password fields and hidden credential-like inputs.
    // Only a password field made invisible on purpose (opacity 0, off-screen, 1px) is
    // suspicious. A field inside a closed modal or an inactive login step (display:none)
    // is normal, and so are hidden inputs whose name merely contains "pass" (e.g. "passkey").
    // The raw counts are still exported as features for the learned fusion.
    if (passwordFields.some(isStealthHidden)) {
      findings.push("hidden_password_field");
    }

    // Only flag a hidden iframe if that particular accessible iframe
    // actually contains a form.
    for (const frame of iframes) {
      if (!isHidden(frame)) {
        continue;
      }

      hiddenIframeCount += 1;
      counters.hiddenIframes += 1;

      try {
        const frameForms = frame.contentDocument?.forms;

        if (frameForms && frameForms.length > 0) {
          hiddenIframesWithForms += 1;
          counters.hiddenIframesWithForms += 1;
        }
      } catch {
        // Cross-origin iframe contents cannot be inspected.
      }
    }

    if (hiddenIframesWithForms > 0) {
      findings.push("hidden_iframe_with_form");
    }

    // A password field without a form may still be legitimate.
    // Treat this as a low-weight indicator, not proof of phishing.
    if (passwordFields.length > 0 && forms.length === 0) {
      findings.push("password_field_without_form");
    }

    // Each finding contributes rule-based risk points.
    const points = {
      password_form_cross_origin: 35,
      password_form_http: 35,
      external_form_http: 15,
      hidden_password_field: 20,
      hidden_iframe_with_form: 10,
      password_field_without_form: 5,
      invalid_form_action: 5
    };

    const uniqueFindings = [...new Set(findings)];

    const domScore = Math.max(
      0,
      Math.min(
        MAX_SCORE,
        uniqueFindings.reduce(
          (total, id) => total + (points[id] || 0),
          0
        )
      )
    );

    // Counts help the popup display meaningful structural statistics.
    // No input values or page text are included.
    return {
      domScore,
      findings: uniqueFindings,
      // Extra field for the fusion model / dataset. background.js ignores it.
      features: extractFeatures({ forms, passwordFields, hiddenCredentials, iframes, counters }),
      stats: {
        passwordFields: passwordFields.length,
        hiddenCredentialInputs: hiddenCredentials.length,
        forms: forms.length,
        crossOriginForms,
        httpForms,
        iframes: iframes.length,
        hiddenIframes: hiddenIframeCount,
        hiddenIframesWithForms
      }
    };
  }

  // Stop all work when the extension was reloaded or updated: the old content script stays
  // alive in already-open tabs and chrome.runtime then throws "Extension context invalidated".
  function shutdown() {
    clearTimeout(probeTimer);
    clearTimeout(fullScanTimer);
    observer?.disconnect();
    observer = null;
  }

  // Send results only to the extension's runtime.
  function send(type, payload) {
    try {
      if (!chrome.runtime?.id) {
        shutdown();
        return;
      }

      chrome.runtime.sendMessage({
        type,
        url: location.href,
        scanId,
        ...payload
      })?.catch?.(() => {
        // The background worker may be asleep.
      });
    } catch {
      shutdown();
    }
  }

  // Run the complete scan with a minimum interval.
  function runFullScan() {
    const now = Date.now();
    const wait = lastFullScanAt + RESCAN_INTERVAL_MS - now;

    if (wait > 0) {
      if (!fullScanTimer) {
        fullScanTimer = setTimeout(() => {
          fullScanTimer = null;
          runFullScan();
        }, wait);
      }

      return;
    }

    const result = scanDom();
    const signature = `${location.href}|${JSON.stringify(result)}`;

    lastFullScanAt = now;

    if (signature === lastFullSignature) {
      return;
    }

    lastFullSignature = signature;
    send("PHISHGUARD_DOM_RESULT", result);
  }

  // Run the lightweight probe.
  function runProbe(force = false) {
    const probe = probePage();
    const signature = `${location.href}|${JSON.stringify(probe)}`;

    if (!force && signature === lastProbeSignature) {
      return;
    }

    lastProbeSignature = signature;
    send("PHISHGUARD_DOM_PROBE_RESULT", { probe });
  }

  function scheduleProbe(force = false) {
    clearTimeout(probeTimer);

    if (force) {
      lastProbeSignature = "";
      lastFullSignature = "";
    }

    probeTimer = setTimeout(() => {
      runProbe(force);
    }, 50);
  }

  globalThis.__phishGuardScheduleProbe = scheduleProbe;
  globalThis.__phishGuardScanDom = scanDom;

  // Listen for scan requests from the extension background script.
  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "PHISHGUARD_SCAN_INIT") {
      if (scanId !== message.scanId) {
        clearTimeout(fullScanTimer);
        fullScanTimer = null;
        lastFullScanAt = 0;
        lastFullSignature = "";
      }

      scanId = message.scanId;
      scheduleProbe(true);
    } else if (message?.type === "PHISHGUARD_RUN_DOM_SCAN") {
      if (message.scanId === scanId) {
        runFullScan();
      }
    }
  });

  // Check whether a DOM node contains relevant structure.
  function nodeHasSensitiveStructure(node) {
    if (!(node instanceof Element)) {
      return false;
    }

    return (
      node.matches("form, input, iframe") ||
      Boolean(node.querySelector("form, input, iframe"))
    );
  }

  function mutationAffectsStructure(record) {
    if (record.type === "attributes") {
      return (
        record.target instanceof Element &&
        record.target.matches("form, input, iframe")
      );
    }

    if (
      record.target instanceof Element &&
      record.target.closest("form")
    ) {
      return true;
    }

    return [...record.addedNodes, ...record.removedNodes]
      .some(nodeHasSensitiveStructure);
  }

  function inspectAfterMutation() {
    scheduleProbe(true);
  }

  function ready() {
    scheduleProbe(true);

    observer = new MutationObserver((records) => {
      if (records.some(mutationAffectsStructure)) {
        inspectAfterMutation();
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["type", "action", "style", "class"]
    });

    // Avoid observing page changes indefinitely.
    setTimeout(() => observer?.disconnect(), 30000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready, {
      once: true
    });
  } else {
    ready();
  }
})();
