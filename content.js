
/*
 * PhishGuard DOM Analysis
 *
 * Privacy contract:
 * - Inspect page structure and form destinations only.
 * - Never read input values.
 * - Never submit forms.
 * - Never send page text or content to an external server.
 * - Send structural findings to the local extension background script.
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

    const action = form.getAttribute("action") || baseUrl;

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
    const hiddenPasswordFields = passwordFields.filter(isHidden);

    if (hiddenPasswordFields.length > 0 || hiddenCredentials.length > 0) {
      findings.push("hidden_password_field");
    }

    // Only flag a hidden iframe if that particular accessible iframe
    // actually contains a form.
    for (const frame of iframes) {
      if (!isHidden(frame)) {
        continue;
      }

      hiddenIframeCount += 1;

      try {
        const frameForms = frame.contentDocument?.forms;

        if (frameForms && frameForms.length > 0) {
          hiddenIframesWithForms += 1;
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

  // Send results only to the extension's runtime.
  function send(type, payload) {
    chrome.runtime.sendMessage({
      type,
      url: location.href,
      scanId,
      ...payload
    }).catch(() => {
      // The extension may have been reloaded or its background may be asleep.
    });
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
