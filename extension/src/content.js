/**
 * Role 3 DOM signal extractor bridge (safe read-only DOM inspection, never submits forms).
 */

function extractDomSignals() {
  try {
    const pageHost = window.location.hostname.toLowerCase().replace(/^www\./, "");
    const scriptsAndLinks = Array.from(
      document.querySelectorAll("script[src], img[src], link[href]")
    );
    let externalRes = 0;
    for (const el of scriptsAndLinks) {
      const raw = el.getAttribute("src") || el.getAttribute("href") || "";
      if (raw.startsWith("http")) {
        try {
          const h = new URL(raw).hostname.toLowerCase().replace(/^www\./, "");
          if (h && h !== pageHost && !h.endsWith(`.${pageHost}`)) externalRes++;
        } catch {
          // ignore invalid URL
        }
      }
    }
    const externalRatio =
      scriptsAndLinks.length > 0 ? externalRes / scriptsAndLinks.length : 0;

    const favicon = document.querySelector('link[rel*="icon"]');
    let foreignFavicon = 0;
    if (favicon) {
      const href = favicon.getAttribute("href") || "";
      if (href.startsWith("http")) {
        try {
          const favHost = new URL(href).hostname.toLowerCase().replace(/^www\./, "");
          if (favHost && favHost !== pageHost) foreignFavicon = 1;
        } catch {
          // ignore
        }
      }
    }

    const anchors = Array.from(document.querySelectorAll("a[href]"));
    const voidLinks = anchors.filter((a) => {
      const h = (a.getAttribute("href") || "").trim().toLowerCase();
      return h === "#" || h.startsWith("javascript:void");
    }).length;
    const voidRatio = anchors.length > 0 ? voidLinks / anchors.length : 0;

    const metaRefresh = document.querySelector('meta[http-equiv="refresh" i]') ? 1 : 0;
    const inlineText = Array.from(document.querySelectorAll("script:not([src])"))
      .map((s) => s.textContent || "")
      .join("\n");
    const evalAtobHits = /\b(eval|atob)\s*\(/i.test(inlineText) ? 1 : 0;

    const forms = Array.from(document.querySelectorAll("form"));
    const hasPassword = Boolean(document.querySelector('input[type="password"]'));
    let externalForm = 0;
    if (hasPassword) {
      for (const f of forms) {
        const action = (f.getAttribute("action") || "").trim();
        if (action.startsWith("http")) {
          try {
            const actionHost = new URL(action).hostname.toLowerCase().replace(/^www\./, "");
            if (actionHost && actionHost !== pageHost) externalForm = 1;
          } catch {
            // ignore
          }
        }
      }
    }

    return {
      dom_external_resource_ratio: Number(externalRatio.toFixed(3)),
      dom_foreign_favicon: foreignFavicon,
      dom_void_links_ratio: Number(voidRatio.toFixed(3)),
      dom_meta_refresh: metaRefresh,
      dom_eval_atob_hits: evalAtobHits,
      dom_brand_domain_mismatch: 0,
      dom_password_external_form: externalForm,
    };
  } catch {
    return {};
  }
}

if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
  chrome.runtime.sendMessage({
    type: "DOM_SIGNALS",
    url: window.location.href,
    domFeatures: extractDomSignals(),
  });
}
