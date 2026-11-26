/**
 * Chrome Extension MV3 Background Service Worker (Role 4).
 * Integrates Bloom filter, verdict cache, hybrid scoring, blocking warning page, and allowlist.
 */

import { DomainBloomFilter } from "./src/bloom-filter.js";
import { evaluateHybrid } from "./src/hybrid.js";
import { VerdictCache } from "./src/verdict-cache.js";
import { AllowlistStore } from "./src/allowlist.js";

const cache = new VerdictCache(15 * 60 * 1000, 500);
let bloomFilter = null;
let urlModel = null;
let allowlist = new AllowlistStore();

async function ensureAssetsLoaded() {
  if (!bloomFilter) {
    const resp = await fetch(chrome.runtime.getURL("data/tranco-top50k-bloom.json"));
    bloomFilter = DomainBloomFilter.fromJSON(await resp.json());
  }
  if (!urlModel) {
    const resp = await fetch(chrome.runtime.getURL("src/ml/model.json"));
    urlModel = await resp.json();
  }
  const stored = await chrome.storage.local.get(["allowlistData"]);
  if (stored?.allowlistData) {
    allowlist = AllowlistStore.fromSerialized(stored.allowlistData);
  }
}

async function saveAllowlist() {
  await chrome.storage.local.set({
    allowlistData: JSON.parse(allowlist.exportJSON()),
  });
}

async function evaluateUrlWithCache(url, domFeatures = {}) {
  await ensureAssetsLoaded();

  if (allowlist.has(url)) {
    return evaluateHybrid(url, { bloomFilter, allowlistSet: allowlist.hosts, domFeatures, model: urlModel });
  }

  // Only serve cached verdict when no new DOM features override URL check
  const hasDom = Object.keys(domFeatures || {}).length > 0;
  if (!hasDom) {
    const cached = cache.get(url);
    if (cached) return cached;
  }

  const result = evaluateHybrid(url, {
    bloomFilter,
    allowlistSet: allowlist.hosts,
    domFeatures,
    model: urlModel,
  });
  cache.set(url, result);
  return result;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http://") && !details.url.startsWith("https://")) return;

  const result = await evaluateUrlWithCache(details.url);
  await chrome.storage.local.set({ [`tab_${details.tabId}`]: result });

  if (result.verdict === "PHISHING") {
    await chrome.storage.local.set({ lastBlockedResult: result });
    const blockedUrl = `${chrome.runtime.getURL("blocked.html")}?url=${encodeURIComponent(details.url)}`;
    chrome.tabs.update(details.tabId, { url: blockedUrl });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "DOM_SIGNALS" && message.url) {
      const result = await evaluateUrlWithCache(message.url, message.domFeatures || {});
      if (sender.tab?.id !== undefined) {
        await chrome.storage.local.set({ [`tab_${sender.tab.id}`]: result });
        if (result.verdict === "PHISHING") {
          await chrome.storage.local.set({ lastBlockedResult: result });
          const blockedUrl = `${chrome.runtime.getURL("blocked.html")}?url=${encodeURIComponent(message.url)}`;
          chrome.tabs.update(sender.tab.id, { url: blockedUrl });
        }
      }
      sendResponse({ ok: true, result });
      return;
    }

    if (message?.type === "GET_TAB_VERDICT") {
      const stored = await chrome.storage.local.get([`tab_${message.tabId}`]);
      let res = stored[`tab_${message.tabId}`];
      if (!res && message.url) {
        res = await evaluateUrlWithCache(message.url);
      }
      sendResponse({ result: res || null });
      return;
    }

    if (message?.type === "MARK_SAFE") {
      await ensureAssetsLoaded();
      const record = allowlist.markSafe(message.url, message.metadata || {});
      cache.invalidate(message.url);
      await saveAllowlist();
      sendResponse({ ok: true, record });
      return;
    }

    if (message?.type === "EXPORT_FALSE_POSITIVES") {
      await ensureAssetsLoaded();
      sendResponse({ json: allowlist.exportJSON() });
      return;
    }

    if (message?.type === "CLEAR_CACHE") {
      cache.clear();
      sendResponse({ ok: true });
      return;
    }
  })();

  return true;
});
