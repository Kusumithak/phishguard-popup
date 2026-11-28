/**
 * Per-hostname verdict cache with TTL and latency telemetry.
 */

export class VerdictCache {
  /**
   * @param {number} ttlMs - Time-to-live in milliseconds (default 15 minutes)
   * @param {number} maxEntries - Maximum cached hostnames
   */
  constructor(ttlMs = 15 * 60 * 1000, maxEntries = 500) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.store = new Map();
  }

  static extractHostname(rawUrl) {
    try {
      return new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return String(rawUrl || "").toLowerCase();
    }
  }

  get(rawUrl) {
    const start = typeof performance !== "undefined" ? performance.now() : Date.now();
    const host = VerdictCache.extractHostname(rawUrl);
    const entry = this.store.get(host);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(host);
      return null;
    }

    // Refresh LRU order
    this.store.delete(host);
    this.store.set(host, entry);

    const end = typeof performance !== "undefined" ? performance.now() : Date.now();
    return {
      ...entry.result,
      cacheHit: true,
      latencyMs: Number(Math.max(0.05, end - start).toFixed(2)),
    };
  }

  set(rawUrl, result) {
    const host = VerdictCache.extractHostname(rawUrl);
    if (!host) return;
    if (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) this.store.delete(oldestKey);
    }
    this.store.set(host, {
      result: { ...result, cacheHit: false },
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  invalidate(rawUrl) {
    const host = VerdictCache.extractHostname(rawUrl);
    this.store.delete(host);
  }

  clear() {
    this.store.clear();
  }

  size() {
    return this.store.size;
  }
}
