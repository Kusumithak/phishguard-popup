/**
 * Local allowlist & false-positive report store with JSON export.
 * Used by both popup.js and blocked.js ("Mark as safe / Report false positive").
 */

export class AllowlistStore {
  constructor() {
    this.hosts = new Set();
    this.reports = [];
  }

  static normalizeHost(rawUrlOrHost) {
    try {
      if (String(rawUrlOrHost).includes("://")) {
        return new URL(rawUrlOrHost).hostname.toLowerCase().replace(/^www\./, "");
      }
    } catch {
      // fall through
    }
    return String(rawUrlOrHost || "").trim().toLowerCase().replace(/^www\./, "");
  }

  markSafe(rawUrlOrHost, metadata = {}) {
    const host = AllowlistStore.normalizeHost(rawUrlOrHost);
    if (!host) return null;
    this.hosts.add(host);

    const record = {
      hostname: host,
      url: metadata.url || rawUrlOrHost,
      previous_verdict: metadata.verdict || "PHISHING",
      previous_risk_score: metadata.riskScore ?? null,
      active_flags: metadata.activeFlags || [],
      reported_at: new Date().toISOString(),
      reason: metadata.reason || "Marked safe by user",
    };
    this.reports.push(record);
    return record;
  }

  has(rawUrlOrHost) {
    return this.hosts.has(AllowlistStore.normalizeHost(rawUrlOrHost));
  }

  remove(rawUrlOrHost) {
    const host = AllowlistStore.normalizeHost(rawUrlOrHost);
    this.hosts.delete(host);
    this.reports = this.reports.filter((r) => r.hostname !== host);
  }

  exportJSON() {
    return JSON.stringify(
      {
        schema: "phishguard-false-positive-report-v1",
        exported_at: new Date().toISOString(),
        allowlisted_hosts: Array.from(this.hosts),
        false_positive_reports: this.reports,
      },
      null,
      2
    );
  }

  static fromSerialized(data) {
    const store = new AllowlistStore();
    if (Array.isArray(data?.allowlisted_hosts)) {
      for (const h of data.allowlisted_hosts) store.hosts.add(String(h));
    }
    if (Array.isArray(data?.false_positive_reports)) {
      store.reports = [...data.false_positive_reports];
    }
    return store;
  }
}
