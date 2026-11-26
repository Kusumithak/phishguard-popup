/**
 * Compact multi-hash Bloom filter for Tranco Top-50k trusted domains.
 * Works identically in Chrome Extension Service Workers, browser popup, and Node.js.
 */

export class DomainBloomFilter {
  /**
   * @param {number} bitSize - Total bits in filter (m)
   * @param {number} hashCount - Number of hash functions (k)
   * @param {Uint8Array} [bytes] - Optional precomputed bitset bytes
   */
  constructor(bitSize, hashCount, bytes) {
    this.bitSize = bitSize;
    this.hashCount = hashCount;
    this.bytes = bytes || new Uint8Array(Math.ceil(bitSize / 8));
  }

  static normalizeDomain(input) {
    let host = String(input || "").trim().toLowerCase();
    try {
      if (host.includes("://")) {
        host = new URL(host).hostname.toLowerCase();
      }
    } catch {
      // Fallback to raw string cleanup
    }
    host = host.replace(/^www\./, "").split(":")[0];
    return host;
  }

  _hashPair(str) {
    // Double hashing (FNV-1a 32-bit + DJB2-xor 32-bit)
    let h1 = 2166136261;
    let h2 = 5381;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 ^= ch;
      h1 = Math.imul(h1, 16777619);
      h2 = (Math.imul(h2, 33) ^ ch) >>> 0;
    }
    return [h1 >>> 0, (h2 | 1) >>> 0];
  }

  add(domain) {
    const clean = DomainBloomFilter.normalizeDomain(domain);
    if (!clean) return;
    const [h1, h2] = this._hashPair(clean);
    for (let i = 0; i < this.hashCount; i++) {
      const bitIndex = (h1 + i * h2) % this.bitSize;
      this.bytes[bitIndex >>> 3] |= 1 << (bitIndex & 7);
    }
  }

  has(domainOrUrl) {
    const clean = DomainBloomFilter.normalizeDomain(domainOrUrl);
    if (!clean) return false;

    // Check exact domain and registrable parent suffix (e.g., accounts.google.com -> google.com)
    const parts = clean.split(".");
    const candidates = [clean];
    if (parts.length > 2) {
      candidates.push(parts.slice(-2).join("."));
    }
    if (parts.length > 3) {
      candidates.push(parts.slice(-3).join("."));
    }

    return candidates.some((cand) => this._hasExact(cand));
  }

  _hasExact(clean) {
    const [h1, h2] = this._hashPair(clean);
    for (let i = 0; i < this.hashCount; i++) {
      const bitIndex = (h1 + i * h2) % this.bitSize;
      if ((this.bytes[bitIndex >>> 3] & (1 << (bitIndex & 7))) === 0) {
        return false;
      }
    }
    return true;
  }

  toJSON() {
    let bin = "";
    for (let i = 0; i < this.bytes.length; i++) {
      bin += String.fromCharCode(this.bytes[i]);
    }
    const base64 =
      typeof Buffer !== "undefined"
        ? Buffer.from(this.bytes).toString("base64")
        : btoa(bin);
    return {
      version: 1,
      bitSize: this.bitSize,
      hashCount: this.hashCount,
      bitsetBase64: base64,
    };
  }

  static fromJSON(json) {
    let bytes;
    if (typeof Buffer !== "undefined") {
      bytes = new Uint8Array(Buffer.from(json.bitsetBase64, "base64"));
    } else {
      const bin = atob(json.bitsetBase64);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    }
    return new DomainBloomFilter(json.bitSize, json.hashCount, bytes);
  }
}
