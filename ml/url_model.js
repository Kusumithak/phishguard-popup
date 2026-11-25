// PhishGuard - URL model for the extension (pure JS, no network, no dependencies).
// Mirrors extract() in url_pipeline.py. The lexicon comes from model.json, so nothing is duplicated.
//
// Usage (service worker or Node):
//   const model = await (await fetch(chrome.runtime.getURL('ml/model.json'))).json();
//   const p = PhishUrlModel.score(model, 'http://paypal-login.example.xyz/verify');   // 0..1
//
(function (root) {
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  function fnv1a(s) {
    const bytes = new TextEncoder().encode(s);
    let h = 0x811c9dc5;
    for (const b of bytes) {
      h = (h ^ b) >>> 0;
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h;
  }

  function entropy(s) {
    if (!s.length) return 0;
    const n = s.length, c = new Map();
    for (const ch of s) c.set(ch, (c.get(ch) || 0) + 1);
    let e = 0;
    for (const v of c.values()) e -= (v / n) * Math.log2(v / n);
    return e;
  }

  function parse(url) {
    let u = url.trim().replace(/[^\x00-\x7f]/gu, '?');
    u = u.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');
    const m = u.search(/[/?#]/);
    let authority = m >= 0 ? u.slice(0, m) : u;
    let rest = m >= 0 ? u.slice(m) : '';
    const hasAt = authority.includes('@');
    if (authority.includes('@')) authority = authority.slice(authority.lastIndexOf('@') + 1);
    let port = '';
    const mp = authority.match(/:(\d+)$/);
    if (mp) { port = mp[1]; authority = authority.slice(0, mp.index); }
    const host = authority.toLowerCase().replace(/^\.+|\.+$/g, '');
    rest = rest.split('#')[0];
    const q = rest.indexOf('?');
    const path = q >= 0 ? rest.slice(0, q) : rest;
    const query = q >= 0 ? rest.slice(q + 1) : '';
    return { u, host, port, path, query, hasAt };
  }

  function splitHost(host, multi) {
    if (IPV4.test(host) || host.startsWith('[')) return { labels: [host], reg: host, sub: [], tld: '' };
    let labels = host.split('.').filter(Boolean);
    if (labels.length && labels[0] === 'www') labels = labels.slice(1);
    let k = (labels.length >= 3 && multi.has(labels.slice(-2).join('.'))) ? 3 : 2;
    k = Math.min(k, labels.length);
    return {
      labels,
      reg: labels.length ? labels.slice(labels.length - k).join('.') : '',
      sub: labels.slice(0, labels.length - k),
      tld: labels.length ? labels[labels.length - 1] : '',
    };
  }

  const tokens = (s) => s.split(/[^a-z0-9]+/).filter(Boolean);
  const brandHit = (b, text, toks) => (b.length >= 6 ? text.includes(b) : toks.includes(b));

  function extract(url, lex) {
    const multi = lex._multi || (lex._multi = new Set(lex.multi));
    const { u, host, port, path, query, hasAt } = parse(url);
    const authorityEnd = u.search(/[/?#]/);
    const authority = authorityEnd >= 0 ? u.slice(0, authorityEnd) : u;
    const userinfo = authority.includes('@') ? authority.slice(0, authority.lastIndexOf('@')) : '';
    const userSep = userinfo.indexOf(':');
    const username = userSep >= 0 ? userinfo.slice(0, userSep) : userinfo;
    const password = userSep >= 0 ? userinfo.slice(userSep + 1) : '';
    const hasUserinfo = Boolean(username || password);
    const { labels, reg, sub, tld } = splitHost(host, multi);
    const isIp = (IPV4.test(host) || host.startsWith('[')) ? 1 : 0;
    const pathqRaw = path + (query ? '?' + query : '');
    const pathq = pathqRaw.toLowerCase();
    const hostToks = tokens(host), pathToks = tokens(pathq);
    const nDigits = (host.match(/[0-9]/g) || []).length;
    const modelHost = host.startsWith('www.') ? host.slice(4) : host;
    const modelLabels = modelHost ? modelHost.split('.') : [];
    const oldSecondLevel = new Set(['co', 'com', 'ac', 'edu', 'gov', 'org', 'net', 'or', 'ne', 'go']);
    const oldSuffixLen = modelLabels.length >= 3 && modelLabels[modelLabels.length - 1].length === 2 &&
      oldSecondLevel.has(modelLabels[modelLabels.length - 2]) ? 2 : 1;
    const oldSubdomainCount = isIp ? 0 : Math.max(0, modelLabels.length - oldSuffixLen - 1);
    const oldKeywords = new Set([
      'login', 'signin', 'verify', 'verification', 'account', 'secure', 'security', 'update',
      'password', 'credential', 'authenticate', 'bank', 'banking', 'payment', 'billing',
      'wallet', 'card', 'transaction', 'urgent', 'suspended', 'blocked', 'expired',
    ]);
    const oldHostTokens = tokens(modelHost);
    const brands = Object.entries(lex.brands);
    const f = {
      host_len: host.length, n_dots_host: (host.match(/\./g) || []).length, n_subdomains: sub.length,
      n_hyphens_host: (host.match(/-/g) || []).length, n_digits_host: nDigits,
      digit_ratio_host: host.length ? nDigits / host.length : 0,
      host_entropy: entropy(host), longest_label: labels.reduce((m, l) => Math.max(m, l.length), 0),
      tld_len: tld.length, is_ip: isIp, has_at: hasAt ? 1 : 0,
      has_punycode: host.includes('xn--') ? 1 : 0,
      has_port: (port && port !== '80' && port !== '443') ? 1 : 0,
      kw_host: lex.keywords.filter((k) => host.includes(k)).length,
      brand_mismatch_host: brands.some(([b, off]) => brandHit(b, host, hostToks) && !off.includes(reg)) ? 1 : 0,
      host_length: modelHost.length,
      deep_subdomain_count: Math.max(0, oldSubdomainCount - 1),
      digit_ratio: modelHost.length ? (modelHost.match(/[0-9]/g) || []).length / modelHost.length : 0,
      hyphen_count: (modelHost.match(/-/g) || []).length,
      has_ip: isIp,
      has_userinfo: hasUserinfo ? 1 : 0,
      host_keyword_count: oldHostTokens.filter((token) => oldKeywords.has(token)).length,
      url_len: u.length, path_len: path.length, query_len: query.length,
      path_depth: (path.match(/\//g) || []).length,
      n_params: query.split('&').filter(Boolean).length,
      n_pct: (u.match(/%/g) || []).length, path_entropy: entropy(pathqRaw),
      double_slash: path.includes('//') ? 1 : 0,
      kw_path: lex.keywords.filter((k) => pathq.includes(k)).length,
      brand_in_path: brands.some(([b, off]) => brandHit(b, pathq, pathToks) && !off.includes(reg)) ? 1 : 0,
    };
    if (tld) f['tld_h' + (fnv1a(tld) % lex.n_tld)] = 1;
    const s = host + pathq;
    const nTri = Math.max(1, s.length - 2);
    for (let i = 0; i < s.length - 2; i++) {
      const key = 'ng_h' + (fnv1a(s.slice(i, i + 3)) % lex.n_ng);
      f[key] = (f[key] || 0) + 1 / nTri;
    }
    return f;
  }

  function vector(model, url) {
    const f = extract(url, model.lexicon);
    return model.features.map((n) => (f[n] === undefined ? 0 : f[n]));
  }

  const sigmoid = (z) => 1 / (1 + Math.exp(-z));

  function score(model, url) {
    const x = vector(model, url);
    if (model.type === 'lr') {
      let z = model.intercept;
      for (let i = 0; i < x.length; i++) z += model.coef[i] * ((x[i] - model.mean[i]) / model.scale[i]);
      return sigmoid(z);
    }
    let z = model.init;
    for (const t of model.trees) {
      let node = 0;
      while (t.l[node] !== -1) node = x[t.f[node]] <= t.t[node] ? t.l[node] : t.r[node];
      z += model.lr * t.v[node];
    }
    return sigmoid(z);
  }

  const api = { extract, vector, score };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PhishUrlModel = api;
})(typeof self !== 'undefined' ? self : globalThis);
