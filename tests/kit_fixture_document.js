"use strict";

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);

// Minimal parser for static safe fixtures. It constructs only the document structure that
// kitFingerprint reads; it intentionally discards text and all attributes except type/method.
function documentFromHtml(html, domain = "fixture.test") {
  const elements = [];
  const forms = [];
  const stack = [];
  const tokens = /<!--[\s\S]*?-->|<![^>]*>|<\/?([a-z][\w:-]*)\b([^>]*)>/gi;
  for (const match of html.matchAll(tokens)) {
    const raw = match[0];
    const tag = match[1]?.toLowerCase();
    if (!tag) continue;
    if (raw.startsWith("</")) {
      const index = stack.map((item) => item.tagName).lastIndexOf(tag);
      if (index >= 0) stack.length = index;
      continue;
    }

    const attrs = Object.fromEntries([...raw.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)]
      .map((item) => [item[1].toLowerCase(), item[2] ?? item[3] ?? item[4] ?? ""]));
    const node = { tagName: tag, type: (attrs.type || "text").toLowerCase() };
    elements.push(node);
    if (tag === "form") {
      node.method = (attrs.method || "get").toLowerCase();
      node.inputs = [];
      node.querySelectorAll = (selector) => selector === "input" ? node.inputs : [];
      forms.push(node);
    } else if (tag === "input") {
      const parentForm = [...stack].reverse().find((item) => item.tagName === "form");
      parentForm?.inputs.push(node);
    }
    if (!VOID.has(tag) && !raw.endsWith("/>")) stack.push(node);
  }

  return {
    URL: `https://${domain}/`,
    forms,
    querySelectorAll(selector) {
      if (selector === "*") return elements;
      if (selector === 'input[type="password"]') return elements.filter((item) => item.tagName === "input" && item.type === "password");
      const tags = selector.split(",").map((value) => value.trim());
      return elements.filter((item) => tags.includes(item.tagName));
    }
  };
}

module.exports = { documentFromHtml };
