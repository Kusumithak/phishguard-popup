async function initPopup() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const resp = await chrome.runtime.sendMessage({
    type: "GET_TAB_VERDICT",
    tabId: tab.id,
    url: tab.url,
  });

  const result = resp?.result;
  if (!result) {
    document.getElementById("verdict").textContent = "Not scanned";
    return;
  }

  document.getElementById("verdict").textContent = `${result.verdict} (${result.riskScore})`;
  document.getElementById("latency").textContent =
    `${result.latencyMs} ms · ${result.cacheHit ? "Cache Hit" : "Cache Miss"}`;
  document.getElementById("host").textContent = `Host: ${result.hostname || tab.url}`;
  document.getElementById("bloom").textContent =
    `Tranco 50k Bloom: ${result.trustedBloomHit ? "Trusted Match" : "Not in Top 50k"}`;

  const container = document.getElementById("why-list");
  container.innerHTML = "";
  for (const item of result.whyFlagged || []) {
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <span><code>${item.feature}</code> (${item.coefficient} &times; ${item.value})</span>
      <span class="meta">${item.impact >= 0 ? "+" : ""}${item.impact}</span>
    `;
    container.appendChild(div);
  }

  document.getElementById("mark-safe").onclick = async () => {
    await chrome.runtime.sendMessage({
      type: "MARK_SAFE",
      url: tab.url,
      metadata: result,
    });
    document.getElementById("verdict").textContent = "SAFE (Allowlisted)";
  };

  document.getElementById("export-json").onclick = async () => {
    const exportResp = await chrome.runtime.sendMessage({ type: "EXPORT_FALSE_POSITIVES" });
    const blob = new Blob([exportResp.json || "{}"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "false-positives.json";
    a.click();
    URL.revokeObjectURL(url);
  };
}

initPopup();
