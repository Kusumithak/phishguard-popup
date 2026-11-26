const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url") || "";

document.getElementById("blocked-url").textContent = targetUrl || "Unknown URL";

async function loadDetails() {
  const { lastBlockedResult } = await chrome.storage.local.get(["lastBlockedResult"]);
  if (!lastBlockedResult) return;

  document.getElementById("meta-line").textContent =
    `Verdict: ${lastBlockedResult.verdict} · Risk Score: ${lastBlockedResult.riskScore} · ` +
    `Latency: ${lastBlockedResult.latencyMs} ms (${lastBlockedResult.cacheHit ? "Cache Hit" : "Cache Miss"})`;

  const tbody = document.getElementById("why-rows");
  tbody.innerHTML = "";
  for (const row of lastBlockedResult.whyFlagged || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${row.feature}</code></td>
      <td>${row.layer}</td>
      <td class="num">${Number(row.coefficient).toFixed(2)}</td>
      <td class="num">${Number(row.value).toFixed(2)}</td>
      <td class="num">${row.impact >= 0 ? "+" : ""}${Number(row.impact).toFixed(3)}</td>
    `;
    tbody.appendChild(tr);
  }

  document.getElementById("mark-safe-btn").onclick = async () => {
    await chrome.runtime.sendMessage({
      type: "MARK_SAFE",
      url: targetUrl,
      metadata: lastBlockedResult,
    });
    document.getElementById("status-msg").textContent =
      "Domain added to local allowlist and logged as a false positive.";
    if (targetUrl.startsWith("http")) {
      window.location.href = targetUrl;
    }
  };
}

document.getElementById("go-back-btn").onclick = () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "about:blank";
  }
};

document.getElementById("export-json-btn").onclick = async () => {
  const resp = await chrome.runtime.sendMessage({ type: "EXPORT_FALSE_POSITIVES" });
  const blob = new Blob([resp.json || "{}"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "false-positives.json";
  a.click();
  URL.revokeObjectURL(url);
};

loadDetails();
