
let latestResult = null;

const $ = (selector) => document.querySelector(selector);

function decisionClass(decision) {
  const value = String(decision || "").toUpperCase();

  if (value === "PHISHING" || value === "CRITICAL" || value === "HIGH RISK") {
    return "critical";
  }

  if (value === "SUSPICIOUS" || value === "MEDIUM RISK") {
    return "suspicious";
  }

  if (value === "SAFE" || value === "LOW RISK") {
    return "low-risk";
  }

  return "pending";
}

function scoreText(value) {
  return Number.isFinite(value) ? `${Math.round(value)}/100` : "Unavailable";
}

function setLayerBar(selector, value, decision) {
  const bar = $(selector);
  if (!bar) return;

  bar.style.width = Number.isFinite(value)
    ? `${Math.max(0, Math.min(100, value))}%`
    : "0%";

  bar.className = decisionClass(decision);
}

function getFindings(result) {
  return Array.isArray(result.findings) ? result.findings : [];
}

function findingParts(item) {
  if (typeof item === "string") {
    return { title: item, detail: "", points: null };
  }

  if (!item || typeof item !== "object") {
    return { title: String(item), detail: "", points: null };
  }

  return {
    title: item.title || item.name || item.rule || item.id || "Detection finding",
    detail: item.detail || item.description || item.message || item.reason || "",
    points: Number.isFinite(item.points)
      ? item.points
      : Number.isFinite(item.score)
        ? item.score
        : null
  };
}

function renderList(selector, items, emptyText) {
  const list = $(selector);
  if (!list) return;

  list.replaceChildren();

  if (!Array.isArray(items) || items.length === 0) {
    const row = document.createElement("li");
    row.textContent = emptyText;
    list.append(row);
    return;
  }

  for (const item of items) {
    const row = document.createElement("li");

    if (typeof item === "string") {
      row.textContent = item;
    } else if (item && typeof item === "object") {
      const title = document.createElement("strong");
      title.textContent =
        item.title || item.name || item.rule || item.id || "Detection finding";

      const detail = document.createElement("span");
      detail.textContent =
        item.detail || item.description || item.message || item.reason ||
        JSON.stringify(item);

      row.append(title, detail);
    } else {
      row.textContent = String(item);
    }

    list.append(row);
  }
}

function getDomData(result) {
  return result.dom ||
    result.domReport ||
    result.pageStructure ||
    result.structure ||
    {};
}

function getDomStats(result) {
  const dom = getDomData(result);
  return dom.stats || dom.probe || dom.features || result.domStats || {};
}

function firstNumber(objects, keys) {
  for (const object of objects) {
    if (!object || typeof object !== "object") continue;

    for (const key of keys) {
      if (Number.isFinite(object[key])) return object[key];
    }
  }

  return null;
}

function setCheck(id, text, status = "") {
  const element = $(`#${id}`);
  if (!element) return;

  element.textContent = text;
  element.className = status;
}

function displayChecks(result) {
  const dom = getDomData(result);
  const stats = getDomStats(result);
  const url = result.url || dom.pageUrl || "";
  const findings = getFindings(result);

  const objects = [stats, dom, result];

  const passwordCount = firstNumber(objects, [
    "passwordFields", "passwordFieldCount", "password_count"
  ]);

  const externalForms = firstNumber(objects, [
    "externalForms", "externalFormCount", "external_form_count"
  ]);

  const iframeCount = firstNumber(objects, [
    "hiddenIframes", "hiddenIframeCount", "hidden_iframes"
  ]);

  const insecureForms = firstNumber(objects, [
    "insecureForms", "insecureFormCount", "insecure_forms"
  ]);

  const formCount = firstNumber(objects, ["formCount", "forms"]);
  const hasDomReport = Number.isFinite(result.domScore) ||
    Object.keys(dom).length > 0 ||
    Object.keys(stats).length > 0;

  if (!hasDomReport) {
    setCheck("passwordCheck", "Not checked");
    setCheck("formCheck", "Not checked");
    setCheck("iframeCheck", "Not checked");
    setCheck("httpsCheck", "Not checked");
    return;
  }

  const hasPasswordFinding = findings.some((item) =>
    /password/i.test(JSON.stringify(item))
  );

  setCheck(
    "passwordCheck",
    passwordCount !== null
      ? passwordCount > 0 ? `Found (${passwordCount})` : "None found"
      : hasPasswordFinding ? "Finding reported" : "Count unavailable",
    passwordCount > 0 || hasPasswordFinding ? "warning" : "good"
  );

  setCheck(
    "formCheck",
    externalForms !== null
      ? externalForms > 0 ? `Found (${externalForms})` : "None found"
      : insecureForms !== null
        ? insecureForms > 0 ? `Insecure (${insecureForms})` : "None found"
        : formCount === 0
          ? "No forms"
          : "Not reported",
    externalForms > 0 || insecureForms > 0 ? "warning" : ""
  );

  setCheck(
    "iframeCheck",
    iframeCount !== null
      ? iframeCount > 0 ? `Found (${iframeCount})` : "None found"
      : "Not reported",
    iframeCount > 0 ? "warning" : ""
  );

  let httpsStatus = "Not reported";
  let httpsClass = "";

  if (url) {
    try {
      const protocol = new URL(url).protocol;

      if (protocol === "https:") {
        httpsStatus = "Yes";
        httpsClass = "good";
      } else if (protocol === "http:") {
        httpsStatus = "No";
        httpsClass = "warning";
      }
    } catch {
      // Leave the status as not reported for an invalid URL.
    }
  }

  setCheck("httpsCheck", httpsStatus, httpsClass);
}

function explainResult(result) {
  const decision = String(result.decision || "").toUpperCase();
  const findings = getFindings(result);
  const reasons = findings.slice(0, 3).map((item) => {
    const parts = findingParts(item);
    return parts.detail
      ? `${parts.title}: ${parts.detail}`
      : parts.title;
  });

  if (result.status !== "complete") {
    return "The scan is still running. The final explanation will be available when the URL and page-structure checks finish.";
  }

  if (decision === "PHISHING" || decision === "CRITICAL") {
    return reasons.length
      ? `High-risk signals were detected: ${reasons.join(" ")} Review the evidence before interacting with this page.`
      : "The detector classified this page as high risk. Review the detection evidence before interacting with it.";
  }

  if (decision === "SUSPICIOUS") {
    return reasons.length
      ? `Some indicators need attention: ${reasons.join(" ")} These signals are warnings, not proof of phishing.`
      : "The detector found enough risk signals to warrant caution. Review the URL, page structure and evidence.";
  }

  if (decision === "SAFE" || decision === "LOW RISK") {
    return reasons.length
      ? `The overall score is low, but these observations were recorded: ${reasons.join(" ")} A low score does not guarantee safety.`
      : "No strong phishing indicators were reported by the available checks. This is not a guarantee that the page is safe.";
  }

  return reasons.length
    ? `The scan recorded these observations: ${reasons.join(" ")}`
    : "Review the individual detection layers and evidence to understand this scan.";
}

function displayResult(result) {
  if (!result) return;

  latestResult = result;

  $("#emptyState").classList.add("hidden");
  $("#result").classList.remove("hidden");

  const decision = result.decision || "SCANNING";
  const riskClass = decisionClass(decision);
  const level = $("#riskLevel");

  level.textContent = decision.replaceAll("_", " ");
  level.className = `risk-level ${riskClass}`;

  const fused = Number.isFinite(result.fused) ? result.fused : null;
  const score = $("#score");

  score.replaceChildren();

  const scoreValue = document.createTextNode(
    fused === null ? "—" : String(Math.round(fused))
  );
  const suffix = document.createElement("small");
  suffix.textContent = "/100";

  score.append(scoreValue, suffix);

  $("#meterFill").style.width =
    fused === null ? "0%" : `${Math.max(0, Math.min(100, fused))}%`;
  $("#meterFill").className = riskClass;

  $("#host").textContent = result.url || "Current tab";

  $("#summary").textContent = result.status === "complete"
    ? `Scan complete · Updated ${new Date(
        result.timestamps?.updatedAt || Date.now()
      ).toLocaleTimeString()}`
    : result.extremeBlock
      ? "A strong URL warning was raised while page analysis completes."
      : "The URL was checked. Waiting for page-structure analysis.";

  const mlScore = result.mlAvailable && Number.isFinite(result.mlScore)
    ? result.mlScore
    : null;

  const urlScore = Number.isFinite(result.urlHeurScore)
    ? result.urlHeurScore
    : null;

  const domScore = Number.isFinite(result.domScore)
    ? result.domScore
    : null;

  $("#mlScore").textContent = scoreText(mlScore);
  $("#heuristicScore").textContent = scoreText(urlScore);
  $("#domScore").textContent = scoreText(domScore);

  setLayerBar("#mlFill", mlScore, "LOW RISK");
  setLayerBar("#urlFill", urlScore, "LOW RISK");
  setLayerBar("#domFill", domScore, "LOW RISK");

  $("#modelStatus").textContent = result.mlAvailable
    ? "Local ML model loaded"
    : "Local ML model unavailable";

  $("#extremeConfidence").textContent = result.extremeConfidence
    ? "Yes"
    : "No";

  renderList("#findings", result.findings, "No findings recorded.");
  renderList(
    "#appliedRules",
    result.appliedRules,
    "No fusion rules reported."
  );

  displayChecks(result);
  $("#explanationText").textContent = explainResult(result);
}

async function getResult(tabId) {
  return chrome.runtime.sendMessage({
    type: "PHISHGUARD_GET_RESULT",
    tabId
  });
}

async function loadActiveTab(rescan = false) {
  const scanButton = $("#scan");
  const status = $("#scanStatus");

  scanButton.disabled = true;
  status.textContent = "Scanning the current tab…";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true
    });

    if (!tab?.id || !/^https?:/.test(tab.url || "")) {
      $("#emptyState").classList.remove("hidden");
      $("#result").classList.add("hidden");
      status.textContent =
        "This page cannot be scanned. Open a normal HTTP or HTTPS webpage.";
      return;
    }

    let result = rescan
      ? await chrome.runtime.sendMessage({
          type: "PHISHGUARD_SCAN_TAB",
          tabId: tab.id
        })
      : await getResult(tab.id);

    if (!result) {
      result = await chrome.runtime.sendMessage({
        type: "PHISHGUARD_SCAN_TAB",
        tabId: tab.id
      });
    }

    if (result) displayResult(result);

    for (
      let attempt = 0;
      attempt < 10 && result?.status !== "complete";
      attempt += 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 400));

      result = await getResult(tab.id);

      if (result) displayResult(result);
    }

    if (result?.status !== "complete") {
      status.textContent =
        "The scan may still be running. Try rescanning this tab.";
    }
  } catch (error) {
    status.textContent = "Scan failed. Reload the extension and try again.";
    console.error("PhishGuard scan error:", error);
  } finally {
    scanButton.disabled = false;
  }
}

$("#scan").addEventListener("click", () => {
  void loadActiveTab(true);
});

$("#copyReport").addEventListener("click", async () => {
  if (!latestResult) return;

  const button = $("#copyReport");

  try {
    await navigator.clipboard.writeText(
      JSON.stringify(latestResult, null, 2)
    );

    button.textContent = "Report copied!";
  } catch (error) {
    console.error("Could not copy report:", error);
    button.textContent = "Copy failed — try again";
  }

  setTimeout(() => {
    button.textContent = "Copy report";
  }, 1800);
});

$("#viewReport").addEventListener("click", () => {
  const details = document.querySelector(".fusion-details");

  if (details) {
    details.open = true;
    details.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  $("#findings").scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
});

void loadActiveTab();
