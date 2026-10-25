const DEFAULT_API_URL = "https://vit-phishing-detector-api.onrender.com";

let currentConfig = {
  apiUrl: DEFAULT_API_URL,
  useLocalFallback: true
};

let lastAnalysisResult = null;

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  initTabs();
  initActiveTabPreview();
  bindActionButtons();
  checkApiHealth();
});

// Load saved settings from Chrome Storage
async function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiUrl", "useLocalFallback"], (items) => {
      if (items.apiUrl) currentConfig.apiUrl = items.apiUrl;
      if (items.useLocalFallback !== undefined) currentConfig.useLocalFallback = items.useLocalFallback;

      const input = document.getElementById("backendUrlInput");
      const chk = document.getElementById("chkLocalFallback");
      if (input) input.value = currentConfig.apiUrl;
      if (chk) chk.checked = currentConfig.useLocalFallback;
      resolve();
    });
  });
}

// Tab Switching
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });
}

// Display Current Tab Info
async function initActiveTabPreview() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const targetUrlEl = document.getElementById("currentTabUrl");
    if (tab && targetUrlEl) {
      targetUrlEl.textContent = tab.url || "about:blank";
      targetUrlEl.title = tab.url;
    }
  } catch (err) {
    console.error("Tab query failed:", err);
  }
}

// Bind Buttons
function bindActionButtons() {
  // Quick Scan
  const btnScan = document.getElementById("btnScanCurrentPage");
  if (btnScan) btnScan.addEventListener("click", scanCurrentPage);

  // Manual Scan
  const btnManual = document.getElementById("btnAnalyzeManual");
  if (btnManual) btnManual.addEventListener("click", analyzeManualInput);

  // Sample buttons
  const btnPhish = document.getElementById("btnSamplePhish");
  if (btnPhish) {
    btnPhish.addEventListener("click", () => {
      document.getElementById("inputSender").value = "VIT Admin <security@vtop-verify-portal.example>";
      document.getElementById("inputSubject").value = "URGENT: VTOP Account Suspended Within 24 Hours";
      document.getElementById("inputBody").value = "Dear Student, unauthorized login attempts detected on your VTOP portal. Verify your password and enter OTP at http://vtop-login-secure.example/auth to restore access immediately.";
    });
  }

  const btnLegit = document.getElementById("btnSampleLegit");
  if (btnLegit) {
    btnLegit.addEventListener("click", () => {
      document.getElementById("inputSender").value = "Controller of Examinations <coe@vit.ac.in>";
      document.getElementById("inputSubject").value = "Circular: Winter Semester FAT Slot Allotment Schedule";
      document.getElementById("inputBody").value = "Dear Students, the finalized schedule for Fall Semester examinations is released. Please view your hall ticket directly on the official VTOP portal at https://vtop.vit.ac.in.";
    });
  }

  // Copy Defanged
  const btnCopy = document.getElementById("btnCopyDefanged");
  if (btnCopy) btnCopy.addEventListener("click", copyDefangedUrls);

  // Settings Buttons
  const btnSave = document.getElementById("btnSaveSettings");
  if (btnSave) btnSave.addEventListener("click", saveSettings);

  const btnTest = document.getElementById("btnTestApi");
  if (btnTest) btnTest.addEventListener("click", testApiConnection);
}

// Check Backend API Health
async function checkApiHealth() {
  const dot = document.getElementById("statusDot");
  const txt = document.getElementById("statusText");
  try {
    const res = await fetch(`${currentConfig.apiUrl}/`, { method: "GET" });
    if (res.ok) {
      dot.className = "status-dot online";
      txt.textContent = "Online";
      return true;
    }
  } catch (e) {
    // offline
  }
  dot.className = "status-dot offline";
  txt.textContent = "Local Only";
  return false;
}

// Settings Handlers
async function saveSettings() {
  const input = document.getElementById("backendUrlInput");
  const chk = document.getElementById("chkLocalFallback");
  const newUrl = (input.value || "").trim().replace(/\/+$/, "");

  currentConfig.apiUrl = newUrl || DEFAULT_API_URL;
  currentConfig.useLocalFallback = chk.checked;

  chrome.storage.sync.set({
    apiUrl: currentConfig.apiUrl,
    useLocalFallback: currentConfig.useLocalFallback
  }, () => {
    testApiConnection();
  });
}

async function testApiConnection() {
  const box = document.getElementById("pingResult");
  box.className = "ping-box";
  box.textContent = "Pinging API endpoint...";
  box.classList.remove("hidden");

  const start = Date.now();
  try {
    const res = await fetch(`${currentConfig.apiUrl}/`, { method: "GET" });
    const latency = Date.now() - start;
    if (res.ok) {
      box.className = "ping-box success";
      box.textContent = `Connected! Response in ${latency}ms (Status 200 OK)`;
      checkApiHealth();
      return;
    }
  } catch (e) {
    // fail
  }
  box.className = "ping-box error";
  box.textContent = "Failed to connect to API. If using Render, service may be sleeping or URL is incorrect.";
  checkApiHealth();
}

// 1. Scan Active Webpage / Email
async function scanCurrentPage() {
  const loading = document.getElementById("quickLoading");
  const results = document.getElementById("resultsContainer");

  loading.classList.remove("hidden");
  results.classList.add("hidden");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) throw new Error("No active tab accessible");

    // Injected extraction
    const injectionResults = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const selection = window.getSelection().toString().trim();
        const title = document.title || "";
        const bodyText = document.body ? document.body.innerText.slice(0, 3000) : "";
        const urls = [];
        document.querySelectorAll("a[href]").forEach(a => {
          const h = a.href;
          if (h && (h.startsWith("http://") || h.startsWith("https://"))) {
            urls.push(h);
          }
        });
        return {
          selection,
          title,
          bodyText,
          url: window.location.href,
          extractedUrls: urls.slice(0, 10)
        };
      }
    });

    const pageData = injectionResults && injectionResults[0] ? injectionResults[0].result : null;
    const inspectText = (pageData && pageData.selection) ? pageData.selection : (pageData ? pageData.bodyText : "");
    const inspectSubject = pageData ? pageData.title : "";
    const inspectUrl = pageData ? pageData.url : "";

    const analysis = await analyzeThreat({
      text: inspectText,
      subject: inspectSubject,
      url: inspectUrl
    });

    renderResults(analysis);
  } catch (err) {
    console.error("Scan error:", err);
    // Fallback to active tab URL only
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const analysis = await analyzeThreat({
      text: tab ? tab.title : "",
      subject: tab ? tab.title : "",
      url: tab ? tab.url : ""
    });
    renderResults(analysis);
  } finally {
    loading.classList.add("hidden");
  }
}

// 2. Manual Analysis
async function analyzeManualInput() {
  const sender = document.getElementById("inputSender").value.trim();
  const subject = document.getElementById("inputSubject").value.trim();
  const body = document.getElementById("inputBody").value.trim();

  if (!sender && !subject && !body) {
    alert("Please enter a sender, subject, or message text to analyze.");
    return;
  }

  // Switch to quick tab to show results
  document.querySelector('.tab-btn[data-tab="tab-quick"]').click();
  const loading = document.getElementById("quickLoading");
  const results = document.getElementById("resultsContainer");

  loading.classList.remove("hidden");
  results.classList.add("hidden");

  try {
    const analysis = await analyzeThreat({
      sender,
      subject,
      text: body
    });
    renderResults(analysis);
  } catch (err) {
    console.error("Manual evaluation error:", err);
  } finally {
    loading.classList.add("hidden");
  }
}

// Master Threat Analyzer (Backend API with Local Fallback)
async function analyzeThreat(payload) {
  // Try remote API first
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000); // 4s timeout

    const res = await fetch(`${currentConfig.apiUrl}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return data;
    }
  } catch (err) {
    console.warn("Backend API call failed or timed out. Falling back to local heuristics.", err);
  }

  // Fallback to local heuristic engine
  return runLocalHeuristicEngine(payload);
}

// Local Heuristic Fallback Engine
function runLocalHeuristicEngine(payload) {
  const text = (payload.text || "").toLowerCase();
  const subject = (payload.subject || "").toLowerCase();
  const sender = (payload.sender || "").toLowerCase();
  const url = (payload.url || "").toLowerCase();
  const combined = `${sender} ${subject} ${text} ${url}`;

  // Find and defang URLs
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+/gi;
  const rawUrls = (payload.text + " " + (payload.url || "")).match(urlRegex) || [];
  const defangedUrls = rawUrls.map(defangUrlClient);

  const signals = [];
  let threatScore = 0.05;

  // 1. Urgency
  const urgencyTerms = ["immediately", "within 24 hours", "account suspended", "deactivated", "final warning", "urgent", "action required"];
  const matchedUrgency = urgencyTerms.filter(t => combined.includes(t));
  if (matchedUrgency.length > 0) {
    threatScore += 0.35;
    signals.push({
      signal_name: "Urgency Pressure",
      triggered: true,
      reason: `Coercive urgency keywords found: '${matchedUrgency.slice(0, 2).join("', '")}'.`
    });
  }

  // 2. Credential Theft
  const credTerms = ["verify your password", "enter otp", "credentials", "confirm password", "atm pin", "login details", "update your account"];
  const matchedCred = credTerms.filter(t => combined.includes(t));
  if (matchedCred.length > 0) {
    threatScore += 0.40;
    signals.push({
      signal_name: "Credential Harvesting",
      triggered: true,
      reason: `Explicit requests for sensitive credentials detected ('${matchedCred[0]}').`
    });
  }

  // 3. Lookalike / Spoofed Domains
  let lookalikeFound = false;
  rawUrls.forEach(u => {
    try {
      const parsed = new URL(u.startsWith("http") ? u : "http://" + u);
      const host = parsed.hostname.toLowerCase();
      if ((host.includes("vit") || host.includes("vtop")) && !host.endsWith("vit.ac.in") && !host.endsWith("vitstudent.ac.in")) {
        lookalikeFound = true;
        signals.push({
          signal_name: "Lookalike Domain",
          triggered: true,
          reason: `Deceptive university lookalike host detected ('${host}' is not official vit.ac.in).`
        });
        threatScore += 0.45;
      }
    } catch (e) {}
  });

  // 4. Sender Mismatch
  if (sender) {
    const claimsVit = sender.includes("vit") || sender.includes("vtop") || sender.includes("registrar") || sender.includes("admin");
    const isVitDomain = sender.includes("@vit.ac.in") || sender.includes("@vitstudent.ac.in");
    const isFreemail = sender.includes("@gmail.com") || sender.includes("@yahoo.com") || sender.includes("@outlook.com");

    if (claimsVit && !isVitDomain) {
      threatScore += 0.35;
      signals.push({
        signal_name: "Sender Impersonation",
        triggered: true,
        reason: isFreemail 
          ? "Official VIT designation sent from public commercial email provider." 
          : "Sender claims university role from unverified domain."
      });
    }
  }

  threatScore = Math.min(0.97, Math.max(0.04, threatScore));

  let risk_level = "Low";
  let risk_color = "green";
  if (threatScore > 0.65) {
    risk_level = "High";
    risk_color = "red";
  } else if (threatScore >= 0.35) {
    risk_level = "Medium";
    risk_color = "amber";
  }

  return {
    status: "success (local fallback)",
    probability: threatScore,
    risk_level,
    risk_color,
    verdict_summary: risk_level === "High"
      ? "High risk detected. Deceptive links or credential theft vectors found."
      : (risk_level === "Medium" ? "Caution warranted: ambiguous urgency or external links present." : "Low risk: aligns with benign academic communication."),
    defanged_urls: defangedUrls,
    signals
  };
}

// Client URL Defanger
function defangUrlClient(rawUrl) {
  if (!rawUrl) return "";
  let defanged = rawUrl.replace(/^https?:\/\//i, (m) => m.toLowerCase().replace("http", "hxxp"));
  const parts = defanged.split("/");
  if (parts.length >= 3 && parts[0].includes("hxxp")) {
    parts[2] = parts[2].replace(/\./g, "[.]");
    return parts.join("/");
  }
  return defanged.replace(/\./g, "[.]");
}

// Render Results to UI
function renderResults(data) {
  lastAnalysisResult = data;
  const results = document.getElementById("resultsContainer");
  const card = document.getElementById("riskCard");
  const label = document.getElementById("riskTierLabel");
  const scoreEl = document.getElementById("riskScorePercent");
  const meterVal = document.getElementById("riskMeterVal");
  const verdict = document.getElementById("verdictSummary");
  const signalsList = document.getElementById("signalsList");
  const defangedSection = document.getElementById("defangedSection");
  const defangedList = document.getElementById("defangedList");

  // Reset classes
  card.className = "risk-card";
  const pct = Math.round(data.probability * 100);

  if (data.risk_level === "High") {
    card.classList.add("risk-high");
    label.textContent = "HIGH RISK";
  } else if (data.risk_level === "Medium") {
    card.classList.add("risk-med");
    label.textContent = "MEDIUM RISK";
  } else {
    card.classList.add("risk-low");
    label.textContent = "LOW RISK";
  }

  scoreEl.textContent = `Probability: ${pct}%`;
  meterVal.textContent = `${pct}%`;
  verdict.textContent = data.verdict_summary || "Analysis complete.";

  // Render Signals
  signalsList.innerHTML = "";
  const activeSignals = (data.signals || []).filter(s => s.triggered);
  if (activeSignals.length === 0) {
    signalsList.innerHTML = `
      <div class="signal-row">
        <span class="signal-desc">No adverse heuristic flags triggered.</span>
      </div>
    `;
  } else {
    activeSignals.forEach(sig => {
      const row = document.createElement("div");
      row.className = "signal-row";
      row.innerHTML = `
        <div class="signal-icon">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#f59e0b" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </div>
        <div class="signal-desc">
          <strong>${sig.signal_name}:</strong> ${sig.reason}
        </div>
      `;
      signalsList.appendChild(row);
    });
  }

  // Render Defanged URLs
  defangedList.innerHTML = "";
  const urls = data.defanged_urls || [];
  if (urls.length === 0) {
    defangedSection.classList.add("hidden");
  } else {
    defangedSection.classList.remove("hidden");
    urls.forEach(u => {
      const item = document.createElement("div");
      item.className = "defanged-item";
      item.textContent = u;
      defangedList.appendChild(item);
    });
  }

  results.classList.remove("hidden");
}

// Copy Defanged URLs to Clipboard
function copyDefangedUrls() {
  if (!lastAnalysisResult || !lastAnalysisResult.defanged_urls) return;
  const textToCopy = lastAnalysisResult.defanged_urls.join("\n");
  navigator.clipboard.writeText(textToCopy).then(() => {
    const btn = document.getElementById("btnCopyDefanged");
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}
