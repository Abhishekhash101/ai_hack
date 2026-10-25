// background.js - Background Service Worker for Manifest V3

const API_ENDPOINT = "https://vit-phishing-detector-api.onrender.com";

chrome.runtime.onInstalled.addListener(() => {
  // Create Context Menus
  chrome.contextMenus.create({
    id: "vit-scan-selection",
    title: "VIT Guardian: Scan selected text for Phishing",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "vit-defang-link",
    title: "VIT Guardian: Copy Defanged URL (Inert)",
    contexts: ["link"]
  });
});

// Context Menu Handlers
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "vit-defang-link" && info.linkUrl) {
    const rawUrl = info.linkUrl;
    const defanged = defangUrl(rawUrl);
    
    if (tab && tab.id) {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (text) => {
          navigator.clipboard.writeText(text);
          alert(`URL safely defanged and copied to clipboard:\n\n${text}`);
        },
        args: [defanged]
      });
    }
  }

  if (info.menuItemId === "vit-scan-selection" && info.selectionText) {
    chrome.action.openPopup();
  }
});

// Centralized API Gateway to bypass page Content Security Policies (CSP)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "PREDICT_THREAT") {
    handlePredictionRequest(request.payload)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err => {
        // Fallback to local heuristic engine
        const fallback = runLocalHeuristics(request.payload.subject, request.payload.sender, request.payload.text);
        sendResponse({ success: true, data: fallback });
      });
    return true; // Keep message port open for async response
  }
});

async function handlePredictionRequest(payload) {
  // Get configured API URL or use default
  const config = await new Promise(resolve => {
    chrome.storage.sync.get(["apiUrl"], items => {
      resolve(items.apiUrl || API_ENDPOINT);
    });
  });

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

  try {
    const res = await fetch(`${config}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      return await res.json();
    }
    throw new Error(`API returned status ${res.status}`);
  } catch (err) {
    clearTimeout(timeoutId);
    console.warn("API call failed or timed out. Using local fallback.", err);
    return runLocalHeuristics(payload.subject, payload.sender, payload.text);
  }
}

// Local Heuristic Fallback Engine
function runLocalHeuristics(subject = "", sender = "", body = "") {
  const combined = `${sender} ${subject} ${body}`.toLowerCase();
  let score = 0.05;
  const signals = [];

  // 1. Urgency
  if (/immediately|within \d+ (?:hours?|mins?)|account suspended|final warning|urgent|deactivated/i.test(combined)) {
    score += 0.35;
    signals.push({
      signal_name: "Urgency Pressure",
      triggered: true,
      reason: "Urgent action-pressuring phrasing detected in message."
    });
  }

  // 2. Credentials
  if (/verify your password|enter otp|credentials|confirm password|atm pin|vtop portal/i.test(combined)) {
    score += 0.40;
    signals.push({
      signal_name: "Credential Harvesting",
      triggered: true,
      reason: "Explicit requests for sensitive credentials or authentication data."
    });
  }

  // 3. Lookalike domains
  const urlMatches = (body + " " + combined).match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
  const defangedUrls = [];
  urlMatches.forEach(u => {
    const d = defangUrl(u);
    defangedUrls.push(d);
    try {
      const host = new URL(u.startsWith("http") ? u : "http://" + u).hostname.toLowerCase();
      if ((host.includes("vit") || host.includes("vtop")) && !host.endsWith("vit.ac.in") && !host.endsWith("vitstudent.ac.in")) {
        score += 0.45;
        signals.push({
          signal_name: "Lookalike Domain",
          triggered: true,
          reason: `University lookalike domain detected ('${host}' is not official vit.ac.in).`
        });
      }
    } catch (e) {}
  });

  // 4. Sender Spoofing
  if (sender && (sender.includes("vit") || sender.includes("vtop") || sender.includes("admin")) && !sender.includes("vit.ac.in")) {
    score += 0.35;
    signals.push({
      signal_name: "Sender Impersonation",
      triggered: true,
      reason: "Claims official university role from an unauthorized email domain."
    });
  }

  score = Math.min(0.98, Math.max(0.04, score));
  const risk_level = score > 0.65 ? "High" : (score >= 0.35 ? "Medium" : "Low");
  const risk_color = risk_level === "High" ? "red" : (risk_level === "Medium" ? "amber" : "green");

  return {
    status: "success (local fallback)",
    probability: score,
    risk_level,
    risk_color,
    verdict_summary: risk_level === "High"
      ? "Warning: High risk detected! This message contains coercive urgency or credential theft vectors."
      : (risk_level === "Medium" ? "Caution: Contains ambiguous urgency or unverified external context." : "Low Risk: Aligns with normal communication."),
    signals,
    defanged_urls: defangedUrls
  };
}

function defangUrl(url) {
  if (!url) return "";
  let defanged = url.replace(/^https?:\/\//i, (m) => m.toLowerCase().replace("http", "hxxp"));
  const parts = defanged.split("/");
  if (parts.length >= 3 && parts[0].includes("hxxp")) {
    parts[2] = parts[2].replace(/\./g, "[.]");
    return parts.join("/");
  }
  return defanged.replace(/\./g, "[.]");
}
