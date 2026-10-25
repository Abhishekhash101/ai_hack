// content.js - Autonomous Webmail (Gmail, Outlook) & In-Page Phishing Guardian

const API_ENDPOINT = "https://vit-phishing-detector-api.onrender.com";

// Set to track already scanned message IDs/containers
const scannedContainers = new WeakSet();

// 1. Initialize MutationObserver to watch for opened emails
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 0) {
      checkForEmailContent();
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Run immediate check on initial load
setTimeout(checkForEmailContent, 1000);

// Detect email containers across Gmail, Outlook, and webmail clients
function checkForEmailContent() {
  const host = window.location.hostname;

  if (host.includes("mail.google.com")) {
    inspectGmailMessages();
  } else if (host.includes("outlook.live.com") || host.includes("outlook.office")) {
    inspectOutlookMessages();
  } else {
    inspectGenericEmailContainers();
  }
}

// -------------------------------------------------------------
// GMAIL DETECTOR
// -------------------------------------------------------------
function inspectGmailMessages() {
  // Gmail email body containers typically have class .a3s.aiL
  const emailBodies = document.querySelectorAll("div.a3s.aiL, div[dir='ltr'].a3s");
  emailBodies.forEach((bodyEl) => {
    if (scannedContainers.has(bodyEl) || bodyEl.getAttribute("data-vit-guardian-scanned")) {
      return;
    }

    // Must have readable text
    const textContent = bodyEl.innerText.trim();
    if (textContent.length < 15) return;

    // Find parent message wrapper
    const messageContainer = bodyEl.closest(".adn, .ii.gt, .ha") || bodyEl.parentElement;

    // Extract Subject line
    const subjectEl = document.querySelector("h2.hP") || document.querySelector("div.ha h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    // Extract Sender info
    const senderEl = messageContainer.querySelector("span.gD, span[email]") || document.querySelector("span.gD");
    const senderName = senderEl ? senderEl.innerText.trim() : "";
    const senderEmail = senderEl ? senderEl.getAttribute("email") || "" : "";
    const sender = senderEmail ? `${senderName} <${senderEmail}>` : senderName;

    // Mark as scanned
    scannedContainers.add(bodyEl);
    bodyEl.setAttribute("data-vit-guardian-scanned", "true");

    // Run prediction
    analyzeAndInjectBanner({
      subject,
      sender,
      body: textContent,
      targetEl: bodyEl,
      containerEl: messageContainer
    });
  });
}

// -------------------------------------------------------------
// OUTLOOK WEB DETECTOR
// -------------------------------------------------------------
function inspectOutlookMessages() {
  const messageBodies = document.querySelectorAll("div[aria-label='Message body'], div.ReadingPaneContents");
  messageBodies.forEach((bodyEl) => {
    if (scannedContainers.has(bodyEl) || bodyEl.getAttribute("data-vit-guardian-scanned")) {
      return;
    }

    const textContent = bodyEl.innerText.trim();
    if (textContent.length < 15) return;

    // Extract subject
    const subjectEl = document.querySelector("[role='heading'][aria-level='2'], div[data-testid='ReadingPane'] h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    // Extract sender
    const senderEl = document.querySelector("div[data-testid='senderPersona'] span, span.l8Tnu");
    const sender = senderEl ? senderEl.innerText.trim() : "";

    scannedContainers.add(bodyEl);
    bodyEl.setAttribute("data-vit-guardian-scanned", "true");

    analyzeAndInjectBanner({
      subject,
      sender,
      body: textContent,
      targetEl: bodyEl,
      containerEl: bodyEl.parentElement
    });
  });
}

// -------------------------------------------------------------
// GENERIC WEBMAIL / UNIVERSITY PORTAL DETECTOR
// -------------------------------------------------------------
function inspectGenericEmailContainers() {
  const genericContainers = document.querySelectorAll(".message-body, .mail-body, #message-content, .email-content");
  genericContainers.forEach((bodyEl) => {
    if (scannedContainers.has(bodyEl) || bodyEl.getAttribute("data-vit-guardian-scanned")) return;
    const textContent = bodyEl.innerText.trim();
    if (textContent.length < 20) return;

    scannedContainers.add(bodyEl);
    bodyEl.setAttribute("data-vit-guardian-scanned", "true");

    analyzeAndInjectBanner({
      subject: document.title || "",
      sender: "",
      body: textContent,
      targetEl: bodyEl,
      containerEl: bodyEl.parentElement
    });
  });
}

// -------------------------------------------------------------
// THREAT ANALYSIS & BANNER INJECTION
// -------------------------------------------------------------
async function analyzeAndInjectBanner({ subject, sender, body, targetEl, containerEl }) {
  // Show a discreet loading badge while predicting
  const loadingBadge = document.createElement("div");
  loadingBadge.className = "vit-guardian-email-banner banner-low";
  loadingBadge.innerHTML = `
    <div class="vit-banner-header">
      <div class="vit-banner-branding">
        <div class="vit-shield-icon">🛡️</div>
        <span class="vit-risk-title">VIT Guardian: Scanning incoming message...</span>
      </div>
    </div>
  `;
  targetEl.parentNode.insertBefore(loadingBadge, targetEl);

  let result = null;
  try {
    const res = await fetch(`${API_ENDPOINT}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subject: subject || "",
        sender: sender || "",
        text: body || ""
      })
    });

    if (res.ok) {
      result = await res.json();
    }
  } catch (err) {
    console.warn("Live API call timed out or failed. Falling back to in-browser heuristics.", err);
  }

  // Fallback to local heuristic engine if API is unreachable
  if (!result) {
    result = runLocalHeuristics(subject, sender, body);
  }

  // Remove loading badge
  loadingBadge.remove();

  // Create real banner
  const banner = document.createElement("div");
  const riskClass = result.risk_level === "High" ? "banner-high" : (result.risk_level === "Medium" ? "banner-med" : "banner-low");
  banner.className = `vit-guardian-email-banner ${riskClass}`;

  const pct = Math.round(result.probability * 100);
  const activeSignals = (result.signals || []).filter(s => s.triggered);

  let signalsHtml = "";
  if (activeSignals.length > 0) {
    signalsHtml = `
      <div class="vit-signals-container">
        ${activeSignals.slice(0, 3).map(s => `
          <div class="vit-signal-item">
            <span>⚠️</span>
            <div><strong>${s.signal_name}:</strong> ${s.reason}</div>
          </div>
        `).join("")}
      </div>
    `;
  }

  let defangedHtml = "";
  if (result.defanged_urls && result.defanged_urls.length > 0) {
    defangedHtml = `
      <div class="vit-defanged-box">
        <div class="vit-defanged-box-title">Defanged Inert Links (Clickable links in message are disabled):</div>
        ${result.defanged_urls.slice(0, 4).map(u => `
          <div class="vit-defanged-link-item">${u}</div>
        `).join("")}
      </div>
    `;
  }

  banner.innerHTML = `
    <div class="vit-banner-header">
      <div class="vit-banner-branding">
        <div class="vit-shield-icon">🛡️</div>
        <div class="vit-risk-title">
          <span>VIT Phishing Guardian</span>
          <span class="vit-risk-badge">${result.risk_level} RISK (${pct}%)</span>
        </div>
      </div>
      <div class="vit-banner-actions">
        <button class="vit-banner-btn" id="btnDismissGuardianBanner">Dismiss</button>
      </div>
    </div>
    <div class="vit-banner-summary">${result.verdict_summary || "Safety analysis complete."}</div>
    ${signalsHtml}
    ${defangedHtml}
  `;

  // Insert banner right above email body
  targetEl.parentNode.insertBefore(banner, targetEl);

  const dismissBtn = banner.querySelector("#btnDismissGuardianBanner");
  if (dismissBtn) {
    dismissBtn.addEventListener("click", () => banner.remove());
  }

  // If High Risk, neutralize and highlight links inside the email body
  if (result.risk_level === "High") {
    neutralizeEmailLinks(targetEl);
  }
}

// Neutralize and defang links inside suspicious email
function neutralizeEmailLinks(bodyEl) {
  const links = bodyEl.querySelectorAll("a[href]");
  links.forEach(link => {
    const origHref = link.href;
    if (origHref.startsWith("http://") || origHref.startsWith("https://")) {
      const defanged = defangUrl(origHref);
      link.classList.add("vit-guardian-defanged-link");
      link.setAttribute("data-vit-orig-href", origHref);
      link.setAttribute("title", `DEFANGED by VIT Guardian: ${defanged}`);

      // Intercept clicks
      link.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        alert(
          `SECURITY WARNING from VIT Guardian:\n\n` +
          `This message is flagged as HIGH RISK phishing.\n` +
          `The link you clicked has been defanged for your safety:\n\n` +
          `${defanged}\n\n` +
          `Please do NOT navigate to this site or enter your credentials.`
        );
      });
    }
  });
}

// Helper: Local Heuristics Fallback
function runLocalHeuristics(subject = "", sender = "", body = "") {
  const combined = `${sender} ${subject} ${body}`.toLowerCase();
  let score = 0.05;
  const signals = [];

  // Urgency
  if (/immediately|within 24 hours|account suspended|final warning|urgent/i.test(combined)) {
    score += 0.35;
    signals.push({ signal_name: "Urgency Pressure", triggered: true, reason: "Urgency and account suspension coercion detected." });
  }

  // Credentials
  if (/verify your password|enter otp|credentials|confirm password|atm pin|vtop portal/i.test(combined)) {
    score += 0.40;
    signals.push({ signal_name: "Credential Harvesting", triggered: true, reason: "Request for credentials or authentication data." });
  }

  // Lookalikes
  const urlMatches = combined.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
  const defangedUrls = [];
  urlMatches.forEach(u => {
    defangedUrls.push(defangUrl(u));
    if ((u.includes("vit") || u.includes("vtop")) && !u.includes("vit.ac.in") && !u.includes("vitstudent.ac.in")) {
      score += 0.45;
      signals.push({ signal_name: "Lookalike Domain", triggered: true, reason: `University lookalike link detected in message: ${defangUrl(u)}` });
    }
  });

  // Sender spoofing
  if (sender && (sender.includes("vit") || sender.includes("vtop") || sender.includes("admin")) && !sender.includes("vit.ac.in")) {
    score += 0.35;
    signals.push({ signal_name: "Sender Impersonation", triggered: true, reason: "Claims official affiliation from non-university domain." });
  }

  score = Math.min(0.98, Math.max(0.04, score));
  const risk_level = score > 0.65 ? "High" : (score >= 0.35 ? "Medium" : "Low");

  return {
    probability: score,
    risk_level,
    verdict_summary: risk_level === "High"
      ? "Warning: High risk detected! This message contains coercive urgency or credential theft vectors."
      : (risk_level === "Medium" ? "Caution: Contains ambiguous urgency or unverified external links." : "Low Risk: Aligns with normal communications."),
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
