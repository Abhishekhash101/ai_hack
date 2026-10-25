// content.js - Autonomous Webmail (Gmail, Outlook) & In-Page Phishing Guardian

// Track scanned elements and last analyzed email
const scannedContainers = new WeakSet();
let lastScannedEmailData = null;

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "GET_CURRENT_EMAIL_DATA") {
    // If we have an open email on screen, return its exact data
    const emailInfo = extractCurrentEmailOnScreen();
    sendResponse({
      isEmailView: !!emailInfo,
      emailData: emailInfo,
      lastResult: lastScannedEmailData ? lastScannedEmailData.result : null
    });
    return true;
  }
});

// Debounced mutation observer to watch for opened emails
let debounceTimer = null;
const observer = new MutationObserver((mutations) => {
  let hasRelevantChange = false;
  for (const m of mutations) {
    if (m.addedNodes.length > 0) {
      hasRelevantChange = true;
      break;
    }
  }
  if (hasRelevantChange) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkForEmailContent, 400);
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Initial scan
setTimeout(checkForEmailContent, 800);

// Check if an email is currently open on screen
function checkForEmailContent() {
  const host = window.location.hostname;
  if (host.includes("mail.google.com")) {
    inspectGmailMessages();
  } else if (host.includes("outlook.live.com") || host.includes("outlook.office")) {
    inspectOutlookMessages();
  }
}

// -------------------------------------------------------------
// GMAIL DETECTOR
// -------------------------------------------------------------
function inspectGmailMessages() {
  // Target only the primary open email body
  const emailBodies = document.querySelectorAll("div.a3s.aiL, div[dir='ltr'].a3s");
  emailBodies.forEach((bodyEl) => {
    // Skip if element is not visible or already scanned
    if (scannedContainers.has(bodyEl) || bodyEl.getAttribute("data-vit-guardian-scanned")) {
      return;
    }

    // Skip hidden or tiny quote containers
    if (bodyEl.offsetWidth === 0 || bodyEl.offsetHeight === 0) return;
    const textContent = bodyEl.innerText.trim();
    if (textContent.length < 20) return;

    // Find parent message container
    const messageContainer = bodyEl.closest(".adn, .ii.gt, .ha") || bodyEl.parentElement;
    if (!messageContainer) return;

    // Check if a banner is already injected in this container
    if (messageContainer.querySelector(".vit-guardian-email-banner")) {
      scannedContainers.add(bodyEl);
      bodyEl.setAttribute("data-vit-guardian-scanned", "true");
      return;
    }

    // Extract Subject Line
    const subjectEl = document.querySelector("h2.hP") || document.querySelector("div.ha h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    // Extract Sender Information
    const senderEl = messageContainer.querySelector("span.gD, span[email]") || document.querySelector("span.gD");
    const senderName = senderEl ? senderEl.innerText.trim() : "";
    const senderEmail = senderEl ? (senderEl.getAttribute("email") || "") : "";
    const sender = senderEmail ? `${senderName} <${senderEmail}>` : senderName;

    // Mark as scanned
    scannedContainers.add(bodyEl);
    bodyEl.setAttribute("data-vit-guardian-scanned", "true");

    // Perform threat analysis
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
    if (scannedContainers.has(bodyEl) || bodyEl.getAttribute("data-vit-guardian-scanned")) return;
    if (bodyEl.offsetWidth === 0 || bodyEl.offsetHeight === 0) return;

    const textContent = bodyEl.innerText.trim();
    if (textContent.length < 20) return;

    const containerEl = bodyEl.parentElement;
    if (containerEl && containerEl.querySelector(".vit-guardian-email-banner")) {
      scannedContainers.add(bodyEl);
      bodyEl.setAttribute("data-vit-guardian-scanned", "true");
      return;
    }

    const subjectEl = document.querySelector("[role='heading'][aria-level='2'], div[data-testid='ReadingPane'] h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl = document.querySelector("div[data-testid='senderPersona'] span, span.l8Tnu");
    const sender = senderEl ? senderEl.innerText.trim() : "";

    scannedContainers.add(bodyEl);
    bodyEl.setAttribute("data-vit-guardian-scanned", "true");

    analyzeAndInjectBanner({
      subject,
      sender,
      body: textContent,
      targetEl: bodyEl,
      containerEl: containerEl || bodyEl.parentElement
    });
  });
}

// -------------------------------------------------------------
// EXTRACT EMAIL FOR POPUP SYNCHRONIZATION
// -------------------------------------------------------------
function extractCurrentEmailOnScreen() {
  const host = window.location.hostname;
  if (host.includes("mail.google.com")) {
    const bodyEl = document.querySelector("div.a3s.aiL, div[dir='ltr'].a3s");
    if (!bodyEl) return null;

    const subjectEl = document.querySelector("h2.hP") || document.querySelector("div.ha h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl = document.querySelector("span.gD, span[email]");
    const senderName = senderEl ? senderEl.innerText.trim() : "";
    const senderEmail = senderEl ? (senderEl.getAttribute("email") || "") : "";
    const sender = senderEmail ? `${senderName} <${senderEmail}>` : senderName;

    const urls = [];
    bodyEl.querySelectorAll("a[href]").forEach(a => {
      const h = a.href;
      if (h && (h.startsWith("http://") || h.startsWith("https://"))) urls.push(h);
    });

    return {
      subject,
      sender,
      body: bodyEl.innerText.trim(),
      urls: urls.slice(0, 10),
      isEmail: true
    };
  }

  if (host.includes("outlook.live.com") || host.includes("outlook.office")) {
    const bodyEl = document.querySelector("div[aria-label='Message body'], div.ReadingPaneContents");
    if (!bodyEl) return null;

    const subjectEl = document.querySelector("[role='heading'][aria-level='2']");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl = document.querySelector("div[data-testid='senderPersona'] span, span.l8Tnu");
    const sender = senderEl ? senderEl.innerText.trim() : "";

    return {
      subject,
      sender,
      body: bodyEl.innerText.trim(),
      urls: [],
      isEmail: true
    };
  }

  return null;
}

// -------------------------------------------------------------
// THREAT ANALYSIS & BANNER INJECTION
// -------------------------------------------------------------
function analyzeAndInjectBanner({ subject, sender, body, targetEl, containerEl }) {
  // 1. Create Loading Placeholder
  const loadingBanner = document.createElement("div");
  loadingBanner.className = "vit-guardian-email-banner banner-low";
  loadingBanner.innerHTML = `
    <div class="vit-banner-header">
      <div class="vit-banner-branding">
        <div class="vit-shield-icon">🛡️</div>
        <div class="vit-risk-title">
          <span>VIT Phishing Guardian</span>
          <span style="font-size: 11px; opacity: 0.8; font-weight: 500;">Analyzing email via AI & heuristic models...</span>
        </div>
      </div>
    </div>
  `;
  targetEl.parentNode.insertBefore(loadingBanner, targetEl);

  // 2. Send to Background Worker (Bypasses Gmail CSP & CORS)
  chrome.runtime.sendMessage({
    action: "PREDICT_THREAT",
    payload: {
      subject: subject || "",
      sender: sender || "",
      text: body || ""
    }
  }, (response) => {
    // Always remove loading banner
    loadingBanner.remove();

    if (!response || !response.success || !response.data) {
      console.warn("VIT Guardian: No response received from background.");
      return;
    }

    const result = response.data;

    // Cache email data in memory and persistent storage for instant popup sync
    lastScannedEmailData = {
      subject,
      sender,
      body,
      result
    };

    chrome.storage.local.set({
      latestEmailScan: {
        url: window.location.href,
        subject,
        sender,
        body,
        result,
        timestamp: Date.now()
      }
    });

    // 3. Inject Finalized Result Banner
    injectResultBanner({ result, targetEl });
  });
}

function injectResultBanner({ result, targetEl }) {
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

  targetEl.parentNode.insertBefore(banner, targetEl);

  const dismissBtn = banner.querySelector("#btnDismissGuardianBanner");
  if (dismissBtn) {
    dismissBtn.addEventListener("click", () => banner.remove());
  }

  // If High Risk, defang and neutralize all links inside the email body
  if (result.risk_level === "High") {
    neutralizeEmailLinks(targetEl);
  }
}

// Defang and lock down clickable links in high risk email
function neutralizeEmailLinks(bodyEl) {
  const links = bodyEl.querySelectorAll("a[href]");
  links.forEach(link => {
    const origHref = link.href;
    if (origHref.startsWith("http://") || origHref.startsWith("https://")) {
      const defanged = defangUrl(origHref);
      link.classList.add("vit-guardian-defanged-link");
      link.setAttribute("data-vit-orig-href", origHref);
      link.setAttribute("title", `DEFANGED by VIT Guardian: ${defanged}`);

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
