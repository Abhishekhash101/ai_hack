// content.js - In-page Guardian Content Script

// Listen for messages from popup or background service worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "EXTRACT_PAGE_CONTENT") {
    const selection = window.getSelection().toString().trim();
    const title = document.title || "";
    const bodyText = document.body ? document.body.innerText.slice(0, 3000) : "";
    
    // Extract links
    const urls = [];
    document.querySelectorAll("a[href]").forEach(a => {
      const h = a.href;
      if (h && (h.startsWith("http://") || h.startsWith("https://"))) {
        urls.push(h);
      }
    });

    sendResponse({
      selection,
      title,
      bodyText,
      url: window.location.href,
      urls: urls.slice(0, 15)
    });
    return true;
  }
});

// Autonomous passive lookalike domain warning
(function inspectActiveHost() {
  const host = window.location.hostname.toLowerCase();
  
  // Check if page claims to be VIT/VTOP but is not genuine
  const isSpoofed = (host.includes("vit") || host.includes("vtop")) &&
                    !host.endsWith("vit.ac.in") &&
                    !host.endsWith("vitstudent.ac.in") &&
                    !host.endsWith("localhost") &&
                    !host.includes("127.0.0.1");

  if (isSpoofed) {
    const banner = document.createElement("div");
    banner.id = "vit-guardian-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background: linear-gradient(135deg, #b91c1c 0%, #7f1d1d 100%);
      color: #ffffff;
      padding: 10px 16px;
      z-index: 999999999;
      font-family: -apple-system, sans-serif;
      font-size: 13px;
      font-weight: 600;
      box-shadow: 0 4px 15px rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 2px solid #ef4444;
    `;
    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 16px;">⚠️</span>
        <span><strong>VIT Phishing Warning:</strong> This domain ('${host}') is NOT an official VIT university website (vit.ac.in). Do NOT enter your VTOP credentials or OTP.</span>
      </div>
      <button id="vit-guardian-dismiss-btn" style="
        background: rgba(255,255,255,0.2);
        border: 1px solid rgba(255,255,255,0.4);
        color: #fff;
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
      ">Dismiss</button>
    `;

    document.documentElement.prepend(banner);

    const btn = document.getElementById("vit-guardian-dismiss-btn");
    if (btn) {
      btn.addEventListener("click", () => banner.remove());
    }
  }
})();
