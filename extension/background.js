// background.js - Background Service Worker for Manifest V3

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

// Handle Context Menu Clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "vit-defang-link" && info.linkUrl) {
    const rawUrl = info.linkUrl;
    const defanged = defangUrl(rawUrl);
    
    // Copy to clipboard via scripting injection
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
    // Open action popup
    chrome.action.openPopup();
  }
});

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
