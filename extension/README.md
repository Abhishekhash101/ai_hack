# 🛡️ VIT Phishing Guardian - Chrome Extension

A Manifest V3 Google Chrome extension that brings explainable AI phishing detection, heuristic vector analysis, and zero-trust URL defanging directly into student and staff web browsers.

---

## 🚀 Features

1. **1-Click Webpage & Email Scanning:**
   - Evaluates active browser tab content, email messages (Gmail, Outlook Web, VTOP), or highlighted text against our AI and rule engines.
2. **Deterministic Security Signals:**
   - Flags psychological urgency (*"account suspended within 24 hours"*), credential harvesting (*"enter OTP"*, *"confirm password"*), lookalike domains (*"vit-account-verify.example"*), and sender mismatches.
3. **Automatic URL Defanging:**
   - Instantly converts clickable links into inert strings (`hxxp://host[.]domain/path`) preventing accidental link execution.
4. **Context Menu Shortcuts:**
   - Right-click any link on the web to copy its safely defanged version directly to the clipboard.
5. **Passive Lookalike Warning Banner:**
   - Displays a warning banner if a user inadvertently navigates to an unofficial university domain containing `vit` or `vtop`.
6. **Dual Mode (Backend API + Local Heuristic Fallback):**
   - Connects to your Render cloud deployment or local server, with an automatic client-side heuristic fallback ensuring instant response times even while cloud instances wake up.

---

## 📥 How to Install in Google Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in the URL address bar.
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. In the top-left corner, click **Load unpacked**.
5. Select the `extension/` folder located inside this repository (`/home/abhishek/Documents/Ai Hackathon/extension`).
6. The **VIT Phishing Guardian** extension icon will now appear in your browser toolbar! (Click the puzzle piece icon to pin it to your toolbar).

---

## 🌐 How to Deploy the Backend to Render (render.com)

Deploying the detection API to Render allows your Chrome extension to analyze messages anywhere without keeping your local machine running.

### Prerequisites:
- A free account on [Render](https://render.com).
- Your GitHub repository: `https://github.com/Abhishekhash101/ai_hack.git`.

### Step-by-Step Deployment:
1. Log in to your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** in the top navigation bar and select **Web Service**.
3. Choose **Build and deploy from a Git repository** and connect your GitHub account.
4. Select your repository: `Abhishekhash101/ai_hack`.
5. Configure the web service settings:
   - **Name:** `vit-phishing-detector-api` (or any custom name)
   - **Region:** Choose the region closest to you (e.g., Singapore or Frankfurt)
   - **Branch:** `main`
   - **Root Directory:** Leave blank (default)
   - **Runtime:** `Python 3`
   - **Build Command:** 
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command:** 
     ```bash
     uvicorn api:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type:** `Free`
6. Click **Create Web Service**.
7. Render will automatically build the dependencies and start the FastAPI service. Once deployed, Render will provide a public URL like:
   `https://vit-phishing-detector-api.onrender.com`
8. Verify deployment by visiting your URL in the browser. You should see:
   ```json
   {
     "status": "online",
     "service": "VIT Phishing Detection & Awareness API",
     "version": "1.0.0",
     "models_loaded": true
   }
   ```

---

## ⚙️ Connecting the Chrome Extension to Your Render URL

1. Click the **VIT Guardian** shield icon in Chrome.
2. Navigate to the **Settings** tab.
3. In the **API Endpoint URL** field, replace `http://localhost:8000` with your deployed Render URL:
   `https://your-service-name.onrender.com`
4. Click **Save API URL**, then click **Test Ping** to confirm the connection.
5. You're all set! The extension is now connected to your cloud AI detector.
